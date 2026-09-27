//! Fork-only, blocking, client-side capability probe. No host listeners, resolver,
//! production adapter, or VCore lifecycle claims. Only isolated synthetic peers.
#[cfg(not(all(feature = "shadow-tls-v3", feature = "client-fingerprint")))]
fn main() {
    eprintln!("shadow-tls-v3 and client-fingerprint features required");
    std::process::exit(2);
}

#[cfg(all(feature = "shadow-tls-v3", feature = "client-fingerprint"))]
fn main() {
    if let Err(stage) = probe::run() {
        println!("{{\"status\":\"failed\",\"stage\":\"{stage}\"}}");
        std::process::exit(1);
    }
}

#[cfg(all(feature = "shadow-tls-v3", feature = "client-fingerprint"))]
mod probe {
    use boring::{
        memcmp,
        sha::Sha256,
        ssl::{
            ClientFingerprint, FingerprintConnector, SslConnector, SslMethod, SslStream,
            SslVerifyMode, SslVersion,
        },
    };
    use std::{
        io::{self, Read, Write},
        net::{IpAddr, SocketAddr, TcpStream},
        ptr::{self, NonNull},
        time::Duration,
    };

    fn invalid() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "ShadowTLS probe record rejected",
        )
    }

    // Thin RAII over the public native incremental primitive; no hand-written HMAC.
    struct Mac(NonNull<boring_sys::HMAC_CTX>);
    impl Mac {
        fn allocate() -> io::Result<Self> {
            NonNull::new(unsafe { boring_sys::HMAC_CTX_new() })
                .map(Self)
                .ok_or_else(invalid)
        }
        fn new(password: &[u8], seed: &[u8]) -> io::Result<Self> {
            let mut mac = Self::allocate()?;
            let ok = unsafe {
                boring_sys::HMAC_Init_ex(
                    mac.0.as_ptr(),
                    password.as_ptr().cast(),
                    password.len(),
                    boring_sys::EVP_sha1(),
                    ptr::null_mut(),
                )
            };
            if ok != 1 {
                return Err(invalid());
            }
            mac.update(seed)?;
            Ok(mac)
        }
        fn update(&mut self, bytes: &[u8]) -> io::Result<()> {
            if unsafe { boring_sys::HMAC_Update(self.0.as_ptr(), bytes.as_ptr(), bytes.len()) } != 1
            {
                return Err(invalid());
            }
            Ok(())
        }
        fn sum(&self) -> io::Result<[u8; 4]> {
            let copy = Self::allocate()?;
            let mut result = [0; 64];
            let mut length = 0;
            if unsafe { boring_sys::HMAC_CTX_copy_ex(copy.0.as_ptr(), self.0.as_ptr()) } != 1
                || unsafe {
                    boring_sys::HMAC_Final(copy.0.as_ptr(), result.as_mut_ptr(), &mut length)
                } != 1
                || length != 20
            {
                return Err(invalid());
            }
            Ok(result[..4].try_into().unwrap())
        }
    }
    impl Drop for Mac {
        fn drop(&mut self) {
            unsafe {
                boring_sys::HMAC_CTX_cleanse(self.0.as_ptr());
                boring_sys::HMAC_CTX_free(self.0.as_ptr());
            }
        }
    }

    fn frame(raw: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut header = [0; 5];
        raw.read_exact(&mut header)?;
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if header[1] != 3 || !(1..=18436).contains(&length) {
            return Err(invalid());
        }
        let mut record = header.to_vec();
        record.resize(5 + length, 0);
        raw.read_exact(&mut record[5..])?;
        Ok(record)
    }

    fn tls13(message: &[u8]) -> io::Result<bool> {
        let id_size = usize::from(*message.get(38).ok_or_else(invalid)?);
        let mut at = 39 + id_size + 3;
        if at == message.len() {
            return Ok(false);
        }
        let size = message.get(at..at + 2).ok_or_else(invalid)?;
        let end = at + 2 + usize::from(u16::from_be_bytes([size[0], size[1]]));
        if end != message.len() {
            return Err(invalid());
        }
        at += 2;
        let mut supported = false;
        while at < end {
            let header = message.get(at..at + 4).ok_or_else(invalid)?;
            let size = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let body = message.get(at + 4..at + 4 + size).ok_or_else(invalid)?;
            if header[..2] == [0, 43] {
                supported = body == [3, 4];
            }
            at += 4 + size;
        }
        Ok(supported)
    }

    struct Relay {
        raw: TcpStream,
        password: Vec<u8>,
        seed: Option<[u8; 32]>,
        mask: [u8; 32],
        ignore: Option<Mac>,
        pending: io::Cursor<Vec<u8>>,
        authorized: bool,
        corrupt: bool,
    }
    impl Read for Relay {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if output.is_empty() {
                return Ok(0);
            }
            if self.pending.position() == self.pending.get_ref().len() as u64 {
                let mut record = frame(&mut self.raw)?;
                if record[0] == 22 && record.get(5) == Some(&2) && self.seed.is_none() {
                    let random: [u8; 32] =
                        record.get(11..43).ok_or_else(invalid)?.try_into().unwrap();
                    self.ignore = Some(Mac::new(&self.password, &random)?);
                    let mut sha = Sha256::new();
                    sha.update(&self.password);
                    sha.update(&random);
                    self.mask = sha.finish();
                    self.seed = Some(random);
                    self.authorized = !tls13(&record[5..])?;
                } else if record[0] == 23 {
                    self.authorized = false;
                    if record.len() <= 9 {
                        return Err(invalid());
                    }
                    let mac = self.ignore.as_mut().ok_or_else(invalid)?;
                    mac.update(&record[9..])?;
                    if self.corrupt {
                        record[5] ^= 1;
                    }
                    if !memcmp::eq(&mac.sum()?, &record[5..9]) {
                        return Err(invalid());
                    }
                    for (i, byte) in record[9..].iter_mut().enumerate() {
                        *byte ^= self.mask[i % 32];
                    }
                    record.drain(5..9);
                    let size = (record.len() - 5) as u16;
                    record[3..5].copy_from_slice(&size.to_be_bytes());
                    self.authorized = true;
                }
                self.pending = io::Cursor::new(record);
            }
            self.pending.read(output)
        }
    }
    impl Write for Relay {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.raw.write(input)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.raw.flush()
        }
    }

    struct Verified {
        relay: Relay,
        tx: Mac,
        rx: Mac,
        pending: io::Cursor<Vec<u8>>,
    }
    impl Verified {
        fn new(relay: Relay) -> io::Result<Self> {
            if !relay.authorized || relay.pending.position() != relay.pending.get_ref().len() as u64
            {
                return Err(invalid());
            }
            let seed = relay.seed.ok_or_else(invalid)?;
            let mut tx = Mac::new(&relay.password, &seed)?;
            let mut rx = Mac::new(&relay.password, &seed)?;
            tx.update(b"C")?;
            rx.update(b"S")?;
            Ok(Self {
                relay,
                tx,
                rx,
                pending: io::Cursor::new(Vec::new()),
            })
        }
    }
    impl Read for Verified {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if output.is_empty() {
                return Ok(0);
            }
            if self.pending.position() != self.pending.get_ref().len() as u64 {
                return self.pending.read(output);
            }
            for _ in 0..128 {
                let record = frame(&mut self.relay.raw)?;
                if record.len() < 9 || record[..3] != [23, 3, 3] {
                    return Err(invalid());
                }
                if let Some(mac) = self.relay.ignore.as_mut() {
                    mac.update(&record[9..])?;
                    if memcmp::eq(&mac.sum()?, &record[5..9]) {
                        continue;
                    }
                    self.relay.ignore = None;
                }
                self.rx.update(&record[9..])?;
                let sum = self.rx.sum()?;
                if !memcmp::eq(&sum, &record[5..9]) {
                    return Err(invalid());
                }
                self.rx.update(&sum)?;
                self.pending = io::Cursor::new(record[9..].to_vec());
                if record.len() > 9 {
                    return self.pending.read(output);
                }
            }
            Err(invalid())
        }
    }
    impl Write for Verified {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            if input.is_empty() {
                return Ok(0);
            }
            let length = input.len().min(16384);
            self.tx.update(&input[..length])?;
            let sum = self.tx.sum()?;
            self.tx.update(&sum)?;
            let mut record = vec![23, 3, 3];
            record.extend_from_slice(&((length + 4) as u16).to_be_bytes());
            record.extend_from_slice(&sum);
            record.extend_from_slice(&input[..length]);
            self.relay.raw.write_all(&record)?;
            Ok(length)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.relay.raw.flush()
        }
    }

    pub fn run() -> Result<(), &'static str> {
        // endpoint, SNI, synthetic password, profile, root PEM file, target,
        // byte count and no-fault/corrupt. No credentials on argv or in output.
        let mut input = String::new();
        io::stdin()
            .take(8193)
            .read_to_string(&mut input)
            .map_err(|_| "input")?;
        let fields: Vec<_> = input.lines().collect();
        if input.len() > 8192 || fields.len() != 8 {
            return Err("input");
        }
        let endpoint: SocketAddr = fields[0].parse().map_err(|_| "input")?;
        let target: SocketAddr = fields[5].parse().map_err(|_| "input")?;
        let total: usize = fields[6].parse().map_err(|_| "input")?;
        if total == 0 || total > 10 * 1024 * 1024 {
            return Err("input");
        }
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| "config")?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|_| "config")?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| "config")?;
        builder.set_verify(SslVerifyMode::PEER);
        if fields[4] != "-" {
            builder.set_ca_file(fields[4]).map_err(|_| "root")?;
        }
        let profile = match fields[3] {
            "none" => None,
            "chrome120" => Some(ClientFingerprint::Chrome120),
            "chrome133" => Some(ClientFingerprint::Chrome133),
            "firefox120" => Some(ClientFingerprint::Firefox120),
            "safari16" => Some(ClientFingerprint::Safari16),
            _ => return Err("input"),
        };
        let mut config = if let Some(profile) = profile {
            FingerprintConnector::new(builder, profile)
                .map_err(|_| "config")?
                .configure(&[])
                .map_err(|_| "config")?
        } else {
            builder.build().configure().map_err(|_| "config")?
        };
        config
            .set_shadow_tls_v3_client(fields[2].as_bytes())
            .map_err(|_| "config")?;
        let ssl = config.into_ssl(fields[1]).map_err(|_| "config")?;
        let raw =
            TcpStream::connect_timeout(&endpoint, Duration::from_secs(5)).map_err(|_| "dial")?;
        raw.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "timeout")?;
        raw.set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "timeout")?;
        let relay = Relay {
            raw,
            password: fields[2].as_bytes().to_vec(),
            seed: None,
            mask: [0; 32],
            ignore: None,
            pending: io::Cursor::new(Vec::new()),
            authorized: false,
            corrupt: fields[7] == "corrupt",
        };
        let mut tls = SslStream::new(ssl, relay).map_err(|_| "config")?;
        if let Err(error) = tls.connect() {
            let timeout = error.io_error().is_some_and(|e| {
                matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                )
            });
            println!(
                "{{\"status\":\"{}\",\"stage\":\"handshake\"}}",
                if timeout { "timeout" } else { "rejected" }
            );
            return Ok(());
        }
        let version = if tls.ssl().version2() == Some(SslVersion::TLS1_3) {
            "TLS1.3"
        } else {
            "TLS1.2"
        };
        let hrr = tls.ssl().used_hello_retry_request();
        let mut io = Verified::new(tls.into_inner()).map_err(|_| "relay-authentication")?;
        let mut header = vec![0];
        header.extend_from_slice(&[7; 16]);
        header.extend_from_slice(&[0, 1]);
        header.extend_from_slice(&target.port().to_be_bytes());
        match target.ip() {
            IpAddr::V4(ip) => {
                header.push(1);
                header.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                header.push(3);
                header.extend_from_slice(&ip.octets());
            }
        }
        io.write_all(&header).map_err(|_| "vless-header")?;
        io.flush().map_err(|_| "flush")?;
        let mut response = [0; 2];
        io.read_exact(&mut response).map_err(|_| "vless-response")?;
        if response != [0, 0] {
            return Err("vless-response");
        }
        let mut greeting = [0; 5];
        io.read_exact(&mut greeting).map_err(|_| "server-first")?;
        if greeting != *b"hello" {
            return Err("server-first");
        }
        let mut received = [0; 4096];
        for offset in (0..total).step_by(4096) {
            let length = (total - offset).min(4096);
            io.write_all(&vec![(offset / 4096) as u8; length])
                .map_err(|_| "data-write")?;
            io.read_exact(&mut received[..length])
                .map_err(|_| "data-read")?;
            if received[..length]
                .iter()
                .any(|b| *b != (offset / 4096) as u8)
            {
                return Err("data-mismatch");
            }
        }
        drop(io);
        println!("{{\"status\":\"passed\",\"version\":\"{version}\",\"hrr\":{hrr},\"bytes_each_way\":{total}}}");
        Ok(())
    }
}
