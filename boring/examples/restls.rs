//! Client-only Restls native hook probe. All real peers must be isolated.
#[cfg(not(all(feature = "restls", feature = "client-fingerprint")))]
fn main() {
    eprintln!("restls and client-fingerprint features required");
    std::process::exit(2);
}

#[cfg(all(feature = "restls", feature = "client-fingerprint"))]
fn main() {
    if let Err(stage) = probe::run() {
        println!("{{\"status\":\"failed\",\"stage\":\"{stage}\"}}");
        std::process::exit(1);
    }
}

#[cfg(all(feature = "restls", feature = "client-fingerprint"))]
mod probe {
    use boring::ssl::{
        ClientFingerprint, ErrorCode, FingerprintConnector, RestlsClientConfig, RestlsVersionHint,
        SslConnector, SslFiletype, SslMethod, SslStream, SslVersion,
    };
    use foreign_types::ForeignTypeRef;
    use std::{
        ffi::c_void,
        io::{self, Read, Write},
        net::{IpAddr, SocketAddr, TcpStream},
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[derive(Default)]
    struct Observations {
        certificate_verify: AtomicUsize,
        server_key_exchange: AtomicUsize,
        finished: AtomicUsize,
        client_certificate_verify: AtomicUsize,
    }

    unsafe extern "C" fn observe(
        write: i32,
        _: i32,
        kind: i32,
        bytes: *const c_void,
        length: usize,
        _: *mut boring_sys::SSL,
        arg: *mut c_void,
    ) {
        if kind != 22 || length == 0 || bytes.is_null() || arg.is_null() {
            return;
        }
        let state = unsafe { &*arg.cast::<Observations>() };
        if write != 0 {
            if unsafe { *bytes.cast::<u8>() } == 15 {
                state
                    .client_certificate_verify
                    .fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        match unsafe { *bytes.cast::<u8>() } {
            12 => &state.server_key_exchange,
            15 => &state.certificate_verify,
            20 => &state.finished,
            _ => return,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    fn record(raw: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut header = [0; 5];
        raw.read_exact(&mut header)?;
        let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if size > 18_432 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = header.to_vec();
        bytes.resize(5 + size, 0);
        raw.read_exact(&mut bytes[5..])?;
        Ok(bytes)
    }

    struct NativeIo {
        raw: TcpStream,
        pending: io::Cursor<Vec<u8>>,
        capture: Vec<u8>,
        last_write: Vec<u8>,
        controlled: bool,
        ccs: bool,
        tls12_hint: bool,
        first_encrypted_zero_nonce: Option<bool>,
        tls13_server_records: u64,
        tls13_client_records: u64,
        fault: u8,
    }

    impl Read for NativeIo {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if out.is_empty() {
                return Ok(0);
            }
            if self.pending.position() as usize == self.pending.get_ref().len() {
                if self.controlled {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let mut bytes = record(&mut self.raw)?;
                if bytes[0] == 23 {
                    self.tls13_server_records += 1;
                }
                let encrypted = bytes[0] == 23 || (self.tls12_hint && self.ccs && bytes[0] == 22);
                if encrypted && self.first_encrypted_zero_nonce.is_none() {
                    self.first_encrypted_zero_nonce = Some(bytes.get(5..13) == Some(&[0; 8]));
                    if self.fault == 2 {
                        *bytes.last_mut().unwrap() ^= 1;
                        self.fault = 0;
                    }
                }
                if bytes[0] == 22 && bytes.len() >= 43 && bytes[5] == 2 && self.fault == 1 {
                    bytes[11] ^= 1;
                    self.fault = 0;
                }
                self.ccs |= bytes[0] == 20;
                self.pending = io::Cursor::new(bytes);
            }
            self.pending.read(out)
        }
    }

    impl Write for NativeIo {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let size = self.raw.write(bytes)?;
            if self.capture.len() + size > 65_536 {
                return Err(io::ErrorKind::OutOfMemory.into());
            }
            self.capture.extend_from_slice(&bytes[..size]);
            while self.capture.len() >= 5 {
                let length =
                    usize::from(u16::from_be_bytes(self.capture[3..5].try_into().unwrap()));
                if length > 18_432 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                if self.capture.len() < 5 + length {
                    break;
                }
                self.last_write = self.capture.drain(..5 + length).collect();
                if self.last_write[0] == 23 {
                    self.tls13_client_records += 1;
                }
            }
            Ok(size)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.raw.flush()
        }
    }

    // Minimal blocking protocol consumer, not VCore's asynchronous adapter.
    // Native SSL is retained to authenticate and consume delayed cover records.
    struct RestlsStream {
        tls: SslStream<NativeIo>,
        key: [u8; 32],
        random: [u8; 32],
        sent: u64,
        received: u64,
        real_received: u64,
        gcm12: bool,
        gcm_counter: bool,
        finished: Option<Vec<u8>>,
        pending: io::Cursor<Vec<u8>>,
        tail_records: usize,
    }

    impl Drop for RestlsStream {
        fn drop(&mut self) {
            unsafe { boring_sys::OPENSSL_cleanse(self.key.as_mut_ptr().cast(), self.key.len()) };
        }
    }

    impl RestlsStream {
        fn hash(&self, receiving: bool) -> blake3::Hasher {
            let mut hash = blake3::Hasher::new_keyed(&self.key);
            hash.update(&self.random);
            hash.update(if receiving {
                b"server-to-client"
            } else {
                b"client-to-server"
            });
            hash.update(&if receiving { self.received } else { self.sent }.to_be_bytes());
            hash
        }

        fn send(&mut self, data: &[u8]) -> io::Result<()> {
            if data.len() > 4096 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let padding = if data.is_empty() { 32 } else { 0 };
            let prefix = if self.gcm12 { 13 } else { 5 };
            let mut bytes = vec![0; prefix + 12 + data.len() + padding];
            bytes[..3].copy_from_slice(&[23, 3, 3]);
            let size = (bytes.len() - 5) as u16;
            bytes[3..5].copy_from_slice(&size.to_be_bytes());
            if self.gcm12 {
                bytes[5..13].copy_from_slice(&(self.sent + 1).to_be_bytes());
            }
            bytes[prefix + 8..prefix + 10].copy_from_slice(&(data.len() as u16).to_be_bytes());
            bytes[prefix + 12..prefix + 12 + data.len()].copy_from_slice(data);
            if padding != 0 {
                boring::rand::rand_bytes(&mut bytes[prefix + 12..])?;
            }
            let mut mask = self.hash(false);
            mask.update(&bytes[prefix + 12..][..(data.len() + padding).min(32)]);
            for (byte, mask) in bytes[prefix + 8..prefix + 12]
                .iter_mut()
                .zip(mask.finalize().as_bytes())
            {
                *byte ^= mask;
            }
            let mut auth = self.hash(false);
            if let Some(finished) = self.finished.take() {
                auth.update(&finished);
            }
            auth.update(&bytes[..prefix]);
            auth.update(&bytes[prefix + 8..]);
            bytes[prefix..prefix + 8].copy_from_slice(&auth.finalize().as_bytes()[..8]);
            self.tls.get_mut().raw.write_all(&bytes)?;
            self.sent = self.sent.checked_add(1).ok_or(io::ErrorKind::InvalidData)?;
            Ok(())
        }

        fn decode(&self, record: &[u8]) -> Option<(Vec<u8>, u8)> {
            let prefix = if self.gcm_counter { 13 } else { 5 };
            if record[0] != 23 || record.len() < prefix + 12 {
                return None;
            }
            if self.gcm_counter && record[5..13] != (self.received + 1).to_be_bytes() {
                return None;
            }
            let mut auth = self.hash(true);
            auth.update(&record[..prefix]);
            auth.update(&record[prefix + 8..]);
            if !boring::memcmp::eq(
                &record[prefix..prefix + 8],
                &auth.finalize().as_bytes()[..8],
            ) {
                return None;
            }
            let mut mask = self.hash(true);
            mask.update(&record[prefix + 12..][..(record.len() - prefix - 12).min(32)]);
            let mut fields: [u8; 4] = record[prefix + 8..prefix + 12].try_into().unwrap();
            for (byte, mask) in fields.iter_mut().zip(mask.finalize().as_bytes()) {
                *byte ^= mask;
            }
            let size = usize::from(u16::from_be_bytes([fields[0], fields[1]]));
            if size > record.len() - prefix - 12 || fields[2] > 1 {
                return None;
            }
            Some((
                record[prefix + 12..prefix + 12 + size].to_vec(),
                if fields[2] == 1 { fields[3] } else { 0 },
            ))
        }

        fn receive(&mut self) -> io::Result<Vec<u8>> {
            for _ in 0..64 {
                let mut bytes = record(&mut self.tls.get_mut().raw)?;
                if let Some((data, response)) = self.decode(&bytes) {
                    self.received = self
                        .received
                        .checked_add(1)
                        .ok_or(io::ErrorKind::InvalidData)?;
                    for _ in 0..response {
                        self.send(&[])?;
                    }
                    if !data.is_empty() {
                        return Ok(data);
                    }
                    continue;
                }
                if self.gcm_counter && bytes.len() >= 13 {
                    self.real_received += 1;
                    bytes[5..13].copy_from_slice(&self.real_received.to_be_bytes());
                }
                self.tls.get_mut().pending = io::Cursor::new(bytes);
                let mut discarded = [0; 16_384];
                loop {
                    match self.tls.ssl_read(&mut discarded) {
                        Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                        Ok(_) => {}
                        Err(error) if error.code() == ErrorCode::WANT_READ => break,
                        Err(_) => return Err(io::ErrorKind::InvalidData.into()),
                    }
                }
                self.received += 1;
                self.tail_records += 1;
            }
            Err(io::ErrorKind::InvalidData.into())
        }
    }

    impl Read for RestlsStream {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if output.is_empty() {
                return Ok(0);
            }
            if self.pending.position() as usize == self.pending.get_ref().len() {
                self.pending = io::Cursor::new(self.receive()?);
            }
            self.pending.read(output)
        }
    }

    pub fn run() -> Result<(), &'static str> {
        let mut input = String::new();
        io::stdin()
            .take(65_537)
            .read_to_string(&mut input)
            .map_err(|_| "input")?;
        let fields: Vec<_> = input.lines().collect();
        if input.len() > 65_536 || fields.len() != 10 {
            return Err("input");
        }
        let resume = match fields[9] {
            "normal" | "mtls" | "cbc" => false,
            "resume" => true,
            _ => return Err("input"),
        };
        let endpoint: SocketAddr = fields[0].parse().map_err(|_| "input")?;
        let target: SocketAddr = fields[6].parse().map_err(|_| "input")?;
        let total: usize = fields[8].parse().map_err(|_| "input")?;
        if total != 10 * 1024 * 1024 {
            return Err("input");
        }
        let hint = match fields[4] {
            "tls12" => RestlsVersionHint::Tls12,
            "tls13" => RestlsVersionHint::Tls13,
            _ => return Err("input"),
        };
        let profile = match fields[5] {
            "none" => None,
            "chrome120" => Some(ClientFingerprint::Chrome120),
            "chrome133" => Some(ClientFingerprint::Chrome133),
            "firefox120" => Some(ClientFingerprint::Firefox120),
            "safari16" => Some(ClientFingerprint::Safari16),
            _ => return Err("input"),
        };
        let fault = match fields[7] {
            "none" => 0,
            "server-random" => 1,
            "encrypted-record" => 2,
            _ => return Err("input"),
        };
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| "config")?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|_| "config")?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| "config")?;
        builder.set_ca_file(fields[2]).map_err(|_| "config")?;
        if fields[9] == "mtls" {
            builder
                .set_certificate_file(fields[2], SslFiletype::PEM)
                .map_err(|_| "config")?;
            builder
                .set_private_key_file(
                    std::path::Path::new(fields[2]).with_file_name("key.pem"),
                    SslFiletype::PEM,
                )
                .map_err(|_| "config")?;
        }
        if fields[9] == "cbc" {
            builder
                .set_cipher_list("ECDHE-RSA-AES128-SHA")
                .map_err(|_| "config")?;
        }
        let (fingerprint, standard) = if let Some(profile) = profile {
            (
                Some(FingerprintConnector::new(builder, profile).map_err(|_| "config")?),
                None,
            )
        } else {
            (None, Some(builder.build()))
        };
        let key = blake3::derive_key("restls-traffic-key", fields[3].as_bytes());
        let mut session: Option<boring::ssl::SslSession> = None;
        let mut rounds = Vec::new();
        for round in 0..if resume { 2 } else { 1 } {
            let mut config = if let Some(fingerprint) = &fingerprint {
                fingerprint.configure(&[]).map_err(|_| "config")?
            } else {
                standard
                    .as_ref()
                    .ok_or("config")?
                    .configure()
                    .map_err(|_| "config")?
            };
            if let Some(session) = &session {
                // Both connections use the same immutable connector/context.
                unsafe { config.set_session(session) }.map_err(|_| "session")?;
            }
            config
                .set_restls_client(&RestlsClientConfig::new(hint, move |data| {
                    *blake3::keyed_hash(&key, data).as_bytes()
                }))
                .map_err(|_| "config")?;
            let ssl = config.into_ssl(fields[1]).map_err(|_| "config")?;
            let observed = Box::<Observations>::default();
            unsafe {
                boring_sys::SSL_set_msg_callback(ssl.as_ptr(), Some(observe));
                boring_sys::SSL_set_msg_callback_arg(
                    ssl.as_ptr(),
                    (&*observed as *const Observations).cast_mut().cast(),
                );
            }
            let raw = TcpStream::connect_timeout(&endpoint, Duration::from_secs(5))
                .map_err(|_| "dial")?;
            raw.set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| "timeout")?;
            raw.set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| "timeout")?;
            let mut tls = SslStream::new(
                ssl,
                NativeIo {
                    raw,
                    pending: io::Cursor::new(Vec::new()),
                    capture: Vec::new(),
                    last_write: Vec::new(),
                    controlled: false,
                    ccs: false,
                    tls12_hint: hint == RestlsVersionHint::Tls12,
                    first_encrypted_zero_nonce: None,
                    tls13_server_records: 0,
                    tls13_client_records: 0,
                    fault,
                },
            )
            .map_err(|_| "config")?;
            if let Err(error) = tls.connect() {
                let timeout = error.io_error().is_some_and(|e| {
                    matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    )
                });
                let injected = fault != 0 && tls.get_ref().fault == 0;
                println!(
                    "{{\"status\":\"{}\",\"stage\":\"handshake\",\"fault_injected\":{injected}}}",
                    if timeout { "timeout" } else { "rejected" }
                );
                return Ok(());
            }
            let cv = observed.certificate_verify.load(Ordering::Relaxed);
            let client_cv = observed.client_certificate_verify.load(Ordering::Relaxed);
            let ske = observed.server_key_exchange.load(Ordering::Relaxed);
            let finished_count = observed.finished.load(Ordering::Relaxed);
            let tls13 = tls.ssl().version2() == Some(SslVersion::TLS1_3);
            let reused = tls.ssl().session_reused();
            if !tls.ssl().restls_authenticated()
                || finished_count != 1
                || reused != (round != 0)
                || (tls13 && cv != usize::from(!reused))
                || (!tls13 && ske != usize::from(!reused))
                || client_cv != usize::from(fields[9] == "mtls")
            {
                return Err("native-authentication");
            }
            session = tls.ssl().session().map(|s| s.to_owned());
            let gcm12 = !tls13
                && tls
                    .ssl()
                    .current_cipher()
                    .ok_or("cipher")?
                    .name()
                    .contains("GCM");
            let gcm_counter = gcm12 && tls.get_ref().first_encrypted_zero_nonce == Some(true);
            let finished =
                (tls13 || tls.ssl().session_reused()).then(|| tls.get_ref().last_write.clone());
            // Mirror the official server's accountTLS13EarlyTargetRecords.
            // BoringSSL may coalesce an mTLS client flight into one record;
            // counting messages instead would silently disagree with Mihomo.
            // This is deterministic wire accounting, not a search for a MAC
            // that verifies and not permission to skip any native TLS record.
            let server_records = tls.get_ref().tls13_server_records;
            let client_records = tls.get_ref().tls13_client_records;
            let initial_received = if tls13 {
                let expected = if reused {
                    1
                } else if client_records > 1 {
                    4
                } else {
                    3
                };
                server_records.saturating_sub(1 + expected)
            } else {
                0
            };
            let mut random = [0; 32];
            if tls.ssl().server_random(&mut random) != 32 {
                return Err("server-random");
            }
            tls.get_mut().controlled = true;
            let mut stream = RestlsStream {
                tls,
                key,
                random,
                sent: 0,
                received: initial_received,
                real_received: 0,
                gcm12,
                gcm_counter,
                finished,
                pending: io::Cursor::new(Vec::new()),
                tail_records: 0,
            };
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
            stream.send(&header).map_err(|_| "vless-header")?;
            let mut greeting = [0; 7];
            stream
                .read_exact(&mut greeting)
                .map_err(|_| "server-first")?;
            if greeting != *b"\0\0hello" {
                return Err("server-first");
            }
            let mut received = [0; 4096];
            for offset in (0..total).step_by(4096) {
                let payload = [(offset / 4096) as u8; 4096];
                stream.send(&payload).map_err(|_| "write")?;
                stream.read_exact(&mut received).map_err(|_| "read")?;
                if received != payload {
                    return Err("data");
                }
            }
            let tails = stream.tail_records;
            drop(stream);
            rounds.push(format!("{{\"version\":\"{}\",\"certificate_verify\":{cv},\"client_certificate_verify\":{client_cv},\"server_key_exchange\":{ske},\"finished\":{finished_count},\"cover_tail_records\":{tails},\"bytes_each_way\":{total},\"session_reused\":{reused},\"gcm_explicit_counter\":{gcm_counter},\"tls13_server_records\":{server_records},\"tls13_client_records\":{client_records},\"initial_received_counter\":{initial_received}}}", if tls13 {"TLS1.3"} else {"TLS1.2"}));
        }
        println!(
            "{{\"status\":\"passed\",\"rounds\":[{}]}}",
            rounds.join(",")
        );
        Ok(())
    }
}
