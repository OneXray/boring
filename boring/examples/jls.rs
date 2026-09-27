//! Client-only native JLS probe. Isolated synthetic peers; no resolver/listener.
#[cfg(not(all(feature = "jls", feature = "client-fingerprint")))]
fn main() {
    eprintln!("jls and client-fingerprint features required");
    std::process::exit(2);
}

#[cfg(all(feature = "jls", feature = "client-fingerprint"))]
fn main() {
    if let Err(stage) = probe::run() {
        println!("{{\"status\":\"failed\",\"stage\":\"{stage}\"}}");
        std::process::exit(1);
    }
}

#[cfg(all(feature = "jls", feature = "client-fingerprint"))]
mod probe {
    use boring::ssl::{
        ClientFingerprint, FingerprintConnector, SslConnector, SslMethod, SslStream, SslVersion,
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
        finished: AtomicUsize,
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
        if write != 0 || kind != 22 || length == 0 || bytes.is_null() || arg.is_null() {
            return;
        }
        // Read-only native callback. Its owner outlives SSL; no hello/secret
        // bytes are retained or modified, only two message counts.
        let state = unsafe { &*arg.cast::<Observations>() };
        match unsafe { *bytes.cast::<u8>() } {
            15 => {
                state.certificate_verify.fetch_add(1, Ordering::Relaxed);
            }
            20 => {
                state.finished.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    struct FaultIo {
        raw: TcpStream,
        pending: io::Cursor<Vec<u8>>,
        fault: u8,
    }
    impl Read for FaultIo {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if output.is_empty() {
                return Ok(0);
            }
            if self.pending.position() as usize == self.pending.get_ref().len() {
                let mut header = [0; 5];
                self.raw.read_exact(&mut header)?;
                let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
                if size > 18_432 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let mut record = header.to_vec();
                record.resize(5 + size, 0);
                self.raw.read_exact(&mut record[5..])?;
                if self.fault == 1 && record[0] == 22 && size >= 38 && record[5] == 2 {
                    record[11] ^= 1;
                    self.fault = 0;
                } else if self.fault == 2 && record[0] == 23 && size != 0 {
                    *record.last_mut().unwrap() ^= 1;
                    self.fault = 0;
                }
                self.pending = io::Cursor::new(record);
            }
            self.pending.read(output)
        }
    }
    impl Write for FaultIo {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.raw.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.raw.flush()
        }
    }

    pub fn run() -> Result<(), &'static str> {
        let mut input = String::new();
        io::stdin()
            .take(65_537)
            .read_to_string(&mut input)
            .map_err(|_| "input")?;
        let fields: Vec<_> = input.lines().collect();
        if input.len() > 65_536 || fields.len() != 8 {
            return Err("input");
        }
        let endpoint: SocketAddr = fields[0].parse().map_err(|_| "input")?;
        let target: SocketAddr = fields[5].parse().map_err(|_| "input")?;
        let total: usize = fields[7].parse().map_err(|_| "input")?;
        if total != 10 * 1024 * 1024 {
            return Err("input");
        }
        let fault = match fields[6] {
            "none" => 0,
            "server-random" => 1,
            "encrypted-record" => 2,
            _ => return Err("input"),
        };
        let profile = match fields[4] {
            "none" => None,
            "chrome120" => Some(ClientFingerprint::Chrome120),
            "chrome133" => Some(ClientFingerprint::Chrome133),
            "firefox120" => Some(ClientFingerprint::Firefox120),
            "safari16" => Some(ClientFingerprint::Safari16),
            _ => return Err("input"),
        };
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| "config")?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|_| "config")?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| "config")?;
        let mut config = if let Some(profile) = profile {
            FingerprintConnector::new(builder, profile)
                .map_err(|_| "config")?
                .configure(&[])
                .map_err(|_| "config")?
        } else {
            builder.build().configure().map_err(|_| "config")?
        };
        config
            .set_jls_client(fields[2].as_bytes(), fields[3].as_bytes())
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
        let raw =
            TcpStream::connect_timeout(&endpoint, Duration::from_secs(5)).map_err(|_| "dial")?;
        raw.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "timeout")?;
        raw.set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "timeout")?;
        let mut tls = SslStream::new(
            ssl,
            FaultIo {
                raw,
                pending: io::Cursor::new(Vec::new()),
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
        let finished = observed.finished.load(Ordering::Relaxed);
        if tls.ssl().version2() != Some(SslVersion::TLS1_3)
            || tls.ssl().used_hello_retry_request()
            || cv != 1
            || finished != 1
        {
            return Err("native-authentication");
        }
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
        tls.write_all(&header).map_err(|_| "vless-header")?;
        tls.flush().map_err(|_| "flush")?;
        let mut greeting = [0; 7];
        tls.read_exact(&mut greeting).map_err(|_| "server-first")?;
        if greeting != *b"\0\0hello" {
            return Err("server-first");
        }
        let mut received = [0; 4096];
        for offset in (0..total).step_by(4096) {
            let payload = [(offset / 4096) as u8; 4096];
            tls.write_all(&payload).map_err(|_| "write")?;
            tls.read_exact(&mut received).map_err(|_| "read")?;
            if received != payload {
                return Err("data");
            }
        }
        drop(tls);
        println!("{{\"status\":\"passed\",\"version\":\"TLS1.3\",\"certificate_verify\":{cv},\"finished\":{finished},\"bytes_each_way\":{total}}}");
        Ok(())
    }
}
