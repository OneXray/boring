//! Client-only N7 fork probe. Peers must be isolated containers. This is not a
//! VCore outbound, resolver, socket-protection, or lifecycle acceptance test.
#[cfg(not(all(feature = "reality", feature = "client-fingerprint")))]
fn main() {
    eprintln!("reality and client-fingerprint features required");
    std::process::exit(2);
}

#[cfg(all(feature = "reality", feature = "client-fingerprint"))]
fn main() {
    if let Err(stage) = probe() {
        // Only fixed stage names, never connection/configuration error strings.
        println!("{{\"status\":\"failed\",\"stage\":\"{stage}\"}}");
        std::process::exit(1);
    }
}

#[cfg(all(feature = "reality", feature = "client-fingerprint"))]
fn probe() -> Result<(), &'static str> {
    use boring::ssl::{
        ClientFingerprint, FingerprintConnector, RealityClientConfig, SslConnector, SslMethod,
        SslStream, SslVerifyMode, SslVersion,
    };
    use foreign_types::ForeignTypeRef;
    use std::{
        io::{Read, Write},
        net::{IpAddr, SocketAddr, TcpStream},
        time::Duration,
    };

    // Eight stdin lines: endpoint, SNI, public key hex, short ID hex,
    // classic/hybrid, native/chrome, target IP:port (or '-'), payload bytes.
    let mut input = String::new();
    std::io::stdin()
        .take(4097)
        .read_to_string(&mut input)
        .map_err(|_| "input")?;
    let fields: Vec<_> = input.lines().collect();
    if input.len() > 4096 || fields.len() != 8 {
        return Err("input");
    }
    let endpoint: SocketAddr = fields[0].parse().map_err(|_| "input")?;
    let public: [u8; 32] = hex::decode(fields[2])
        .map_err(|_| "input")?
        .try_into()
        .map_err(|_| "input")?;
    let short_id = hex::decode(fields[3]).map_err(|_| "input")?;
    let mut reality =
        RealityClientConfig::new(public, &short_id, [1, 8, 2]).map_err(|_| "config")?;
    match fields[4] {
        "hybrid" => reality = reality.require_x25519mlkem768(),
        "classic" => {}
        _ => return Err("input"),
    }
    let total: usize = fields[7].parse().map_err(|_| "input")?;
    if total > 10 * 1024 * 1024 {
        return Err("input");
    }
    let target: Option<SocketAddr> = if fields[6] == "-" {
        None
    } else {
        Some(fields[6].parse().map_err(|_| "input")?)
    };
    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| "config")?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|_| "config")?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|_| "config")?;
    // Prove that permissive external trust cannot bypass REALITY authentication.
    builder.set_custom_verify_callback(SslVerifyMode::NONE, |_| Ok(()));
    let mut configuration = match fields[5] {
        "chrome" => FingerprintConnector::new(builder, ClientFingerprint::Chrome133)
            .map_err(|_| "config")?
            .configure(b"\x08http/1.1")
            .map_err(|_| "config")?,
        "native" => {
            builder
                .set_curves_list(if fields[4] == "hybrid" {
                    "X25519MLKEM768"
                } else {
                    "X25519"
                })
                .map_err(|_| "config")?;
            builder.build().configure().map_err(|_| "config")?
        }
        _ => return Err("input"),
    };
    configuration
        .set_reality_client(&reality)
        .map_err(|_| "config")?;
    let ssl = configuration.into_ssl(fields[1]).map_err(|_| "config")?;
    let socket =
        TcpStream::connect_timeout(&endpoint, Duration::from_secs(5)).map_err(|_| "dial")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "timeout-config")?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "timeout-config")?;
    let mut stream = SslStream::new(ssl, socket).map_err(|_| "config")?;
    if let Err(error) = stream.connect() {
        let timeout = error.io_error().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )
        });
        let reason = error
            .ssl_error()
            .and_then(|stack| stack.errors().last())
            .map_or(0, |error| error.reason_code());
        println!(
            "{{\"status\":\"{}\",\"stage\":\"handshake\",\"reason_code\":{reason}}}",
            if timeout { "timeout" } else { "rejected" }
        );
        return Ok(());
    }
    // Read-only query on a live authenticated connection.
    let group = unsafe { boring_sys::SSL_get_group_id(stream.ssl().as_ptr()) };
    if let Some(target) = target {
        if total == 0 {
            return Err("input");
        }
        let mut header = vec![0];
        header.extend_from_slice(&[7; 16]); // Synthetic VLESS fixture identity.
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
        stream.write_all(&header).map_err(|_| "vless-header")?;
        let mut sent = 0;
        while sent < total {
            let size = (total - sent).min(16_384);
            let bytes: Vec<_> = (0..size).map(|i| ((sent + i) % 251) as u8).collect();
            stream.write_all(&bytes).map_err(|_| "data-write")?;
            stream.flush().map_err(|_| "data-flush")?;
            if sent == 0 {
                let mut response = [0; 2];
                stream
                    .read_exact(&mut response)
                    .map_err(|_| "vless-response")?;
                if response != [0, 0] {
                    return Err("vless-response");
                }
            }
            let mut echo = vec![0; size];
            stream.read_exact(&mut echo).map_err(|_| "data-read")?;
            if echo != bytes {
                return Err("data-integrity");
            }
            sent += size;
        }
    }
    println!("{{\"status\":\"passed\",\"group\":{group},\"bytes_each_way\":{total}}}");
    Ok(())
}
