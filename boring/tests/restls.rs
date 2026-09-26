#![cfg(feature = "restls")]

// A deterministic test hash identifies the exact public bytes passed to the
// native hook. Protocol interoperability separately uses official keyed BLAKE3.
use boring::{
    sha::sha256,
    ssl::{
        ErrorCode, RestlsClientConfig, RestlsVersionHint, Ssl, SslContext, SslMethod, SslStream,
        SslVersion,
    },
};
use std::io::{self, Read, Write};

#[derive(Default)]
struct Capture(Vec<u8>);

impl Read for Capture {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > 65_536usize.saturating_sub(self.0.len()) {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn ssl() -> Ssl {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    ctx.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_hostname("restls.invalid").unwrap();
    ssl
}

fn vector<'a>(bytes: &mut &'a [u8], width: usize) -> &'a [u8] {
    let length = match width {
        1 => usize::from(bytes[0]),
        2 => usize::from(u16::from_be_bytes(bytes[..2].try_into().unwrap())),
        _ => unreachable!(),
    };
    let result = &bytes[width..width + length];
    *bytes = &bytes[width + length..];
    result
}

fn hello(records: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    let mut remaining = records;
    while !remaining.is_empty() {
        assert_eq!(remaining[0], 22);
        let length = usize::from(u16::from_be_bytes(remaining[3..5].try_into().unwrap()));
        message.extend_from_slice(&remaining[5..5 + length]);
        remaining = &remaining[5 + length..];
    }
    assert_eq!(message[0], 1);
    assert_eq!(
        4 + u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize,
        message.len()
    );
    message
}

fn assert_tls13_auth(mut ssl: Ssl) {
    let config = RestlsClientConfig::new(RestlsVersionHint::Tls13, sha256);
    ssl.set_restls_client(&config).unwrap();
    assert!(!ssl.restls_authenticated());
    let mut stream = SslStream::new(ssl, Capture::default()).unwrap();
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    let bytes = hello(&stream.get_ref().0);
    let mut body = &bytes[38..];
    let session_id = vector(&mut body, 1);
    assert_eq!(session_id.len(), 32);
    let _ciphers = vector(&mut body, 2);
    let _compression = vector(&mut body, 1);
    let mut extensions = vector(&mut body, 2);
    assert!(body.is_empty());
    let mut hash_input = Vec::new();
    let mut found_shares = false;
    while !extensions.is_empty() {
        let kind = u16::from_be_bytes(extensions[..2].try_into().unwrap());
        extensions = &extensions[2..];
        let mut payload = vector(&mut extensions, 2);
        match kind {
            51 => {
                let mut shares = vector(&mut payload, 2);
                assert!(payload.is_empty());
                while !shares.is_empty() {
                    // GREASE shares are authenticated too. The lengths are not.
                    hash_input.extend_from_slice(&shares[..2]);
                    shares = &shares[2..];
                    hash_input.extend_from_slice(vector(&mut shares, 2));
                }
                found_shares = true;
            }
            41 => panic!("fresh test connection must not offer a session"),
            _ => {}
        }
    }
    assert!(found_shares);
    assert_eq!(&session_id[..16], &sha256(&hash_input)[..16]);
    assert!(!stream.ssl().restls_authenticated());
    let first_wire = stream.get_ref().0.clone();
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    assert_eq!(stream.get_ref().0, first_wire);
}

#[test]
fn tls13_hint_authenticates_exact_wire_key_shares_before_transcript_hashing() {
    assert_tls13_auth(ssl());
}

#[test]
fn official_rust_blake3_matches_the_mihomo_go_module_vector() {
    // Generated with metacubex/restls-client-go v0.1.9's locked blake3 module.
    let key = blake3::derive_key("restls-traffic-key", b"synthetic-restls-password");
    assert_eq!(
        hex::encode(key),
        "a561c8bab2a23ab1473e7fb00c50ffd3868b5d57873b556e5ddc468df804110a"
    );
    let input = hex::decode("0a0a00001d010203040506070809000000").unwrap();
    assert_eq!(
        blake3::keyed_hash(&key, &input).to_hex().as_str(),
        "e08e2f0e7fee912fe294ab0839d6e6c67ac97c3e5f7012aa5ad9a211db7d25c8"
    );
}

#[test]
fn incompatible_security_and_late_server_role_are_rejected_before_io() {
    use boring::ssl::RealityClientConfig;
    let config = RestlsClientConfig::new(RestlsVersionHint::Tls13, sha256);
    let reality = RealityClientConfig::new([9; 32], &[], [26, 7, 11]).unwrap();
    let mut client = ssl();
    client.set_restls_client(&config).unwrap();
    assert!(client.set_restls_client(&config).is_err());
    assert!(client.set_jls_client(b"user", b"password").is_err());
    assert!(client.set_shadow_tls_v3_client(b"password").is_err());
    assert!(client.set_reality_client(&reality).is_err());
    for earlier in [0, 1, 2] {
        let mut client = ssl();
        match earlier {
            0 => client.set_reality_client(&reality),
            1 => client.set_shadow_tls_v3_client(b"password"),
            _ => client.set_jls_client(b"user", b"password"),
        }
        .unwrap();
        assert!(client.set_restls_client(&config).is_err());
    }
    let mut server = ssl().setup_accept(Capture::default());
    assert!(server.ssl_mut().set_restls_client(&config).is_err());
    let mut client = ssl();
    client.set_restls_client(&config).unwrap();
    let mut server = SslStream::new(client, Capture::default()).unwrap();
    assert_eq!(server.accept().unwrap_err().code(), ErrorCode::SSL);
    assert!(server.get_ref().0.is_empty());
}

#[test]
fn callback_failure_early_data_and_lowered_tls_floor_fail_before_io() {
    use foreign_types::ForeignTypeRef;
    let config = RestlsClientConfig::new(RestlsVersionHint::Tls13, sha256);
    let mut client = ssl();
    client
        .set_restls_client(&RestlsClientConfig::new(RestlsVersionHint::Tls13, |_| {
            // This starts an unwind without invoking the process panic hook.
            // The public SSL call must still return an ordinary TLS error.
            std::panic::resume_unwind(Box::new("synthetic callback failure"))
        }))
        .unwrap();
    let mut stream = SslStream::new(client, Capture::default()).unwrap();
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
    assert!(stream.get_ref().0.is_empty());
    assert!(!stream.ssl().restls_authenticated());

    for late in [false, true] {
        let mut client = ssl();
        if late {
            client.set_restls_client(&config).unwrap();
        }
        unsafe { boring_sys::SSL_set_early_data_enabled(client.as_ptr(), 1) };
        if late {
            let mut stream = SslStream::new(client, Capture::default()).unwrap();
            assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
            assert!(stream.get_ref().0.is_empty());
        } else {
            assert!(client.set_restls_client(&config).is_err());
        }
    }
    let mut client = ssl();
    client.set_restls_client(&config).unwrap();
    client
        .set_min_proto_version(Some(SslVersion::TLS1_1))
        .unwrap();
    let mut stream = SslStream::new(client, Capture::default()).unwrap();
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
    assert!(stream.get_ref().0.is_empty());

    let context = SslContext::builder(SslMethod::dtls()).unwrap().build();
    assert!(Ssl::new(&context)
        .unwrap()
        .set_restls_client(&config)
        .is_err());
}

#[cfg(feature = "client-fingerprint")]
#[test]
fn named_hellos_include_grease_and_multiple_shares_in_authentication() {
    use boring::ssl::{ClientFingerprint, FingerprintConnector, SslConnector};
    for profile in [
        ClientFingerprint::Chrome120,
        ClientFingerprint::Chrome133,
        ClientFingerprint::Firefox120,
        ClientFingerprint::Safari16,
    ] {
        let connector =
            FingerprintConnector::new(SslConnector::builder(SslMethod::tls()).unwrap(), profile)
                .unwrap();
        assert_tls13_auth(
            connector
                .configure(b"\x02h2")
                .unwrap()
                .into_ssl("restls.invalid")
                .unwrap(),
        );
    }
}
