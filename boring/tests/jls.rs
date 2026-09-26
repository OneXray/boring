#![cfg(feature = "jls")]

// Exercise the public native hook with bounded memory IO, never a listener.
use boring::{
    sha::Sha256,
    ssl::{ErrorCode, Ssl, SslContext, SslMethod, SslStream, SslVersion},
    symm::{decrypt_aead, Cipher},
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
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > 65_536usize.saturating_sub(self.0.len()) {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
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
    ssl.set_hostname("jls.invalid").unwrap();
    ssl
}

fn auth_hash(value: &[u8], message: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(value);
    hash.update(message);
    hash.finish()
}

fn client_hello(records: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    let mut offset = 0;
    while offset < records.len() {
        assert_eq!(records[offset], 22);
        let length = usize::from(u16::from_be_bytes(
            records[offset + 3..offset + 5].try_into().unwrap(),
        ));
        message.extend_from_slice(&records[offset + 5..offset + 5 + length]);
        offset += 5 + length;
    }
    assert_eq!(message[0], 1);
    assert_eq!(
        4 + u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize,
        message.len()
    );
    message
}

fn accepts_random(username: &[u8], password: &[u8], message: &[u8]) -> bool {
    let mut auth = message.to_vec();
    auth[6..38].fill(0);
    decrypt_aead(
        Cipher::aes_256_gcm(),
        &auth_hash(password, &auth),
        Some(&auth_hash(username, &auth)),
        &[],
        &message[6..22],
        &message[22..38],
    )
    .is_ok_and(|seed| seed.len() == 16)
}

#[test]
fn exact_encoded_hello_authenticates_both_credentials_without_retry_resealing() {
    let username = b"synthetic-jls-user";
    let password = b"synthetic-jls-password";
    let mut previous = None;
    for _ in 0..3 {
        let mut ssl = ssl();
        ssl.set_jls_client(username, password).unwrap();
        let mut stream = SslStream::new(ssl, Capture::default()).unwrap();
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
        let wire = stream.get_ref().0.clone();
        let hello = client_hello(&wire);
        assert!(accepts_random(username, password, &hello));
        assert!(!accepts_random(b"other-user", password, &hello));
        assert!(!accepts_random(username, b"other-password", &hello));
        let mut tampered = hello.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(!accepts_random(username, password, &tampered));
        let random: [u8; 32] = hello[6..38].try_into().unwrap();
        assert_ne!(previous, Some(random));
        previous = Some(random);
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
        assert_eq!(stream.get_ref().0, wire);
    }
}

#[test]
fn credentials_are_owned_and_invalid_or_incompatible_connections_are_rejected() {
    use boring::ssl::RealityClientConfig;
    use foreign_types::ForeignTypeRef;
    let username = b"synthetic-user";
    let password = b"synthetic-password";
    let mut owned_user = username.to_vec();
    let mut owned_password = password.to_vec();
    let mut client = ssl();
    client.set_jls_client(&owned_user, &owned_password).unwrap();
    owned_user.fill(0);
    owned_password.fill(0);
    let mut stream = SslStream::new(client, Capture::default()).unwrap();
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    assert!(accepts_random(
        username,
        password,
        &client_hello(&stream.get_ref().0)
    ));
    assert!(stream.ssl_mut().set_jls_client(username, password).is_err());

    for invalid in [Vec::new(), vec![0; 65_536]] {
        assert!(ssl().set_jls_client(&invalid, password).is_err());
        assert!(ssl().set_jls_client(username, &invalid).is_err());
    }
    let reality = RealityClientConfig::new([9; 32], &[], [26, 7, 11]).unwrap();
    let mut first = ssl();
    first.set_jls_client(username, password).unwrap();
    assert!(first.set_jls_client(username, password).is_err());
    assert!(first.set_shadow_tls_v3_client(password).is_err());
    assert!(first.set_reality_client(&reality).is_err());
    let mut second = ssl();
    second.set_shadow_tls_v3_client(password).unwrap();
    assert!(second.set_jls_client(username, password).is_err());
    let mut third = ssl();
    third.set_reality_client(&reality).unwrap();
    assert!(third.set_jls_client(username, password).is_err());
    let dtls = SslContext::builder(SslMethod::dtls()).unwrap().build();
    assert!(Ssl::new(&dtls)
        .unwrap()
        .set_jls_client(username, password)
        .is_err());
    let mut server = ssl().setup_accept(Capture::default());
    assert!(server.ssl_mut().set_jls_client(username, password).is_err());
    let mut late_server = ssl();
    late_server.set_jls_client(username, password).unwrap();
    let mut late_server = SslStream::new(late_server, Capture::default()).unwrap();
    assert_eq!(late_server.accept().unwrap_err().code(), ErrorCode::SSL);
    assert!(late_server.get_ref().0.is_empty());

    for late in [false, true] {
        let mut client = ssl();
        if late {
            client.set_jls_client(username, password).unwrap();
        }
        unsafe { boring_sys::SSL_set_early_data_enabled(client.as_ptr(), 1) };
        if late {
            let mut stream = SslStream::new(client, Capture::default()).unwrap();
            assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
            assert!(stream.get_ref().0.is_empty());
        } else {
            assert!(client.set_jls_client(username, password).is_err());
        }
    }
    for (min, max) in [
        (SslVersion::TLS1_1, SslVersion::TLS1_3),
        (SslVersion::TLS1_2, SslVersion::TLS1_2),
    ] {
        let mut client = ssl();
        client.set_jls_client(username, password).unwrap();
        client.set_min_proto_version(Some(min)).unwrap();
        client.set_max_proto_version(Some(max)).unwrap();
        let mut stream = SslStream::new(client, Capture::default()).unwrap();
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
        assert!(stream.get_ref().0.is_empty());
    }
}

#[cfg(feature = "client-fingerprint")]
#[test]
fn all_named_profiles_authenticate_the_final_hello() {
    use boring::ssl::{ClientFingerprint, FingerprintConnector, SslConnector};
    for profile in [
        ClientFingerprint::Chrome120,
        ClientFingerprint::Chrome133,
        ClientFingerprint::Firefox120,
        ClientFingerprint::Safari16,
    ] {
        let builder = SslConnector::builder(SslMethod::tls()).unwrap();
        let connector = FingerprintConnector::new(builder, profile).unwrap();
        let mut client = connector
            .configure(b"\x02h2")
            .unwrap()
            .into_ssl("jls.invalid")
            .unwrap();
        client
            .set_jls_client(b"synthetic-user", b"synthetic-password")
            .unwrap();
        let mut stream = SslStream::new(client, Capture::default()).unwrap();
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
        assert!(accepts_random(
            b"synthetic-user",
            b"synthetic-password",
            &client_hello(&stream.get_ref().0)
        ));
    }
}
