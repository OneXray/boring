#![cfg(feature = "shadow-tls-v3")]

// Public TLS interfaces and memory IO only. No local server/listener.
use boring::{
    hash::hmac_sha1,
    ssl::{ErrorCode, Ssl, SslContext, SslMethod, SslStream, SslVersion},
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
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn ssl(version: SslVersion) -> Ssl {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    ctx.set_max_proto_version(Some(version)).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_hostname("cover.invalid").unwrap();
    ssl
}

fn verify_hello(wire: &[u8], password: &[u8]) -> [u8; 32] {
    assert_eq!(wire[0], 22);
    let length = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    let mut message = wire[5..5 + length].to_vec();
    assert_eq!(message[0], 1);
    assert_eq!(message[38], 32);
    let session: [u8; 32] = message[39..71].try_into().unwrap();
    message[67..71].fill(0);
    assert_eq!(&session[28..], &hmac_sha1(password, &message).unwrap()[..4]);
    session
}

#[test]
fn exact_encoded_hello_has_authenticated_sid_for_both_tls_versions() {
    let password = b"synthetic-shadow-tls-password";
    let mut previous = None;
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        for _ in 0..3 {
            let mut ssl = ssl(version);
            ssl.set_shadow_tls_v3_client(password).unwrap();
            let mut stream = SslStream::new(ssl, Capture::default()).unwrap();
            assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
            let session = verify_hello(&stream.get_ref().0, password);
            assert_ne!(previous, Some(session));
            previous = Some(session);
            let hello = stream.get_ref().0.clone();
            assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
            assert_eq!(stream.get_ref().0, hello, "a pending retry must not reseal");
        }
    }
}

#[test]
fn invalid_duplicate_late_and_mutually_exclusive_configuration_is_rejected() {
    use boring::ssl::RealityClientConfig;
    let reality = RealityClientConfig::new([9; 32], &[], [1, 8, 0]).unwrap();
    let password = b"synthetic-shadow-tls-password";
    for invalid in [Vec::new(), vec![7; 65536]] {
        assert!(ssl(SslVersion::TLS1_3)
            .set_shadow_tls_v3_client(&invalid)
            .is_err());
    }
    let mut first = ssl(SslVersion::TLS1_3);
    first.set_shadow_tls_v3_client(password).unwrap();
    assert!(first.set_shadow_tls_v3_client(password).is_err());
    assert!(first.set_reality_client(&reality).is_err());
    let mut second = ssl(SslVersion::TLS1_3);
    second.set_reality_client(&reality).unwrap();
    assert!(second.set_shadow_tls_v3_client(password).is_err());
    let dtls = SslContext::builder(SslMethod::dtls()).unwrap().build();
    assert!(Ssl::new(&dtls)
        .unwrap()
        .set_shadow_tls_v3_client(password)
        .is_err());
    let mut server = ssl(SslVersion::TLS1_3).setup_accept(Capture::default());
    assert!(server.ssl_mut().set_shadow_tls_v3_client(password).is_err());
    let mut late_server = ssl(SslVersion::TLS1_3);
    late_server.set_shadow_tls_v3_client(password).unwrap();
    let mut late_server = SslStream::new(late_server, Capture::default()).unwrap();
    assert_eq!(late_server.accept().unwrap_err().code(), ErrorCode::SSL);
    assert!(late_server.get_ref().0.is_empty());
    let mut late = SslStream::new(ssl(SslVersion::TLS1_3), Capture::default()).unwrap();
    assert_eq!(late.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    assert!(late.ssl_mut().set_shadow_tls_v3_client(password).is_err());
}

#[test]
fn password_is_owned_and_late_incompatible_settings_fail_before_io() {
    use foreign_types::ForeignTypeRef;
    let password = b"synthetic-owned-password";
    let mut copy = password.to_vec();
    let mut client = ssl(SslVersion::TLS1_3);
    client.set_shadow_tls_v3_client(&copy).unwrap();
    copy.fill(0);
    let mut stream = SslStream::new(client, Capture::default()).unwrap();
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    verify_hello(&stream.get_ref().0, password);

    for late in [false, true] {
        let mut client = ssl(SslVersion::TLS1_3);
        if late {
            client.set_shadow_tls_v3_client(password).unwrap();
        }
        // Exercise the native public option used by third-party callers too.
        unsafe { boring_sys::SSL_set_early_data_enabled(client.as_ptr(), 1) };
        if late {
            let mut stream = SslStream::new(client, Capture::default()).unwrap();
            assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
            assert!(stream.get_ref().0.is_empty());
        } else {
            assert!(client.set_shadow_tls_v3_client(password).is_err());
        }
    }
    let mut client = ssl(SslVersion::TLS1_3);
    client.set_shadow_tls_v3_client(password).unwrap();
    client
        .set_min_proto_version(Some(SslVersion::TLS1_1))
        .unwrap();
    let mut stream = SslStream::new(client, Capture::default()).unwrap();
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
    assert!(stream.get_ref().0.is_empty());
}
