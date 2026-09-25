#![cfg(feature = "client-fingerprint")]
//! Named profile integration over memory IO; never starts a network listener.
use boring::{
    pkey::PKey,
    ssl::{
        select_next_proto, AlpnError, CertificateCompressionAlgorithm, CertificateCompressor,
        ClientFingerprint, FingerprintConnector, Ssl, SslAcceptor, SslAcceptorBuilder, SslAlert,
        SslConnector, SslMethod, SslVerifyError, SslVerifyMode, SslVersion,
    },
    x509::X509,
};
use foreign_types::ForeignTypeRef;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn server() -> SslAcceptorBuilder {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder
        .set_certificate(&X509::from_pem(include_bytes!("cert.pem")).unwrap())
        .unwrap();
    builder
        .set_private_key(&PKey::private_key_from_pem(include_bytes!("key.pem")).unwrap())
        .unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x02h2", offered).ok_or(AlpnError::ALERT_FATAL)
    });
    builder
}

#[tokio::test]
async fn named_profile_exposes_negotiated_peer_alps_not_just_the_advertisement() {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        for settings in [
            None,
            Some(b"".as_slice()),
            Some(b"\0\x03\0\0\0\x64".as_slice()),
        ] {
            let (io, peer) = tokio::io::duplex(4096);
            let server = tokio::spawn(async move {
                let acceptor = server().build();
                let ssl = Ssl::new(acceptor.context()).unwrap();
                if let Some(settings) = settings {
                    // Independent peer fixture uses the native public ALPS API.
                    unsafe {
                        boring_sys::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), 0);
                        assert_eq!(
                            boring_sys::SSL_add_application_settings(
                                ssl.as_ptr(),
                                b"h2".as_ptr(),
                                2,
                                settings.as_ptr(),
                                settings.len(),
                            ),
                            1
                        );
                    }
                }
                let mut tls = tokio_boring::SslStreamBuilder::new(ssl, peer)
                    .accept()
                    .await
                    .unwrap();
                assert_eq!(
                    tls.ssl().peer_application_settings(),
                    settings.map(|_| b"".as_slice())
                );
                tls.write_all(b"profile-ready").await.unwrap();
            });
            let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
            // This test-only certificate is not a system trust anchor.
            builder.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
            let connector =
                FingerprintConnector::new(builder, ClientFingerprint::Chrome120).unwrap();
            let mut config = connector.configure(b"\x02h2").unwrap();
            config.set_verify_hostname(false);
            let mut tls = tokio_boring::connect(config, "profile.test", io)
                .await
                .unwrap();
            assert_eq!(tls.ssl().peer_application_settings(), settings);
            let mut response = [0; 13];
            tls.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"profile-ready");
            server.await.unwrap();
        }
    })
    .await
    .unwrap();
}

struct Compress(Arc<AtomicBool>);
impl CertificateCompressor for Compress {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = false;
    fn compress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        self.0.store(true, Ordering::Relaxed);
        std::io::copy(
            &mut brotli::CompressorReader::new(input, 4096, 5, 22),
            output,
        )?;
        Ok(())
    }
}

#[tokio::test]
async fn named_profile_decodes_brotli_without_overriding_the_callers_verifier() {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        for trusted in [false, true] {
            let compressed = Arc::new(AtomicBool::new(false));
            let mut builder = server();
            builder
                .add_certificate_compression_algorithm(Compress(compressed.clone()))
                .unwrap();
            let (io, peer) = tokio::io::duplex(4096);
            let server = tokio::spawn(async move {
                let mut tls = match tokio_boring::accept(&builder.build(), peer).await {
                    Ok(tls) => tls,
                    Err(_) => return false,
                };
                tls.write_all(b"compressed-ready").await.is_ok()
            });
            let verified = Arc::new(AtomicBool::new(false));
            let called = verified.clone();
            let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
            builder.set_custom_verify_callback(SslVerifyMode::PEER, move |_| {
                called.store(true, Ordering::Relaxed);
                if trusted {
                    Ok(())
                } else {
                    Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))
                }
            });
            let connector =
                FingerprintConnector::new(builder, ClientFingerprint::Chrome120).unwrap();
            let mut config = connector.configure(b"\x02h2").unwrap();
            config.set_verify_hostname(false);
            let result = tokio_boring::connect(config, "profile.test", io).await;
            assert_eq!(result.is_ok(), trusted);
            if let Ok(mut tls) = result {
                let mut response = [0; 16];
                tls.read_exact(&mut response).await.unwrap();
                assert_eq!(&response, b"compressed-ready");
            }
            assert_eq!(server.await.unwrap(), trusted);
            assert!(compressed.load(Ordering::Relaxed));
            assert!(verified.load(Ordering::Relaxed));
        }
    })
    .await
    .unwrap();
}
