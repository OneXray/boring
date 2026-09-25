#![cfg(feature = "client-fingerprint")]
//! Real native TLS over bounded memory IO; these are library, not network gates.
use boring::{
    pkey::PKey,
    ssl::{
        select_next_proto, AlpnError, ClientFingerprint, FingerprintConnector, Ssl, SslAcceptor,
        SslAcceptorBuilder, SslConnector, SslMethod, SslSession, SslSessionCacheMode,
        SslVerifyMode, SslVersion,
    },
    x509::X509,
};
use foreign_types::ForeignTypeRef;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct ForgedSignature;
impl boring::ssl::PrivateKeyMethod for ForgedSignature {
    fn sign(
        &self,
        _: &mut boring::ssl::SslRef,
        _: &[u8],
        _: boring::ssl::SslSignatureAlgorithm,
        output: &mut [u8],
    ) -> Result<usize, boring::ssl::PrivateKeyMethodError> {
        output[..256].fill(0); // Deliberately invalid RSA-2048 fixture signature.
        Ok(256)
    }
    fn decrypt(
        &self,
        _: &mut boring::ssl::SslRef,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, boring::ssl::PrivateKeyMethodError> {
        Err(boring::ssl::PrivateKeyMethodError::FAILURE)
    }
    fn complete(
        &self,
        _: &mut boring::ssl::SslRef,
        _: &mut [u8],
    ) -> Result<usize, boring::ssl::PrivateKeyMethodError> {
        Err(boring::ssl::PrivateKeyMethodError::FAILURE)
    }
}

fn server(version: SslVersion, group: &str) -> SslAcceptorBuilder {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    b.set_certificate(&X509::from_pem(include_bytes!("cert.pem")).unwrap())
        .unwrap();
    b.set_private_key(&PKey::private_key_from_pem(include_bytes!("key.pem")).unwrap())
        .unwrap();
    b.set_min_proto_version(Some(version)).unwrap();
    b.set_max_proto_version(Some(version)).unwrap();
    b.set_curves_list(group).unwrap();
    b.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x02h2", offered).ok_or(AlpnError::ALERT_FATAL)
    });
    b.set_session_id_context(b"selected-fingerprint-test")
        .unwrap();
    b
}

fn ecdsa_certificate(server: &mut SslAcceptorBuilder) {
    use boring::{
        asn1::Asn1Time,
        bn::BigNum,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        x509::X509Name,
    };
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "profile.test").unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    server.set_certificate(&cert.build()).unwrap();
    server.set_private_key(&key).unwrap();
}

async fn exchange_profile(
    profile: ClientFingerprint,
    version: SslVersion,
    group: &str,
    cipher: Option<&str>,
) {
    let mut acceptor = server(version, group);
    if let Some(cipher) = cipher {
        acceptor.set_strict_cipher_list(cipher).unwrap();
        if cipher.contains("ECDSA") {
            ecdsa_certificate(&mut acceptor);
        }
    }
    let cipher = cipher.map(str::to_owned);
    let (io, remote) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        let mut tls = tokio_boring::accept(&acceptor.build(), remote)
            .await
            .unwrap();
        if let Some(cipher) = cipher {
            assert_eq!(tls.ssl().current_cipher().unwrap().name(), cipher);
        }
        let mut request = [0; 4];
        tls.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        tls.write_all(b"pong").await.unwrap();
    });
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    b.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
    let connector = FingerprintConnector::new(b, profile).unwrap();
    let mut config = connector.configure(b"\x02h2").unwrap();
    config.set_verify_hostname(false);
    let mut tls = tokio_boring::connect(config, "profile.test", io)
        .await
        .unwrap();
    assert_eq!(tls.ssl().version2(), Some(version));
    tls.write_all(b"ping").await.unwrap();
    let mut response = [0; 4];
    tls.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    task.await.unwrap();
}

async fn classic_profile_suites(profile: ClientFingerprint) {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for group in ["X25519", "P-256", "P-384", "P-521"] {
            exchange_profile(profile, SslVersion::TLS1_3, group, None).await;
        }
        for cipher in [
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-ECDSA-AES128-SHA",
            "ECDHE-ECDSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-RSA-AES256-SHA",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-SHA",
            "AES256-SHA",
        ] {
            exchange_profile(profile, SslVersion::TLS1_2, "X25519", Some(cipher)).await;
        }
        if profile == ClientFingerprint::Safari16 {
            for cipher in ["ECDHE-RSA-DES-CBC3-SHA", "DES-CBC3-SHA"] {
                exchange_profile(profile, SslVersion::TLS1_2, "X25519", Some(cipher)).await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn firefox120_negotiates_declared_classic_groups_and_ciphers() {
    classic_profile_suites(ClientFingerprint::Firefox120).await;
}

#[tokio::test]
async fn safari16_negotiates_declared_classic_groups_and_real_legacy_ciphers() {
    classic_profile_suites(ClientFingerprint::Safari16).await;
}

#[tokio::test]
async fn firefox_and_safari_keep_the_callers_tls12_floor() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for profile in [ClientFingerprint::Firefox120, ClientFingerprint::Safari16] {
            for version in [SslVersion::TLS1, SslVersion::TLS1_1] {
                let (io, remote) = tokio::io::duplex(4096);
                let task = tokio::spawn(async move {
                    tokio_boring::accept(&server(version, "X25519").build(), remote)
                        .await
                        .is_err()
                });
                let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
                b.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
                b.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
                let connector = FingerprintConnector::new(b, profile).unwrap();
                let mut config = connector.configure(b"\x02h2").unwrap();
                config.set_verify_hostname(false);
                let result = tokio_boring::connect(config, "profile.test", io).await;
                assert!(result.is_err());
                drop(result);
                assert!(task.await.unwrap());
            }
        }
    })
    .await
    .unwrap();
}

struct BrotliCertificate(u8);
impl boring::ssl::CertificateCompressor for BrotliCertificate {
    const ALGORITHM: boring::ssl::CertificateCompressionAlgorithm =
        boring::ssl::CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = false;
    fn compress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        use std::io::{Read, Write};
        let inflated;
        let input = if self.0 == 4 {
            inflated = vec![0; 128 * 1024 + 1];
            inflated.as_slice()
        } else {
            input
        };
        let mut encoded = vec![];
        brotli::CompressorReader::new(input, 4096, 5, 22).read_to_end(&mut encoded)?;
        match self.0 {
            1 => {
                encoded.truncate(encoded.len() / 2);
            }
            2 => {
                encoded[..3].fill(0xff);
            }
            3 => {
                let mut encoder =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(input)?;
                encoded = encoder.finish()?;
            }
            _ => {}
        }
        output.write_all(&encoded)
    }
}

#[tokio::test]
async fn chrome_profiles_retain_bounded_brotli_and_reject_wrong_payload_algorithm() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for profile in [ClientFingerprint::Chrome120, ClientFingerprint::Chrome133] {
            for mode in 0..5 {
                let mut acceptor = server(SslVersion::TLS1_3, "X25519");
                acceptor
                    .add_certificate_compression_algorithm(BrotliCertificate(mode))
                    .unwrap();
                let (io, remote) = tokio::io::duplex(4096);
                let task = tokio::spawn(async move {
                    match tokio_boring::accept(&acceptor.build(), remote).await {
                        Ok(mut tls) => tls.write_all(b"brotli").await.is_ok(),
                        Err(_) => false,
                    }
                });
                let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
                b.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
                let connector = FingerprintConnector::new(b, profile).unwrap();
                let mut config = connector.configure(b"\x02h2").unwrap();
                config.set_verify_hostname(false);
                let result = tokio_boring::connect(config, "profile.test", io).await;
                assert_eq!(result.is_ok(), mode == 0);
                match result {
                    Ok(mut tls) => {
                        let mut data = [0; 6];
                        tls.read_exact(&mut data).await.unwrap();
                        assert_eq!(&data, b"brotli");
                    }
                    Err(error) => {
                        assert!(
                            error.to_string().contains("CERT_DECOMPRESSION_FAILED"),
                            "{error}"
                        );
                        drop(error);
                    }
                }
                assert_eq!(task.await.unwrap(), mode == 0);
            }
        }
    })
    .await
    .unwrap();
}

struct ZlibCertificate(u8);
impl boring::ssl::CertificateCompressor for ZlibCertificate {
    const ALGORITHM: boring::ssl::CertificateCompressionAlgorithm =
        boring::ssl::CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = false;
    fn compress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        use std::io::Write;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        if self.0 == 4 {
            encoder.write_all(&vec![0; 128 * 1024 + 1])?;
        } else {
            encoder.write_all(input)?;
        }
        let mut encoded = encoder.finish()?;
        match self.0 {
            1 => {
                encoded.pop();
            }
            2 => {
                encoded[0] ^= 0xff;
            }
            3 => encoded.extend_from_slice(b"trailing"),
            5 => {
                encoded.clear();
                std::io::Read::read_to_end(
                    &mut brotli::CompressorReader::new(input, 4096, 5, 22),
                    &mut encoded,
                )?;
            }
            _ => {}
        }
        output.write_all(&encoded)
    }
}

#[tokio::test]
async fn safari16_real_zlib_rejects_truncation_corruption_trailing_and_oversize() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for mode in 0..8 {
            let mut acceptor = server(SslVersion::TLS1_3, "X25519");
            if mode == 6 {
                for _ in 0..160 {
                    acceptor
                        .add_extra_chain_cert(X509::from_pem(include_bytes!("cert.pem")).unwrap())
                        .unwrap();
                }
            }
            acceptor
                .add_certificate_compression_algorithm(ZlibCertificate(mode))
                .unwrap();
            let (io, remote) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move {
                match tokio_boring::accept(&acceptor.build(), remote).await {
                    Ok(mut tls) => tls.write_all(b"zlib").await.is_ok(),
                    Err(_) => false,
                }
            });
            let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
            b.set_custom_verify_callback(SslVerifyMode::PEER, move |_| {
                if mode == 7 {
                    Err(boring::ssl::SslVerifyError::Invalid(
                        boring::ssl::SslAlert::BAD_CERTIFICATE,
                    ))
                } else {
                    Ok(())
                }
            });
            let connector = FingerprintConnector::new(b, ClientFingerprint::Safari16).unwrap();
            let mut config = connector.configure(b"\x02h2").unwrap();
            config.set_verify_hostname(false);
            let result = tokio_boring::connect(config, "profile.test", io).await;
            assert_eq!(result.is_ok(), mode == 0);
            match result {
                Ok(mut tls) => {
                    let mut out = [0; 4];
                    tls.read_exact(&mut out).await.unwrap();
                    assert_eq!(&out, b"zlib");
                }
                Err(error) => {
                    let expected = if mode == 6 {
                        "UNCOMPRESSED_CERT_TOO_LARGE"
                    } else if mode == 7 {
                        "CERTIFICATE_VERIFY_FAILED"
                    } else {
                        "CERT_DECOMPRESSION_FAILED"
                    };
                    assert!(error.to_string().contains(expected), "{error}");
                    drop(error);
                }
            }
            assert_eq!(task.await.unwrap(), mode == 0);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn chrome133_negotiates_mlkem_x25519_hrr_and_tls12_with_data() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for (version, group, expected_id, hrr) in [
            (SslVersion::TLS1_3, "X25519MLKEM768", 4588, false),
            (SslVersion::TLS1_3, "X25519", 29, false),
            (SslVersion::TLS1_3, "P-256", 23, true),
            (SslVersion::TLS1_2, "X25519", 29, false),
        ] {
            let server = server(version, group).build();
            let (io, remote) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move {
                let mut tls = tokio_boring::accept(&server, remote).await.unwrap();
                assert_eq!(
                    unsafe { boring_sys::SSL_get_group_id(tls.ssl().as_ptr()) },
                    expected_id
                );
                let mut request = [0; 16];
                tls.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"selected-request");
                tls.write_all(b"selected-response").await.unwrap();
            });
            let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
            b.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
            b.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
            let connector = FingerprintConnector::new(b, ClientFingerprint::Chrome133).unwrap();
            let mut config = connector.configure(b"\x02h2").unwrap();
            config.set_verify_hostname(false);
            let mut tls = tokio_boring::connect(config, "profile.test", io)
                .await
                .unwrap();
            assert_eq!(tls.ssl().version2(), Some(version));
            assert_eq!(tls.ssl().used_hello_retry_request(), hrr);
            assert_eq!(
                unsafe { boring_sys::SSL_get_group_id(tls.ssl().as_ptr()) },
                expected_id
            );
            tls.write_all(b"selected-request").await.unwrap();
            let mut response = [0; 17];
            tls.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"selected-response");
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn chrome133_negotiates_only_new_alps_with_absent_empty_and_nonempty_results() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for (new_codepoint, settings) in [
            (false, Some(&b"old"[..])),
            (true, None),
            (true, Some(&b""[..])),
            (true, Some(&b"new-settings"[..])),
        ] {
            let (io, remote) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move {
                let acceptor = server(SslVersion::TLS1_3, "X25519").build();
                let ssl = Ssl::new(acceptor.context()).unwrap();
                if let Some(settings) = settings {
                    unsafe {
                        boring_sys::SSL_set_alps_use_new_codepoint(
                            ssl.as_ptr(),
                            new_codepoint.into(),
                        );
                        assert_eq!(
                            boring_sys::SSL_add_application_settings(
                                ssl.as_ptr(),
                                b"h2".as_ptr(),
                                2,
                                settings.as_ptr(),
                                settings.len()
                            ),
                            1
                        );
                    }
                }
                let mut tls = tokio_boring::SslStreamBuilder::new(ssl, remote)
                    .accept()
                    .await
                    .unwrap();
                tls.write_all(b"alps").await.unwrap();
            });
            let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
            b.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
            let connector = FingerprintConnector::new(b, ClientFingerprint::Chrome133).unwrap();
            let mut config = connector.configure(b"\x02h2").unwrap();
            config.set_verify_hostname(false);
            let mut tls = tokio_boring::connect(config, "profile.test", io)
                .await
                .unwrap();
            assert_eq!(
                tls.ssl().peer_application_settings(),
                if new_codepoint { settings } else { None }
            );
            let mut response = [0; 4];
            tls.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"alps");
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn chrome133_real_ticket_resumption_and_rejected_ticket_full_handshake() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let tickets: Arc<Mutex<Vec<SslSession>>> = Arc::default();
        let saved = tickets.clone();
        let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
        b.set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
        b.set_new_session_callback(move |_, s| saved.lock().unwrap().push(s));
        b.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
        let connector = FingerprintConnector::new(b, ClientFingerprint::Chrome133).unwrap();
        let mut acceptor = server(SslVersion::TLS1_3, "X25519MLKEM768").build();
        for (round, expected_reuse) in [(0, false), (1, true), (2, false)] {
            // A distinct real ticket key rejects the offered previous ticket,
            // then performs a fresh authenticated handshake rather than failing.
            if round == 2 {
                acceptor = server(SslVersion::TLS1_3, "X25519MLKEM768").build();
            }
            let peer = acceptor.clone();
            let (io, remote) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move {
                let mut tls = tokio_boring::accept(&peer, remote).await.unwrap();
                assert_eq!(tls.ssl().session_reused(), expected_reuse);
                tls.write_all(b"ticket-ready").await.unwrap();
                let mut ack = [0; 3];
                tls.read_exact(&mut ack).await.unwrap();
                assert_eq!(&ack, b"ack");
            });
            let mut config = connector.configure(b"\x02h2").unwrap();
            config.set_verify_hostname(false);
            if round != 0 {
                let ticket = tickets.lock().unwrap().pop().expect("real server ticket");
                // All three connections have the same identity and trust policy.
                unsafe {
                    config.set_session(&ticket).unwrap();
                }
            }
            let mut tls = tokio_boring::connect(config, "profile.test", io)
                .await
                .unwrap();
            assert_eq!(tls.ssl().session_reused(), expected_reuse);
            let mut response = [0; 12];
            tls.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"ticket-ready");
            tls.write_all(b"ack").await.unwrap();
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn chrome133_rejects_bad_certificate_and_forged_handshake_signature() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for bad_signature in [false, true] {
            let mut acceptor = server(SslVersion::TLS1_3, "X25519MLKEM768");
            if bad_signature {
                acceptor.set_private_key_method(ForgedSignature);
            }
            let (io, remote) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move {
                tokio_boring::accept(&acceptor.build(), remote)
                    .await
                    .is_err()
            });
            let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
            b.set_custom_verify_callback(SslVerifyMode::PEER, move |_| {
                if bad_signature {
                    Ok(())
                } else {
                    Err(boring::ssl::SslVerifyError::Invalid(
                        boring::ssl::SslAlert::BAD_CERTIFICATE,
                    ))
                }
            });
            let connector = FingerprintConnector::new(b, ClientFingerprint::Chrome133).unwrap();
            let mut config = connector.configure(b"\x02h2").unwrap();
            config.set_verify_hostname(false);
            let error = tokio_boring::connect(config, "profile.test", io)
                .await
                .unwrap_err();
            let text = error.to_string();
            if bad_signature {
                assert!(text.contains("BAD_SIGNATURE"), "{text}");
            } else {
                assert!(text.contains("CERTIFICATE_VERIFY_FAILED"), "{text}");
            }
            drop(error);
            assert!(task.await.unwrap());
        }
    })
    .await
    .unwrap();
}

enum ServerHelloFault {
    ShareLength,
    FfdheSelection,
    FakeCipher,
    Extension(u16),
}

#[cfg(feature = "reality")]
#[tokio::test]
async fn all_classic_reality_profiles_reject_hrr_and_tls12() {
    use boring::ssl::RealityClientConfig;
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for profile in [
            ClientFingerprint::Chrome120,
            ClientFingerprint::Chrome133,
            ClientFingerprint::Firefox120,
            ClientFingerprint::Safari16,
        ] {
            for (version, group, expected) in [
                (SslVersion::TLS1_2, "X25519", "UNSUPPORTED_PROTOCOL"),
                (SslVersion::TLS1_3, "P-384", "UNEXPECTED_MESSAGE"),
            ] {
                let (io, remote) = tokio::io::duplex(4096);
                let peer = tokio::spawn(async move {
                    tokio_boring::accept(&server(version, group).build(), remote)
                        .await
                        .is_err()
                });
                let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
                builder
                    .set_min_proto_version(Some(SslVersion::TLS1_2))
                    .unwrap();
                builder.set_custom_verify_callback(SslVerifyMode::NONE, |_| Ok(()));
                let connector = FingerprintConnector::new(builder, profile).unwrap();
                let mut config = connector.configure(b"\x02h2").unwrap();
                config
                    .set_reality_client(&RealityClientConfig::new([9; 32], &[], [1, 8, 0]).unwrap())
                    .unwrap();
                config.set_verify_hostname(false);
                let error = tokio_boring::connect(config, "profile.test", io)
                    .await
                    .unwrap_err();
                assert!(error.to_string().contains(expected), "{profile:?}: {error}");
                drop(error);
                assert!(peer.await.unwrap());
            }
        }
    })
    .await
    .unwrap();
}

async fn reject_server_hello(
    profile: ClientFingerprint,
    version: SslVersion,
    fault: ServerHelloFault,
    expected_error: &str,
) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (client_io, relay_client) = tokio::io::duplex(4096);
        let (server_io, relay_server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            tokio_boring::accept(&server(version, "X25519").build(), server_io)
                .await
                .is_err()
        });
        // Fault injection is on bounded fixture IO, never production BIO code.
        let relay = tokio::spawn(async move {
            let (mut cr, mut cw) = tokio::io::split(relay_client);
            let (mut sr, mut sw) = tokio::io::split(relay_server);
            let forward = async {
                let result = tokio::io::copy(&mut cr, &mut sw).await;
                let _ = sw.shutdown().await;
                result
            };
            let corrupt = async {
                let mut header = [0; 5];
                sr.read_exact(&mut header).await.unwrap();
                assert_eq!(header[0], 22);
                let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
                assert!(len <= 4096);
                let mut hello = vec![0; len];
                sr.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello[0], 2); // Real ServerHello from the native peer.
                let end = 4
                    + ((usize::from(hello[1]) << 16)
                        | (usize::from(hello[2]) << 8)
                        | usize::from(hello[3]));
                assert!(end <= hello.len());
                let cipher_at = 39 + usize::from(hello[38]);
                let extensions_at = cipher_at + 3;
                match fault {
                    ServerHelloFault::FakeCipher => {
                        hello[cipher_at..cipher_at + 2].copy_from_slice(&0xc008u16.to_be_bytes());
                    }
                    ServerHelloFault::Extension(kind) => {
                        let old_size =
                            u16::from_be_bytes([hello[extensions_at], hello[extensions_at + 1]]);
                        let [a, b] = kind.to_be_bytes();
                        hello.splice(end..end, [a, b, 0, 2, 0x40, 1]);
                        hello[extensions_at..extensions_at + 2]
                            .copy_from_slice(&(old_size + 6).to_be_bytes());
                        let handshake_size = u32::try_from(end - 4 + 6).unwrap().to_be_bytes();
                        hello[1..4].copy_from_slice(&handshake_size[1..]);
                        header[3..5]
                            .copy_from_slice(&u16::try_from(hello.len()).unwrap().to_be_bytes());
                    }
                    ServerHelloFault::ShareLength | ServerHelloFault::FfdheSelection => {
                        let mut at = extensions_at + 2;
                        let mut changed = false;
                        while at < end {
                            let kind = u16::from_be_bytes([hello[at], hello[at + 1]]);
                            let size =
                                usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
                            if kind == 51 {
                                assert_eq!(&hello[at + 4..at + 8], &[0, 29, 0, 32]);
                                if matches!(fault, ServerHelloFault::ShareLength) {
                                    hello[at + 7] = 31;
                                } else {
                                    hello[at + 4..at + 6].copy_from_slice(&256u16.to_be_bytes());
                                }
                                changed = true;
                            }
                            at += 4 + size;
                        }
                        assert_eq!(at, end);
                        assert!(changed);
                    }
                }
                cw.write_all(&header).await.unwrap();
                cw.write_all(&hello).await.unwrap();
                tokio::io::copy(&mut sr, &mut cw).await
            };
            let _ = tokio::join!(forward, corrupt);
        });
        let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
        b.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
        let connector = FingerprintConnector::new(b, profile).unwrap();
        let mut config = connector.configure(b"\x02h2").unwrap();
        config.set_verify_hostname(false);
        let error = tokio_boring::connect(config, "profile.test", client_io)
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected_error), "{error}");
        drop(error);
        assert!(task.await.unwrap());
        relay.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn chrome133_rejects_malformed_server_key_share() {
    reject_server_hello(
        ClientFingerprint::Chrome133,
        SslVersion::TLS1_3,
        ServerHelloFault::ShareLength,
        "DECODE_ERROR",
    )
    .await;
}

#[tokio::test]
async fn firefox120_rejects_template_only_selections() {
    for kind in [28, 34] {
        reject_server_hello(
            ClientFingerprint::Firefox120,
            SslVersion::TLS1_2,
            ServerHelloFault::Extension(kind),
            "UNEXPECTED_EXTENSION",
        )
        .await;
    }
    reject_server_hello(
        ClientFingerprint::Firefox120,
        SslVersion::TLS1_3,
        ServerHelloFault::FfdheSelection,
        "WRONG_CURVE",
    )
    .await;
}

#[tokio::test]
async fn safari16_rejects_utls_fake_cipher_selection() {
    reject_server_hello(
        ClientFingerprint::Safari16,
        SslVersion::TLS1_2,
        ServerHelloFault::FakeCipher,
        "WRONG_CIPHER_RETURNED",
    )
    .await;
}
