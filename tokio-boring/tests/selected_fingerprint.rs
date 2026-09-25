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

#[tokio::test]
async fn chrome133_rejects_malformed_server_key_share() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (client_io, relay_client) = tokio::io::duplex(4096);
        let (server_io, relay_server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            tokio_boring::accept(&server(SslVersion::TLS1_3, "X25519").build(), server_io)
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
                let mut at = 39 + usize::from(hello[38]) + 3 + 2;
                let mut changed = false;
                while at < hello.len() {
                    let kind = u16::from_be_bytes([hello[at], hello[at + 1]]);
                    let size = usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
                    if kind == 51 {
                        assert_eq!(&hello[at + 4..at + 8], &[0, 29, 0, 32]);
                        hello[at + 7] = 31; // Internal length no longer matches share.
                        changed = true;
                    }
                    at += 4 + size;
                }
                assert_eq!(at, hello.len());
                assert!(changed);
                cw.write_all(&header).await.unwrap();
                cw.write_all(&hello).await.unwrap();
                tokio::io::copy(&mut sr, &mut cw).await
            };
            let _ = tokio::join!(forward, corrupt);
        });
        let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
        b.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
        let connector = FingerprintConnector::new(b, ClientFingerprint::Chrome133).unwrap();
        let mut config = connector.configure(b"\x02h2").unwrap();
        config.set_verify_hostname(false);
        let error = tokio_boring::connect(config, "profile.test", client_io)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("DECODE_ERROR"), "{error}");
        drop(error);
        assert!(task.await.unwrap());
        relay.await.unwrap();
    })
    .await
    .unwrap();
}
