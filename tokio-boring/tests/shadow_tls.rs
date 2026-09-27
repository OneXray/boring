#![cfg(all(feature = "shadow-tls-v3", feature = "client-fingerprint"))]

// Complete native handshakes over bounded memory IO, never a host listener.
use boring::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    ssl::{
        ClientFingerprint, FingerprintConnector, SslAcceptor, SslConnector, SslMethod,
        SslVerifyMode, SslVersion,
    },
    x509::{X509Name, X509},
};
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
        output[..64].fill(0);
        Ok(64)
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

async fn exchange(
    version: SslVersion,
    profile: Option<ClientFingerprint>,
    group: &str,
    failure: Option<&str>,
    hook: bool,
) {
    let group_key = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group_key).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "cover.invalid").unwrap();
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
    let cert = cert.build();
    let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    server.set_certificate(&cert).unwrap();
    server.set_private_key(&key).unwrap();
    server.set_min_proto_version(Some(version)).unwrap();
    server.set_max_proto_version(Some(version)).unwrap();
    server.set_curves_list(group).unwrap();
    if failure == Some("signature") {
        server.set_private_key_method(ForgedSignature);
    }
    let server = server.build();
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    builder.set_verify(SslVerifyMode::PEER);
    if failure != Some("trust") {
        builder.cert_store_mut().add_cert(cert).unwrap();
    }
    let mut config = if let Some(profile) = profile {
        FingerprintConnector::new(builder, profile)
            .unwrap()
            .configure(&[])
            .unwrap()
    } else {
        builder.build().configure().unwrap()
    };
    if hook {
        config
            .set_shadow_tls_v3_client(b"synthetic-memory-password")
            .unwrap();
    }
    let (io, peer) = tokio::io::duplex(512);
    let server = tokio::spawn(async move {
        let mut tls = tokio_boring::accept(&server, peer).await.map_err(|_| ())?;
        tls.write_all(b"hello").await.map_err(|_| ())?;
        let mut request = [0; 4];
        tls.read_exact(&mut request).await.map_err(|_| ())?;
        assert_eq!(&request, b"ping");
        Ok::<_, ()>(())
    });
    let result = tokio_boring::connect(
        config,
        if failure == Some("name") {
            "wrong.invalid"
        } else {
            "cover.invalid"
        },
        io,
    )
    .await;
    if failure.is_some() {
        assert!(result.is_err(), "native TLS authentication was bypassed");
        drop(result);
        assert!(server.await.unwrap().is_err());
    } else {
        let mut tls = result.unwrap();
        assert_eq!(tls.ssl().version2(), Some(version));
        assert_eq!(tls.ssl().used_hello_retry_request(), group == "P-384");
        let mut greeting = [0; 5];
        tls.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"hello");
        tls.write_all(b"ping").await.unwrap();
        tls.flush().await.unwrap();
        server.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn native_tls_transcript_and_all_profiles_complete_without_wire_rewriting() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
            for profile in [
                None,
                Some(ClientFingerprint::Chrome120),
                Some(ClientFingerprint::Chrome133),
                Some(ClientFingerprint::Firefox120),
                Some(ClientFingerprint::Safari16),
            ] {
                exchange(version, profile, "X25519", None, true).await;
            }
            exchange(version, None, "X25519", None, false).await;
        }
        // Server P-384 forces a real TLS 1.3 HRR for Chrome's first shares.
        exchange(
            SslVersion::TLS1_3,
            Some(ClientFingerprint::Chrome133),
            "P-384",
            None,
            true,
        )
        .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn hook_does_not_bypass_certificate_name_or_handshake_signature_checks() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
            for failure in ["trust", "name", "signature"] {
                exchange(version, None, "X25519", Some(failure), true).await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_handshakes_drop_io_and_do_not_reuse_authentication_state() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let password = b"synthetic-cancellation-password";
        let mut seen = std::collections::HashSet::new();
        for round in 0..20 {
            let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .unwrap();
            let mut config = if round % 2 == 0 {
                builder.build().configure().unwrap()
            } else {
                FingerprintConnector::new(builder, ClientFingerprint::Chrome133)
                    .unwrap()
                    .configure(&[])
                    .unwrap()
            };
            config.set_shadow_tls_v3_client(password).unwrap();
            let (io, mut peer) = tokio::io::duplex(512);
            let task = tokio::spawn(tokio_boring::connect(config, "cover.invalid", io));
            let mut header = [0; 5];
            peer.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 22);
            let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
            assert!(size <= 16384);
            let mut message = vec![0; size];
            peer.read_exact(&mut message).await.unwrap();
            assert_eq!(message[0], 1);
            assert_eq!(message[38], 32);
            let sid: [u8; 32] = message[39..71].try_into().unwrap();
            message[67..71].fill(0);
            assert_eq!(
                &sid[28..],
                &boring::hash::hmac_sha1(password, &message).unwrap()[..4]
            );
            assert!(seen.insert(sid));
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            // No owner or hidden relay retains the caller's IO after cancellation.
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).await.unwrap();
            assert!(
                rest.len() <= 6,
                "only a compatibility CCS may follow the hello"
            );
        }
    })
    .await
    .unwrap();
}
