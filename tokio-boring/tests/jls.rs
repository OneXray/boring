#![cfg(feature = "jls")]

// Memory TLS peers only. Real JLS acceptance requires an independent container.
use boring::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509Name, X509},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn ordinary_peer(version: SslVersion, group: &str, jls: bool, permissive: bool) {
    let key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "jls.invalid").unwrap();
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
    let server = server.build();
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    // TLS 1.2 also checks the certificate's P-256 curve against this list.
    builder.set_curves_list("X25519:P-256:P-384").unwrap();
    if permissive {
        builder.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
    } else {
        builder.cert_store_mut().add_cert(cert).unwrap();
    }
    let mut config = builder.build().configure().unwrap();
    if jls {
        config
            .set_jls_client(b"synthetic-user", b"synthetic-password")
            .unwrap();
        if !permissive {
            config.set_verify(SslVerifyMode::NONE);
        }
    }
    let (io, peer) = tokio::io::duplex(512);
    let server = tokio::spawn(async move {
        let mut tls = tokio_boring::accept(&server, peer).await.map_err(|_| ())?;
        tls.write_all(b"hello").await.map_err(|_| ())?;
        tls.flush().await.map_err(|_| ())?;
        Ok::<_, ()>(())
    });
    let client = tokio_boring::connect(config, "jls.invalid", io).await;
    if jls {
        assert!(
            client.is_err(),
            "ordinary TLS must never satisfy JLS authentication"
        );
        drop(client);
        assert!(
            server.await.unwrap().is_err(),
            "no completed server handshake"
        );
    } else {
        let mut tls = client.unwrap();
        assert_eq!(tls.ssl().used_hello_retry_request(), group == "P-384");
        let mut hello = [0; 5];
        tls.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        server.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn jls_authentication_is_mandatory_even_when_pki_is_permissive() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for (version, group) in [
            (SslVersion::TLS1_2, "X25519"),
            (SslVersion::TLS1_3, "X25519"),
            (SslVersion::TLS1_3, "P-384"),
        ] {
            ordinary_peer(version, group, false, false).await;
            for permissive in [false, true] {
                ordinary_peer(version, group, true, permissive).await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_handshakes_release_io_and_use_fresh_randoms() {
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    let mut previous = None;
    for _ in 0..20 {
        let mut config = connector.configure().unwrap();
        config
            .set_jls_client(b"synthetic-user", b"synthetic-password")
            .unwrap();
        let (io, mut peer) = tokio::io::duplex(65_536);
        let handshake = tokio::spawn(tokio_boring::connect(config, "jls.invalid", io));
        let mut header = [0; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer.read_exact(&mut header),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(header[0], 22);
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        assert!((38..=16384).contains(&length));
        let mut hello = vec![0; length];
        peer.read_exact(&mut hello).await.unwrap();
        let random: [u8; 32] = hello[6..38].try_into().unwrap();
        assert_ne!(previous, Some(random));
        previous = Some(random);
        handshake.abort();
        assert!(handshake.await.unwrap_err().is_cancelled());
        assert_eq!(peer.read(&mut header).await.unwrap(), 0);
    }
}
