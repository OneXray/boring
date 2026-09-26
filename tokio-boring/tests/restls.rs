#![cfg(feature = "restls")]

use boring::{
    sha::sha256,
    ssl::{RestlsClientConfig, RestlsVersionHint, SslConnector, SslMethod, SslVersion},
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::AsyncReadExt;

struct Owner(Arc<AtomicUsize>);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn cancelled_native_handshakes_release_callback_owner_and_controlled_io() {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    let connector = builder.build();
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut previous = None;
    for (index, hint) in [RestlsVersionHint::Tls12, RestlsVersionHint::Tls13]
        .into_iter()
        .cycle()
        .take(40)
        .enumerate()
    {
        let mut config = connector.configure().unwrap();
        let owner = Owner(dropped.clone());
        let restls = RestlsClientConfig::new(hint, move |input| {
            let _keep_alive = &owner;
            sha256(input)
        });
        config.set_restls_client(&restls).unwrap();
        drop(restls);
        let (io, mut peer) = tokio::io::duplex(65_536);
        let handshake = tokio::spawn(tokio_boring::connect(config, "restls.invalid", io));
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
        assert!((71..=16_384).contains(&length));
        let mut hello = vec![0; length];
        peer.read_exact(&mut hello).await.unwrap();
        let session: [u8; 32] = hello[39..71].try_into().unwrap();
        assert_ne!(previous, Some(session));
        previous = Some(session);
        assert_eq!(dropped.load(Ordering::Relaxed), index);
        handshake.abort();
        assert!(handshake.await.unwrap_err().is_cancelled());
        assert_eq!(peer.read(&mut header).await.unwrap(), 0);
        assert_eq!(dropped.load(Ordering::Relaxed), index + 1);
    }
}
