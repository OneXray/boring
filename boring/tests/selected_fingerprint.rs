#![cfg(feature = "client-fingerprint")]
//! Closed-template wire observations through the production connector. No sockets.
use boring::ssl::{ClientFingerprint, FingerprintConnector, SslConnector, SslMethod, SslVersion};
use std::io::{self, Read, Write};

#[derive(Debug, Default)]
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
fn take<'a>(input: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (out, rest) = input.split_at(n);
    *input = rest;
    out
}
fn vector<'a>(input: &mut &'a [u8], width: usize) -> &'a [u8] {
    let n = take(input, width)
        .iter()
        .fold(0usize, |n, b| n * 256 + usize::from(*b));
    take(input, n)
}
fn codes(input: &[u8]) -> Vec<u16> {
    assert_eq!(input.len() % 2, 0);
    input
        .chunks_exact(2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .collect()
}
fn grease(id: u16) -> bool {
    id & 0x0f0f == 0x0a0a && id >> 8 == id & 0xff
}

fn configuration(
    connector: &FingerprintConnector,
    reality: bool,
) -> boring::ssl::ConnectConfiguration {
    let config = connector.configure(b"\x02h2\x08http/1.1").unwrap();
    #[cfg(feature = "reality")]
    let config = {
        let mut config = config;
        if reality {
            use boring::{
                pkey::{Id, PKey},
                ssl::RealityClientConfig,
            };
            let peer = PKey::generate(Id::X25519).unwrap();
            let mut public = [0; 32];
            peer.raw_public_key(&mut public).unwrap();
            config
                .set_reality_client(&RealityClientConfig::new(public, &[], [1, 8, 0]).unwrap())
                .unwrap();
        }
        config
    };
    #[cfg(not(feature = "reality"))]
    assert!(!reality);
    config
}

fn check_firefox(reality: bool) {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    let connector = FingerprintConnector::new(builder, ClientFingerprint::Firefox120).unwrap();
    for _ in 0..8 {
        let error = configuration(&connector, reality)
            .connect("fingerprint.test", Capture::default())
            .unwrap_err();
        let boring::ssl::HandshakeError::WouldBlock(stream) = error else {
            panic!("expected hello");
        };
        let mut record = stream.get_ref().0.as_slice();
        assert_eq!(take(&mut record, 3), &[22, 3, 1]);
        let mut hello = vector(&mut record, 2);
        assert!(record.is_empty());
        assert_eq!(take(&mut hello, 1), &[1]);
        let mut body = vector(&mut hello, 3);
        assert!(hello.is_empty());
        assert_eq!(take(&mut body, 2), &[3, 3]);
        take(&mut body, 32);
        assert_eq!(vector(&mut body, 1).len(), 32);
        assert_eq!(
            codes(vector(&mut body, 2)),
            [
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a,
                0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
            ]
        );
        assert_eq!(vector(&mut body, 1), &[0]);
        let mut ext = vector(&mut body, 2);
        assert!(body.is_empty());
        let mut rows = vec![];
        while !ext.is_empty() {
            let kind = codes(take(&mut ext, 2))[0];
            rows.push((kind, vector(&mut ext, 2)));
        }
        // Exact, not sorted: official Firefox120 vector includes template-only
        // FFDHE, delegated_credentials and record_size_limit declarations.
        assert_eq!(
            rows.iter().map(|r| r.0).collect::<Vec<_>>(),
            [0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 65037]
        );
        let value = |id| rows.iter().find(|r| r.0 == id).unwrap().1;
        assert_eq!(&value(0)[5..], b"fingerprint.test");
        assert_eq!(value(16), b"\0\x0c\x02h2\x08http/1.1");
        assert_eq!(codes(&value(10)[2..]), [29, 23, 24, 25, 256, 257]);
        assert_eq!(codes(&value(34)[2..]), [0x0403, 0x0503, 0x0603, 0x0203]);
        assert_eq!(
            codes(&value(13)[2..]),
            [
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201
            ]
        );
        assert_eq!(value(43), &[4, 3, 4, 3, 3]);
        for (id, expected) in [
            (23, &[][..]),
            (65281, &[0]),
            (11, &[1, 0]),
            (35, &[]),
            (5, &[1, 0, 0, 0, 0]),
            (45, &[1, 1]),
            (28, &[0x40, 1]),
        ] {
            assert_eq!(value(id), expected);
        }
        let mut shares = &value(51)[2..];
        for (id, size) in [(29, 32), (23, 65)] {
            assert_eq!(codes(take(&mut shares, 2)), [id]);
            let key = vector(&mut shares, 2);
            assert_eq!(key.len(), size);
            if id == 23 {
                assert_eq!(key[0], 4);
            }
        }
        assert!(shares.is_empty());
        let ech = value(65037);
        assert_eq!(ech.len(), 281);
        assert_eq!(&ech[..3], &[0, 0, 1]);
        assert!([1, 3].contains(&codes(&ech[3..5])[0]));
        assert_eq!(&ech[6..8], &[0, 32]);
        assert_eq!(&ech[40..42], &[0, 239]);
    }
}

fn check_safari(reality: bool) {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    let connector = FingerprintConnector::new(builder, ClientFingerprint::Safari16).unwrap();
    for _ in 0..8 {
        let error = configuration(&connector, reality)
            .connect("fingerprint.test", Capture::default())
            .unwrap_err();
        let boring::ssl::HandshakeError::WouldBlock(stream) = error else {
            panic!("expected hello");
        };
        let mut record = stream.get_ref().0.as_slice();
        assert_eq!(take(&mut record, 3), &[22, 3, 1]);
        let mut hello = vector(&mut record, 2);
        assert!(record.is_empty());
        assert_eq!(take(&mut hello, 1), &[1]);
        let mut body = vector(&mut hello, 3);
        assert!(hello.is_empty());
        assert_eq!(take(&mut body, 2), &[3, 3]);
        take(&mut body, 32);
        assert_eq!(vector(&mut body, 1).len(), 32);
        let ciphers = codes(vector(&mut body, 2));
        assert!(grease(ciphers[0]));
        assert_eq!(
            &ciphers[1..],
            &[
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a,
                0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a
            ]
        );
        assert_eq!(vector(&mut body, 1), &[0]);
        let mut ext = vector(&mut body, 2);
        assert!(body.is_empty());
        let mut rows = vec![];
        while !ext.is_empty() {
            let kind = codes(take(&mut ext, 2))[0];
            rows.push((kind, vector(&mut ext, 2)));
        }
        assert!(grease(rows[0].0));
        assert!(rows[0].1.is_empty());
        let last = rows.len() - 1 - usize::from(rows.last().unwrap().0 == 21);
        assert!(grease(rows[last].0));
        assert_eq!(rows[last].1, &[0]);
        assert_eq!(
            rows[1..last].iter().map(|r| r.0).collect::<Vec<_>>(),
            [0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27]
        );
        let value = |id| rows.iter().find(|r| r.0 == id).unwrap().1;
        assert_eq!(&value(0)[5..], b"fingerprint.test");
        assert_eq!(value(16), b"\0\x0c\x02h2\x08http/1.1");
        assert_eq!(value(27), &[2, 0, 1]); // Zlib, not Brotli.
        assert_eq!(
            codes(&value(13)[2..]),
            [
                0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601,
                0x0201
            ]
        );
        assert_eq!(&value(43)[3..], &[3, 4, 3, 3]); // Approved TLS1.2 floor.
        let groups = codes(&value(10)[2..]);
        assert!(grease(groups[0]));
        assert_eq!(&groups[1..], &[29, 23, 24, 25]);
        let mut shares = &value(51)[2..];
        for (id, size) in [(groups[0], 1), (29, 32)] {
            assert_eq!(codes(take(&mut shares, 2)), [id]);
            assert_eq!(vector(&mut shares, 2).len(), size);
        }
        assert!(shares.is_empty());
        for (id, expected) in [
            (23, &[][..]),
            (65281, &[0]),
            (11, &[1, 0]),
            (5, &[1, 0, 0, 0, 0]),
            (18, &[]),
            (45, &[1, 1]),
        ] {
            assert_eq!(value(id), expected);
        }
        let padding = value(21);
        let unpadded = stream.get_ref().0.len() - 5 - padding.len() - 4;
        assert!((256..512).contains(&unpadded));
        assert_eq!(padding.len(), 512 - unpadded - 4);
        assert!(padding.iter().all(|b| *b == 0));
    }
}

fn check_chrome133(reality: bool) {
    // Independent expected fields: CF0 official Mihomo v1.19.31 / uTLS v1.8.7
    // Chrome133, not data loaded from the implementation's profile table.
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    let connector = FingerprintConnector::new(builder, ClientFingerprint::Chrome133).unwrap();
    for sni in [
        "fingerprint.test".to_owned(),
        format!("{}.fingerprint.test", "f".repeat(63)),
    ] {
        for _ in 0..8 {
            let error = configuration(&connector, reality)
                .connect(&sni, Capture::default())
                .unwrap_err();
            let boring::ssl::HandshakeError::WouldBlock(stream) = error else {
                panic!("expected captured ClientHello");
            };
            let mut record = stream.get_ref().0.as_slice();
            assert_eq!(take(&mut record, 3), &[22, 3, 1]);
            let mut hello = vector(&mut record, 2);
            assert!(record.is_empty());
            assert_eq!(take(&mut hello, 1), &[1]);
            let mut body = vector(&mut hello, 3);
            assert!(hello.is_empty());
            assert_eq!(take(&mut body, 2), &[3, 3]);
            take(&mut body, 32);
            assert_eq!(vector(&mut body, 1).len(), 32);
            let ciphers = codes(vector(&mut body, 2));
            assert!(grease(ciphers[0]));
            assert_eq!(
                &ciphers[1..],
                &[
                    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                    0xc014, 0x009c, 0x009d, 0x002f, 0x0035
                ]
            );
            assert_eq!(vector(&mut body, 1), &[0]);
            let mut ext = vector(&mut body, 2);
            assert!(body.is_empty());
            let mut rows = vec![];
            while !ext.is_empty() {
                let kind = codes(take(&mut ext, 2))[0];
                rows.push((kind, vector(&mut ext, 2)));
            }
            assert!(grease(rows[0].0));
            assert!(rows[0].1.is_empty());
            assert!(grease(rows.last().unwrap().0));
            assert_eq!(rows.last().unwrap().1, &[0]);
            let mut kinds: Vec<_> = rows[1..rows.len() - 1].iter().map(|r| r.0).collect();
            kinds.sort_unstable();
            assert_eq!(
                kinds,
                [0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 65037, 65281]
            );
            let value = |id| rows.iter().find(|r| r.0 == id).unwrap().1;
            assert_eq!(value(17613), b"\0\x03\x02h2");
            assert_eq!(value(16), b"\0\x0c\x02h2\x08http/1.1");
            assert_eq!(&value(0)[5..], sni.as_bytes());
            assert_eq!(value(27), &[2, 0, 2]);
            assert_eq!(
                value(13),
                &[0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1]
            );
            for (id, expected) in [
                (5, &[1, 0, 0, 0, 0][..]),
                (11, &[1, 0]),
                (18, &[]),
                (23, &[]),
                (35, &[]),
                (45, &[1, 1]),
                (65281, &[0]),
            ] {
                assert_eq!(value(id), expected);
            }
            let groups = codes(&value(10)[2..]);
            assert!(grease(groups[0]));
            assert_eq!(
                &groups[1..],
                if reality {
                    &[29, 23, 24][..]
                } else {
                    &[4588, 29, 23, 24][..]
                }
            );
            let mut encoded_shares = value(51);
            let mut shares = vector(&mut encoded_shares, 2);
            assert!(encoded_shares.is_empty());
            for (id, size) in [(groups[0], 1), (4588, 1216), (29, 32)] {
                if reality && id == 4588 {
                    continue;
                }
                assert_eq!(codes(take(&mut shares, 2)), [id]);
                let key = vector(&mut shares, 2);
                assert_eq!(key.len(), size);
                if grease(id) {
                    assert_eq!(key, &[0]);
                } else {
                    assert!(key.iter().any(|b| *b != 0));
                }
            }
            assert!(shares.is_empty());
            let versions = value(43);
            assert_eq!(versions[0], 6);
            assert!(grease(codes(&versions[1..3])[0]));
            assert_eq!(&versions[3..], &[3, 4, 3, 3]);
            let ech = value(65037);
            assert_eq!(&ech[..5], &[0, 0, 1, 0, 1]);
            assert_eq!(&ech[6..8], &[0, 32]);
            let size = usize::from(codes(&ech[40..42])[0]);
            assert!([144, 176, 208, 240].contains(&size));
            assert_eq!(ech.len(), 42 + size);
        }
    }
}

#[test]
fn firefox120_has_independent_fixed_order_and_two_classic_shares() {
    check_firefox(false);
}

#[test]
fn safari16_preserves_fixed_cipher_signature_and_extension_vectors() {
    check_safari(false);
}

#[test]
fn chrome133_has_real_mlkem_shares_new_alps_and_no_padding() {
    check_chrome133(false);
}

#[cfg(feature = "reality")]
#[test]
fn classic_reality_preserves_each_new_profile_except_required_mlkem_removal() {
    check_chrome133(true);
    check_firefox(true);
    check_safari(true);
}
