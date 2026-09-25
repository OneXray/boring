#![cfg(feature = "client-fingerprint")]
//! Public connector tests. Only an in-memory ClientHello sink; no listeners.
use boring::ssl::{ClientFingerprint, ErrorCode, FingerprintConnector, SslConnector, SslMethod};
use std::io::{self, Read, Write};

#[derive(Debug, Default)]
struct Capture(Vec<u8>);
impl Read for Capture {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}
impl Write for Capture {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn extensions(wire: &[u8]) -> std::collections::BTreeMap<u16, Vec<u8>> {
    let read16 = |at: usize| usize::from(u16::from_be_bytes([wire[at], wire[at + 1]]));
    assert_eq!(wire[0], 22);
    assert_eq!(wire[5], 1);
    let mut cursor = 44 + usize::from(wire[43]);
    cursor += 2 + read16(cursor);
    cursor += 1 + usize::from(wire[cursor]);
    let end = cursor + 2 + read16(cursor);
    cursor += 2;
    let mut result = std::collections::BTreeMap::new();
    while cursor < end {
        let kind = read16(cursor) as u16;
        let length = read16(cursor + 2);
        cursor += 4;
        assert!(result
            .insert(kind, wire[cursor..cursor + length].to_vec())
            .is_none());
        cursor += length;
    }
    assert_eq!(cursor, end);
    result
}

#[test]
fn chrome120_connector_applies_profile_and_respects_transport_alpn() {
    let builder = SslConnector::builder(SslMethod::tls()).unwrap();
    let connector = FingerprintConnector::new(builder, ClientFingerprint::Chrome120).unwrap();
    for (alpn, alps) in [
        (b"\x02h2\x08http/1.1".as_slice(), true),
        (b"\x08http/1.1".as_slice(), false),
        (b"".as_slice(), false),
    ] {
        let error = connector
            .configure(alpn)
            .unwrap()
            .connect("fingerprint.test", Capture::default())
            .unwrap_err();
        let boring::ssl::HandshakeError::WouldBlock(stream) = error else {
            panic!("expected captured ClientHello");
        };
        assert_eq!(stream.error().code(), ErrorCode::WANT_READ);
        let hello = extensions(&stream.get_ref().0);
        assert!(hello.contains_key(&65037), "ECH GREASE");
        assert_eq!(
            hello.get(&27).unwrap(),
            &[2, 0, 2],
            "Brotli certificate compression"
        );
        assert_eq!(hello.contains_key(&17513), alps, "ALPS only for offered h2");
        if alpn.is_empty() {
            assert!(!hello.contains_key(&16));
        } else {
            assert_eq!(&hello[&16][2..], alpn);
        }
        // Chrome120 omits Ed25519 on the wire; REALITY keeps proof-of-key
        // verification in the authenticated native exception, not this list.
        assert_eq!(
            hello[&13],
            [0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1]
        );
    }
}

#[test]
fn chrome120_preserves_the_complete_reference_cipher_order() {
    for _ in 0..8 {
        let builder = SslConnector::builder(SslMethod::tls()).unwrap();
        let connector = FingerprintConnector::new(builder, ClientFingerprint::Chrome120).unwrap();
        let error = connector
            .configure(b"\x02h2\x08http/1.1")
            .unwrap()
            .connect("fingerprint.test", Capture::default())
            .unwrap_err();
        let boring::ssl::HandshakeError::WouldBlock(stream) = error else {
            panic!("expected captured ClientHello");
        };
        let wire = &stream.get_ref().0;
        let at = 44 + usize::from(wire[43]);
        let length = usize::from(u16::from_be_bytes([wire[at], wire[at + 1]]));
        let codes: Vec<_> = wire[at + 2..at + 2 + length]
            .chunks_exact(2)
            .map(|v| u16::from_be_bytes([v[0], v[1]]))
            .collect();
        assert_eq!(codes[0] & 0x0f0f, 0x0a0a);
        assert_eq!(
            &codes[1..],
            &[
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ]
        );
        // Independent literals: official Mihomo v1.19.31 / uTLS v1.8.7
        // Chrome120 CF0 capture. Do not derive these from the profile catalog.
        let ext = extensions(wire);
        assert_eq!(&wire[9..11], &[3, 3]);
        assert_eq!(wire[43], 32);
        assert_eq!(ext[&10].len(), 10);
        let grease = &ext[&10][2..4];
        assert_eq!(grease[0], grease[1]);
        assert_eq!(grease[0] & 15, 10);
        assert_eq!(&ext[&10][4..], &[0, 29, 0, 23, 0, 24]);
        assert_eq!(ext[&51].len(), 43);
        assert_eq!(&ext[&51][2..4], grease);
        assert_eq!(&ext[&51][4..11], &[0, 1, 0, 0, 29, 0, 32]);
        assert_eq!(ext[&43].len(), 7);
        assert_eq!(&ext[&43][3..], &[3, 4, 3, 3]);
        for (kind, payload) in [
            (0, b"\0\x13\0\0\x10fingerprint.test".as_slice()),
            (5, &[1, 0, 0, 0, 0]),
            (11, &[1, 0]),
            (18, &[]),
            (23, &[]),
            (27, &[2, 0, 2]),
            (35, &[]),
            (45, &[1, 1]),
            (65281, &[0]),
            (17513, &[0, 3, 2, b'h', b'2']),
        ] {
            assert_eq!(ext[&kind], payload, "extension {kind}");
        }
        let ech = &ext[&65037];
        assert_eq!(&ech[..5], &[0, 0, 1, 0, 1]);
        assert_eq!(&ech[6..8], &[0, 32]);
        let payload = usize::from(u16::from_be_bytes([ech[40], ech[41]]));
        assert!([144, 176, 208, 240].contains(&payload));
        assert_eq!(ech.len(), 42 + payload);
        let mut pos = at + 2 + length + 2 + 2;
        let mut order = vec![];
        while pos < wire.len() {
            let kind = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
            let size = usize::from(u16::from_be_bytes([wire[pos + 2], wire[pos + 3]]));
            order.push(kind);
            pos += 4 + size;
        }
        assert_eq!(pos, wire.len());
        let is_grease = |id: u16| id & 0x0f0f == 0x0a0a && id >> 8 == id & 0xff;
        assert!(is_grease(order[0]));
        assert!(ext[&order[0]].is_empty());
        let last = order.len() - 1 - usize::from(order.last() == Some(&21));
        assert!(is_grease(order[last]));
        assert_eq!(ext[&order[last]], &[0]);
        let mut shuffled = order[1..last].to_vec();
        shuffled.sort_unstable();
        assert_eq!(
            shuffled,
            [0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17513, 65037, 65281]
        );
        if let Some(pad) = ext.get(&21) {
            let unpadded = wire.len() - 5 - pad.len() - 4;
            assert!((256..512).contains(&unpadded));
            assert_eq!(pad.len(), (512usize.saturating_sub(unpadded + 4)).max(1));
            assert!(pad.iter().all(|b| *b == 0));
        }
    }
}

#[test]
fn named_stream_profile_refuses_dtls_before_emitting_bytes() {
    let builder = SslConnector::builder(SslMethod::dtls()).unwrap();
    let connector = FingerprintConnector::new(builder, ClientFingerprint::Chrome120).unwrap();
    assert!(connector.configure(b"\x02h2").is_err());
}
