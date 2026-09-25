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
