#![cfg(feature = "restls")]

// Native TLS peers connected by bounded memory queues, never host listeners.
// The synthetic relay masks one record; no TLS message/key/cipher is fabricated.
use boring::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    ssl::{
        ErrorCode, RestlsClientConfig, RestlsVersionHint, Ssl, SslContext, SslMethod, SslStream,
        SslVersion,
    },
    x509::{X509Name, X509},
};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, PartialEq)]
enum Relay {
    Mask,
    CoverOnly,
    Corrupt,
    BadSignature,
    BadFinished,
}

// Use the existing native signing seam to emit a well-formed but invalid
// ECDSA signature. Native TLS still creates the transcript and encrypted flight.
struct BadSignature;
impl boring::ssl::PrivateKeyMethod for BadSignature {
    fn sign(
        &self,
        _: &mut boring::ssl::SslRef,
        _: &[u8],
        _: boring::ssl::SslSignatureAlgorithm,
        out: &mut [u8],
    ) -> Result<usize, boring::ssl::PrivateKeyMethodError> {
        out[..8].copy_from_slice(&[0x30, 6, 2, 1, 1, 2, 1, 1]);
        Ok(8)
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

#[derive(Default)]
struct State {
    to_client: VecDeque<u8>,
    to_server: VecDeque<u8>,
    client_wire: Vec<u8>,
    server_wire: Vec<u8>,
    server_random: Option<[u8; 32]>,
    server_ccs: bool,
    transformed: bool,
    ticket_tampered: bool,
}

struct MemoryIo {
    state: Arc<Mutex<State>>,
    server: bool,
    relay: Relay,
    tls13: bool,
    key: [u8; 32],
}

impl Read for MemoryIo {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.lock().unwrap();
        let queue = if self.server {
            &mut state.to_server
        } else {
            &mut state.to_client
        };
        if queue.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        // Short reads exercise record assembly without sockets or timers.
        let size = out.len().min(queue.len()).min(137);
        for byte in &mut out[..size] {
            *byte = queue.pop_front().unwrap();
        }
        Ok(size)
    }
}

impl Write for MemoryIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().unwrap();
        if bytes.len()
            > 65_536usize.saturating_sub(
                state.to_client.len() + state.to_server.len() + state.server_wire.len(),
            )
        {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        if !self.server {
            if state.client_wire.len() + bytes.len() > 65_536 {
                return Err(io::ErrorKind::OutOfMemory.into());
            }
            state.client_wire.extend_from_slice(bytes);
            state.to_server.extend(bytes);
            return Ok(bytes.len());
        }
        state.server_wire.extend_from_slice(bytes);
        while state.server_wire.len() >= 5 {
            let size = usize::from(u16::from_be_bytes(
                state.server_wire[3..5].try_into().unwrap(),
            ));
            if size > 18_432 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if state.server_wire.len() < size + 5 {
                break;
            }
            let mut record: Vec<_> = state.server_wire.drain(..5 + size).collect();
            if self.relay == Relay::BadFinished && record[0] == 22 && !state.server_ccs {
                let mut position = 5;
                while position + 4 <= record.len() {
                    let length = u32::from_be_bytes([
                        0,
                        record[position + 1],
                        record[position + 2],
                        record[position + 3],
                    ]) as usize;
                    assert!(position + 4 + length <= record.len());
                    if record[position] == 4 {
                        // TLS 1.2's NewSessionTicket is after key derivation.
                        // Alter its opaque ticket, not any cryptographic key,
                        // so the real encrypted Finished has a wrong transcript.
                        record[position + 3 + length] ^= 1;
                        state.ticket_tampered = true;
                    }
                    position += 4 + length;
                }
            }
            if record[0] == 22 && (self.tls13 || !state.server_ccs) && size >= 38 && record[5] == 2
            {
                state.server_random = Some(record[11..43].try_into().unwrap());
            }
            let encrypted = record[0] == 23 || (!self.tls13 && state.server_ccs && record[0] == 22);
            if encrypted && !state.transformed && self.relay != Relay::CoverOnly {
                let mac = blake3::keyed_hash(&self.key, &state.server_random.unwrap());
                // TLS 1.2 GCM's first explicit nonce is zero. TLS 1.3 and CBC
                // have no such prefix. These cases are selected explicitly.
                let offset = if record[0] == 22 && record.get(5..13) == Some(&[0; 8]) {
                    13
                } else {
                    5
                };
                assert!(record.len() >= offset + 16);
                for (byte, mask) in record[offset..offset + 16]
                    .iter_mut()
                    .zip(&mac.as_bytes()[..16])
                {
                    *byte ^= mask;
                }
                if self.relay == Relay::Corrupt {
                    *record.last_mut().unwrap() ^= 1;
                }
                state.transformed = true;
            }
            if record[0] == 20 {
                state.server_ccs = true;
            }
            state.to_client.extend(record);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn contexts(
    version: SslVersion,
    group: &str,
    cipher: Option<&str>,
    bad_signature: bool,
) -> (Ssl, Ssl) {
    let key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "restls.invalid").unwrap();
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
    let mut server = SslContext::builder(SslMethod::tls()).unwrap();
    server.set_certificate(&cert).unwrap();
    server.set_private_key(&key).unwrap();
    if bad_signature {
        server.set_private_key_method(BadSignature);
    }
    server.set_min_proto_version(Some(version)).unwrap();
    server.set_max_proto_version(Some(version)).unwrap();
    server.set_curves_list(group).unwrap();
    let mut client = SslContext::builder(SslMethod::tls()).unwrap();
    client
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    client.set_max_proto_version(Some(version)).unwrap();
    client.set_curves_list("X25519:P-256:P-384").unwrap();
    client.cert_store_mut().add_cert(cert).unwrap();
    client.set_verify(boring::ssl::SslVerifyMode::PEER);
    if let Some(cipher) = cipher {
        server.set_cipher_list(cipher).unwrap();
        client.set_cipher_list(cipher).unwrap();
    }
    (
        Ssl::new(&client.build()).unwrap(),
        Ssl::new(&server.build()).unwrap(),
    )
}

fn handshake(version: SslVersion, group: &str, cipher: Option<&str>, relay: Relay) -> State {
    let key = blake3::derive_key("restls-traffic-key", b"synthetic-restls-password");
    let hint = if version == SslVersion::TLS1_2 {
        RestlsVersionHint::Tls12
    } else {
        RestlsVersionHint::Tls13
    };
    let (mut client, server) = contexts(version, group, cipher, relay == Relay::BadSignature);
    client
        .set_restls_client(&RestlsClientConfig::new(hint, move |input| {
            *blake3::keyed_hash(&key, input).as_bytes()
        }))
        .unwrap();
    let state = Arc::new(Mutex::new(State::default()));
    let mut client = SslStream::new(
        client,
        MemoryIo {
            state: state.clone(),
            server: false,
            relay,
            tls13: version == SslVersion::TLS1_3,
            key,
        },
    )
    .unwrap();
    let mut server = SslStream::new(
        server,
        MemoryIo {
            state: state.clone(),
            server: true,
            relay,
            tls13: version == SslVersion::TLS1_3,
            key,
        },
    )
    .unwrap();
    let mut completed = false;
    for _ in 0..1000 {
        match client.connect() {
            Ok(()) => {
                assert!(relay == Relay::Mask, "unauthenticated cover accepted");
                assert!(client.ssl().restls_authenticated());
                completed = true;
                break;
            }
            Err(error) if error.code() == ErrorCode::WANT_READ => {}
            Err(error) => {
                assert!(
                    relay != Relay::Mask,
                    "native handshake failed ({version:?}, {group}, {cipher:?}): {error}"
                );
                assert!(!client.ssl().restls_authenticated());
                assert_eq!(error.code(), ErrorCode::SSL);
                if relay == Relay::CoverOnly {
                    assert!(
                        error
                            .to_string()
                            .contains("HANDSHAKE_FAILURE_ON_CLIENT_HELLO"),
                        "plain cover must reach the final Restls gate: {error}"
                    );
                }
                if relay == Relay::BadSignature {
                    assert!(error.to_string().contains("BAD_SIGNATURE"), "{error}");
                }
                if relay == Relay::BadFinished {
                    assert!(error.to_string().contains("DIGEST_CHECK_FAILED"), "{error}");
                }
                completed = true;
                break;
            }
        }
        match server.accept() {
            Ok(()) => {}
            Err(error) if error.code() == ErrorCode::WANT_READ => {}
            Err(error) => panic!("memory TLS server failed: {error}"),
        }
    }
    assert!(
        completed,
        "no timeout or pending result counts as rejection"
    );
    drop(client);
    drop(server);
    Arc::try_unwrap(state).ok().unwrap().into_inner().unwrap()
}

#[test]
fn masked_tls13_is_authenticated_but_plain_cover_and_corruption_are_rejected() {
    for group in ["X25519", "P-384"] {
        for relay in [Relay::Mask, Relay::CoverOnly, Relay::Corrupt] {
            let state = handshake(SslVersion::TLS1_3, group, None, relay);
            assert_eq!(state.transformed, relay != Relay::CoverOnly);
        }
    }
}

#[test]
fn tls12_explicit_nonce_aead_and_cbc_keep_native_finished_validation() {
    for cipher in [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES128-SHA",
    ] {
        for group in ["X25519", "P-256", "P-384"] {
            for relay in [Relay::Mask, Relay::CoverOnly, Relay::Corrupt] {
                let state = handshake(SslVersion::TLS1_2, group, Some(cipher), relay);
                assert_eq!(state.transformed, relay != Relay::CoverOnly);
                // Check authentication against the public key that was really
                // used by native ClientKeyExchange, not merely a generated key.
                let mut wire = state.client_wire.as_slice();
                let mut messages = Vec::new();
                while wire.len() >= 5 && wire[0] == 22 {
                    let length = usize::from(u16::from_be_bytes(wire[3..5].try_into().unwrap()));
                    messages.extend_from_slice(&wire[5..5 + length]);
                    wire = &wire[5 + length..];
                }
                let mut messages = messages.as_slice();
                let mut session = None;
                let mut public = None;
                while !messages.is_empty() {
                    let length =
                        u32::from_be_bytes([0, messages[1], messages[2], messages[3]]) as usize;
                    let body = &messages[4..4 + length];
                    if messages[0] == 1 {
                        assert_eq!(body[34], 32);
                        session = Some(body[35..67].to_vec());
                    } else if messages[0] == 16 {
                        assert_eq!(usize::from(body[0]), body.len() - 1);
                        public = Some(body[1..].to_vec());
                    }
                    messages = &messages[4 + length..];
                }
                let (start, end) = match group {
                    "X25519" => (0, 11),
                    "P-256" => (11, 22),
                    "P-384" => (22, 32),
                    _ => unreachable!(),
                };
                let key = blake3::derive_key("restls-traffic-key", b"synthetic-restls-password");
                assert_eq!(
                    &session.unwrap()[start..end],
                    &blake3::keyed_hash(&key, &public.unwrap()).as_bytes()[..end - start]
                );
            }
        }
    }
}

#[test]
fn tls12_resumption_authenticates_the_offered_ticket_and_both_finished_messages() {
    let key = blake3::derive_key("restls-traffic-key", b"synthetic-restls-password");
    let (client, server) = contexts(
        SslVersion::TLS1_2,
        "X25519",
        Some("ECDHE-ECDSA-AES128-GCM-SHA256"),
        false,
    );
    let client_context = client.ssl_context().to_owned();
    let server_context = server.ssl_context().to_owned();
    let mut session: Option<boring::ssl::SslSession> = None;
    for resumed in [false, true] {
        let mut client = Ssl::new(&client_context).unwrap();
        if let Some(session) = session.as_ref() {
            // The session and SSL share the exact same native context.
            unsafe { client.set_session(session) }.unwrap();
        }
        client
            .set_restls_client(&RestlsClientConfig::new(
                RestlsVersionHint::Tls12,
                move |input| *blake3::keyed_hash(&key, input).as_bytes(),
            ))
            .unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let io = |server| MemoryIo {
            state: state.clone(),
            server,
            relay: Relay::Mask,
            tls13: false,
            key,
        };
        let mut client = SslStream::new(client, io(false)).unwrap();
        let mut server = SslStream::new(Ssl::new(&server_context).unwrap(), io(true)).unwrap();
        let (mut client_done, mut server_done) = (false, false);
        for _ in 0..1000 {
            if !client_done {
                match client.connect() {
                    Ok(()) => client_done = true,
                    Err(error) if error.code() == ErrorCode::WANT_READ => {}
                    Err(error) => panic!("client resumption={resumed}: {error}"),
                }
            }
            if !server_done {
                match server.accept() {
                    Ok(()) => server_done = true,
                    Err(error) if error.code() == ErrorCode::WANT_READ => {}
                    Err(error) => panic!("server resumption={resumed}: {error}"),
                }
            }
            if client_done && server_done {
                break;
            }
        }
        assert!(client_done && server_done);
        assert!(client.ssl().restls_authenticated());
        assert_eq!(client.ssl().session_reused(), resumed);
        assert_eq!(server.ssl().session_reused(), resumed);
        if resumed {
            let state = state.lock().unwrap();
            let wire = &state.client_wire;
            assert_eq!(&wire[..3], &[22, 3, 1]);
            assert_eq!(wire[5], 1);
            let body = &wire[9..];
            assert_eq!(body[34], 32);
            let session_id = &body[35..67];
            let mut position = 67;
            let ciphers = usize::from(u16::from_be_bytes(
                body[position..position + 2].try_into().unwrap(),
            ));
            position += 2 + ciphers;
            position += 1 + usize::from(body[position]);
            let extension_len = usize::from(u16::from_be_bytes(
                body[position..position + 2].try_into().unwrap(),
            ));
            position += 2;
            let mut extensions = &body[position..position + extension_len];
            let mut ticket = None;
            while !extensions.is_empty() {
                let kind = u16::from_be_bytes(extensions[..2].try_into().unwrap());
                let size = usize::from(u16::from_be_bytes(extensions[2..4].try_into().unwrap()));
                if kind == 35 {
                    ticket = Some(&extensions[4..4 + size]);
                }
                extensions = &extensions[4 + size..];
            }
            let ticket = ticket.expect("resumed ClientHello must carry the actual ticket");
            assert!(!ticket.is_empty());
            assert_eq!(
                &session_id[24..],
                &blake3::keyed_hash(&key, ticket).as_bytes()[..8]
            );
        }
        session = Some(client.ssl().session().unwrap().to_owned());
    }
}

#[test]
fn restls_cannot_replace_native_server_key_exchange_or_certificate_verify() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let state = handshake(version, "X25519", None, Relay::BadSignature);
        // TLS 1.2 verifies SKE before its encrypted records. TLS 1.3 first
        // restores a valid Restls mask, then must still reject the bad CV.
        assert_eq!(state.transformed, version == SslVersion::TLS1_3);
    }
}

#[test]
fn authenticated_record_with_wrong_finished_transcript_is_rejected() {
    let state = handshake(SslVersion::TLS1_2, "X25519", None, Relay::BadFinished);
    assert!(state.transformed && state.ticket_tampered);
}
