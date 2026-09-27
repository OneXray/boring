#![cfg(feature = "reality")]

// Public-interface tests only. No sockets or host listeners are created.
use boring::{
    derive::Deriver,
    hash::MessageDigest,
    hkdf::HkdfSuite,
    pkey::{Id, PKey, Private},
    ssl::{ErrorCode, RealityClientConfig, Ssl, SslContext, SslMethod, SslStream, SslVersion},
    symm::{decrypt_aead, Cipher},
};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct Capture {
    wire: Vec<u8>,
    budget: usize,
    incoming: VecDeque<u8>,
}
impl Read for Capture {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.incoming.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let count = buffer.len().min(self.incoming.len());
        for byte in &mut buffer[..count] {
            *byte = self.incoming.pop_front().unwrap();
        }
        Ok(count)
    }
}
impl Write for Capture {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.budget == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let count = self.budget.min(data.len());
        self.wire.extend_from_slice(&data[..count]);
        self.budget -= count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn parameters() -> (PKey<Private>, RealityClientConfig) {
    let server = PKey::generate(Id::X25519).unwrap();
    let mut public = [0; 32];
    server.raw_public_key(&mut public).unwrap();
    let config = RealityClientConfig::new(public, &[0xab, 0xcd], [1, 8, 0]).unwrap();
    (server, config)
}

fn client(config: &RealityClientConfig) -> Ssl {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    ctx.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ctx.set_curves_list("X25519:P-256:P-384").unwrap();
    ctx.set_grease_enabled(true);
    ctx.set_permute_extensions(true);
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_hostname("reality.test").unwrap();
    ssl.set_reality_client(config).unwrap();
    ssl
}

fn capture(ssl: Ssl) -> SslStream<Capture> {
    SslStream::new(
        ssl,
        Capture {
            budget: usize::MAX,
            ..Capture::default()
        },
    )
    .unwrap()
}

fn hello(wire: &[u8]) -> Vec<u8> {
    assert_eq!(wire[0], 22);
    let n = u16::from_be_bytes(wire[3..5].try_into().unwrap()) as usize;
    let msg = wire[5..5 + n].to_vec();
    assert_eq!(msg[0], 1);
    assert_eq!(msg[38], 32);
    msg
}

fn u16_at(bytes: &[u8], i: usize) -> usize {
    u16::from_be_bytes(bytes[i..i + 2].try_into().unwrap()) as usize
}

fn wire_auth_key(server: &PKey<Private>, msg: &[u8]) -> [u8; 32] {
    let mut cursor = 71;
    cursor += 2 + u16_at(msg, cursor);
    cursor += 1 + msg[cursor] as usize;
    let end = cursor + 2 + u16_at(msg, cursor);
    cursor += 2;
    let mut public = None;
    let mut hybrid_public = None;
    while cursor < end {
        let kind = u16_at(msg, cursor);
        let len = u16_at(msg, cursor + 2);
        cursor += 4;
        if kind == 51 {
            let mut share = cursor + 2;
            while share < cursor + len {
                let group = u16_at(msg, share);
                let size = u16_at(msg, share + 2);
                if group == 29 {
                    assert_eq!(size, 32);
                    public = Some(&msg[share + 4..share + 4 + size]);
                } else if group == 4588 {
                    assert_eq!(size, 1184 + 32);
                    hybrid_public = Some(&msg[share + 4 + 1184..share + 4 + size]);
                }
                share += 4 + size;
            }
        }
        cursor += len;
    }
    // Independent server-side derivation from only its key and the wire share.
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0,
    ];
    // Independent Mihomo server rule: prefer the classic share when present,
    // otherwise authenticate the X25519 tail of the hybrid share.
    spki.extend_from_slice(public.or(hybrid_public).unwrap());
    let peer = PKey::public_key_from_der(&spki).unwrap();
    let mut derive = Deriver::new(server).unwrap();
    derive.set_peer(&peer).unwrap();
    let shared = derive.derive_to_vec().unwrap();
    let hkdf = HkdfSuite::new(MessageDigest::sha256());
    let prk = hkdf.extract(&msg[6..26], &shared).unwrap();
    let mut key = [0; 32];
    hkdf.expand(&prk, b"REALITY", &mut key).unwrap();
    key
}

fn authenticate_hello(server: &PKey<Private>, msg: &[u8]) {
    let key = wire_auth_key(server, msg);
    let mut aad = msg.to_vec();
    aad[39..71].fill(0);
    let plain = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&msg[26..38]),
        &aad,
        &msg[39..55],
        &msg[55..71],
    )
    .unwrap();
    assert_eq!(&plain[..4], &[1, 8, 0, 0]);
    assert_eq!(&plain[8..], &[0xab, 0xcd, 0, 0, 0, 0, 0, 0]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timestamp = u32::from_be_bytes(plain[4..8].try_into().unwrap()) as u64;
    assert!(timestamp.abs_diff(now) < 30);
    aad[6] ^= 1;
    assert!(decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&msg[26..38]),
        &aad,
        &msg[39..55],
        &msg[55..71]
    )
    .is_err());
}

#[test]
fn hello_authenticates_wire_key_share_and_final_aad() {
    let (server, config) = parameters();
    let mut stream = capture(client(&config));
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    authenticate_hello(&server, &hello(&stream.get_ref().wire));
}

fn hybrid_only_client(config: &RealityClientConfig) -> Ssl {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ctx.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ctx.set_curves_list("X25519MLKEM768").unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_hostname("reality.test").unwrap();
    ssl.set_reality_client(&config.clone().require_x25519mlkem768())
        .unwrap();
    ssl
}

#[test]
fn hybrid_only_reality_authenticates_with_its_own_ecdh_component() {
    let (server, config) = parameters();
    let mut stream = capture(hybrid_only_client(&config));
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    let msg = hello(&stream.get_ref().wire);
    assert_eq!(hello_groups(&msg).1, [(4588, 1216)]);
    authenticate_hello(&server, &msg);
    assert_eq!(
        memory_handshake_with_group(
            hybrid_only_client,
            "X25519MLKEM768",
            false,
            false,
            false,
            false
        )
        .unwrap(),
        4588
    );
}

#[cfg(feature = "client-fingerprint")]
#[test]
fn explicit_hybrid_reality_preserves_chrome133_shares_and_authentication() {
    use boring::ssl::{ClientFingerprint, FingerprintConnector, SslConnector};
    let (server, config) = parameters();
    let connector = FingerprintConnector::new(
        SslConnector::builder(SslMethod::tls()).unwrap(),
        ClientFingerprint::Chrome133,
    )
    .unwrap();
    let mut connection = connector.configure(b"\x02h2").unwrap();
    connection
        .set_reality_client(&config.require_x25519mlkem768())
        .unwrap();
    let mut stream = capture(connection.into_ssl("reality.test").unwrap());
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    let msg = hello(&stream.get_ref().wire);
    assert_eq!(hello_groups(&msg).1, [(4588, 1216), (29, 32)]);
    authenticate_hello(&server, &msg);
}

#[cfg(feature = "client-fingerprint")]
#[test]
fn named_profile_preserves_reality_wire_authentication() {
    use boring::ssl::{ClientFingerprint, FingerprintConnector, SslConnector};
    let (server, config) = parameters();
    for profile in [
        ClientFingerprint::Chrome120,
        ClientFingerprint::Chrome133,
        ClientFingerprint::Firefox120,
        ClientFingerprint::Safari16,
    ] {
        let connector =
            FingerprintConnector::new(SslConnector::builder(SslMethod::tls()).unwrap(), profile)
                .unwrap();
        for _ in 0..4 {
            let mut connection = connector.configure(b"\x02h2\x08http/1.1").unwrap();
            connection.set_reality_client(&config).unwrap();
            let mut stream = capture(connection.into_ssl("reality.test").unwrap());
            // Retry a partial initial write: the authenticated identity must not
            // be resealed, and authentication binds the final profile's bytes.
            stream.get_mut().budget = 7;
            assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_WRITE);
            stream.get_mut().budget = usize::MAX;
            assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
            let bytes = stream.get_ref().wire.clone();
            assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
            assert_eq!(stream.get_ref().wire, bytes);
            let msg = hello(&bytes);
            authenticate_hello(&server, &msg);
            let (groups, shares) = hello_groups(&msg);
            assert!(!groups.contains(&4588));
            let expected = if profile == ClientFingerprint::Firefox120 {
                vec![(29, 32), (23, 65)]
            } else {
                vec![(29, 32)]
            };
            assert_eq!(shares, expected, "{profile:?}");
            assert!(stream.ssl_mut().set_reality_client(&config).is_err());
        }
    }
}

fn hello_groups(msg: &[u8]) -> (Vec<u16>, Vec<(u16, usize)>) {
    let mut cursor = 71;
    cursor += 2 + u16_at(msg, cursor);
    cursor += 1 + usize::from(msg[cursor]);
    let end = cursor + 2 + u16_at(msg, cursor);
    cursor += 2;
    let mut groups = Vec::new();
    let mut shares = Vec::new();
    while cursor < end {
        let kind = u16_at(msg, cursor);
        let len = u16_at(msg, cursor + 2);
        cursor += 4;
        if kind == 10 {
            groups = msg[cursor + 2..cursor + len]
                .chunks_exact(2)
                .map(|x| u16::from_be_bytes([x[0], x[1]]))
                .filter(|id| id & 0x0f0f != 0x0a0a)
                .collect();
        } else if kind == 51 {
            let mut at = cursor + 2;
            while at < cursor + len {
                let id = u16_at(msg, at) as u16;
                let size = u16_at(msg, at + 2);
                if id & 0x0f0f != 0x0a0a {
                    shares.push((id, size));
                }
                at += 4 + size;
            }
            assert_eq!(at, cursor + len);
        }
        cursor += len;
    }
    assert_eq!(cursor, end);
    (groups, shares)
}

#[test]
fn reality_binds_x25519_even_when_it_is_not_the_first_share() {
    use foreign_types::ForeignTypeRef;
    let (server, config) = parameters();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_curves_list("P-256:X25519:P-384").unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    let shares = [23, 29];
    unsafe {
        assert_eq!(
            boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), 2),
            1
        );
    }
    ssl.set_reality_client(&config).unwrap();
    let mut stream = capture(ssl);
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    let msg = hello(&stream.get_ref().wire);
    assert_eq!(hello_groups(&msg).1, [(23, 65), (29, 32)]);
    authenticate_hello(&server, &msg);
}

#[test]
fn retry_does_not_reseal_and_cancel_does_not_reuse_state() {
    let (server, config) = parameters();
    let mut stream = capture(client(&config));
    stream.get_mut().budget = 7;
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_WRITE);
    stream.get_mut().budget = usize::MAX;
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    let first = stream.get_ref().wire.clone();
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    assert_eq!(stream.get_ref().wire, first);
    authenticate_hello(&server, &hello(&first));
    assert!(stream.ssl_mut().set_reality_client(&config).is_err());
    drop(stream);
    for _ in 0..16 {
        let mut next = capture(client(&config));
        assert_eq!(next.connect().unwrap_err().code(), ErrorCode::WANT_READ);
        let next_hello = hello(&next.get_ref().wire);
        assert_ne!(&next_hello[6..71], &hello(&first)[6..71]);
        authenticate_hello(&server, &next_hello);
    }
}

#[test]
fn low_order_key_emits_no_client_hello() {
    for low_order in [[0; 32], {
        let mut k = [0; 32];
        k[0] = 1;
        k
    }] {
        let config = RealityClientConfig::new(low_order, &[], [1, 8, 0]).unwrap();
        let mut stream = capture(client(&config));
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
        assert!(stream.get_ref().wire.is_empty());
    }
}

#[test]
fn invalid_configuration_is_rejected_before_sending() {
    assert!(RealityClientConfig::new([2; 32], &[0; 9], [1, 8, 0]).is_err());
    let (_, config) = parameters();
    let mut ssl = client(&config);
    assert!(ssl.set_reality_client(&config).is_err());
    ssl.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    let mut stream = capture(ssl);
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
    assert!(stream.get_ref().wire.is_empty());
    let ssl = client(&config);
    let mut stream = capture(ssl);
    assert_eq!(stream.accept().unwrap_err().code(), ErrorCode::SSL);
    assert!(stream.get_ref().wire.is_empty());
}

#[test]
fn dtls_and_changed_key_share_configuration_fail_closed() {
    let (_, config) = parameters();
    let ctx = SslContext::builder(SslMethod::dtls()).unwrap().build();
    assert!(Ssl::new(&ctx).unwrap().set_reality_client(&config).is_err());
    let mut ssl = client(&config);
    ssl.set_curves_list("P-256").unwrap();
    let mut stream = capture(ssl);
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
    assert!(stream.get_ref().wire.is_empty());
}

#[test]
fn reality_rejects_reintroduced_pq_and_early_data_before_io() {
    use foreign_types::ForeignTypeRef;
    let (_, parameters) = parameters();
    for pq in [false, true] {
        let mut ssl = client(&parameters);
        unsafe {
            if pq {
                ssl.set_curves_list("X25519MLKEM768:X25519").unwrap();
                let shares = [4588, 29];
                assert_eq!(
                    boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), 2),
                    1
                );
            } else {
                boring_sys::SSL_set_early_data_enabled(ssl.as_ptr(), 1);
            }
        }
        let mut stream = capture(ssl);
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
        assert!(stream.get_ref().wire.is_empty());
    }
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_curves_list("P-256").unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    // No hidden identity key may be created when X25519 is unavailable.
    assert!(ssl.set_reality_client(&parameters).is_err());
}

fn der(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    match payload.len() {
        0..=127 => output.push(payload.len() as u8),
        128..=255 => output.extend_from_slice(&[0x81, payload.len() as u8]),
        _ => {
            output.push(0x82);
            output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
    }
    output.extend_from_slice(payload);
    output
}

// Synthetic certificate envelope only. Native BoringSSL still produces and
// verifies the TLS 1.3 records/transcript; this is not a TLS server decoder.
fn temporary_certificate(
    key: &PKey<Private>,
    auth: &[u8; 32],
    bad_hmac: bool,
    large: bool,
) -> boring::x509::X509 {
    let algorithm = der(0x30, &[0x06, 0x03, 0x2b, 0x65, 0x70]);
    let name = der(
        0x30,
        &der(
            0x31,
            &der(
                0x30,
                &[der(6, &[0x55, 4, 3]), der(0x0c, b"reality.test")].concat(),
            ),
        ),
    );
    let validity = der(
        0x30,
        &[der(0x17, b"200101000000Z"), der(0x17, b"491231235959Z")].concat(),
    );
    let mut tbs = [
        der(0xa0, &der(2, &[2])),
        der(2, &[1]),
        algorithm.clone(),
        name.clone(),
        validity,
        name,
        key.public_key_to_der().unwrap(),
    ]
    .concat();
    if large {
        let extension = der(
            0x30,
            &[der(6, &[0x2a, 3, 4]), der(4, &vec![0; 20000])].concat(),
        );
        tbs.extend_from_slice(&der(0xa3, &der(0x30, &extension)));
    }
    let mut public = [0; 32];
    let mut hmac = boring::hmac::Hmac::init(auth, &MessageDigest::sha512()).unwrap();
    hmac.update(key.raw_public_key(&mut public).unwrap())
        .unwrap();
    let mut signature = hmac.finalize().unwrap();
    if bad_hmac {
        signature[0] ^= 1;
    }
    let signature = der(3, &[vec![0], signature].concat());
    boring::x509::X509::from_der(&der(
        0x30,
        &[der(0x30, &tbs), algorithm, signature].concat(),
    ))
    .unwrap()
}

struct BadSignature;
impl boring::ssl::PrivateKeyMethod for BadSignature {
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

fn memory_handshake(
    make_client: impl FnOnce(&RealityClientConfig) -> Ssl,
    bad_hmac: bool,
    bad_signature: bool,
    extra_cert: bool,
    large: bool,
) -> Result<(), String> {
    memory_handshake_with_group(
        make_client,
        "X25519",
        bad_hmac,
        bad_signature,
        extra_cert,
        large,
    )
    .map(|_| ())
}

fn memory_handshake_with_group(
    make_client: impl FnOnce(&RealityClientConfig) -> Ssl,
    server_group: &str,
    bad_hmac: bool,
    bad_signature: bool,
    extra_cert: bool,
    large: bool,
) -> Result<u16, String> {
    let (static_key, parameters) = parameters();
    let mut ssl = make_client(&parameters);
    // The unmodified native TLS test server obeys the advertised list, unlike
    // a REALITY server. Chrome's unchanged list is covered by Mihomo interop.
    ssl.set_verify_algorithm_prefs(&[boring::ssl::SslSignatureAlgorithm::ED25519])
        .unwrap();
    // Deliberately permissive trust policy cannot bypass REALITY authentication.
    ssl.set_custom_verify_callback(boring::ssl::SslVerifyMode::NONE, |_| Ok(()));
    let mut client = capture(ssl);
    assert_eq!(client.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    let auth = wire_auth_key(&static_key, &hello(&client.get_ref().wire));
    let cert_key = PKey::generate(Id::ED25519).unwrap();
    let cert = temporary_certificate(&cert_key, &auth, bad_hmac, large);
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ctx.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ctx.set_curves_list(server_group).unwrap();
    ctx.set_certificate(&cert).unwrap();
    if extra_cert {
        ctx.add_extra_chain_cert(cert).unwrap();
    }
    ctx.set_private_key(&cert_key).unwrap();
    if bad_signature {
        ctx.set_private_key_method(BadSignature);
    }
    let mut server = capture(Ssl::new(&ctx.build()).unwrap());
    let mut client_done = false;
    let mut server_done = false;
    for _ in 0..16 {
        server
            .get_mut()
            .incoming
            .extend(client.get_mut().wire.drain(..));
        if !server_done {
            match server.accept() {
                Ok(()) => server_done = true,
                Err(error) => assert_eq!(error.code(), ErrorCode::WANT_READ, "fixture: {error}"),
            }
        }
        client
            .get_mut()
            .incoming
            .extend(server.get_mut().wire.drain(..));
        if !client_done {
            match client.connect() {
                Ok(()) => client_done = true,
                Err(error) if error.code() == ErrorCode::WANT_READ => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        if client_done && server_done {
            use foreign_types::ForeignTypeRef;
            // Read-only public query on the completed native TLS connection.
            return Ok(unsafe { boring_sys::SSL_get_group_id(client.ssl().as_ptr()) });
        }
    }
    panic!("bounded memory handshake failed to progress");
}

#[cfg(feature = "client-fingerprint")]
#[test]
fn required_hybrid_reality_negotiates_hybrid_and_rejects_classic_selection() {
    use boring::ssl::{ClientFingerprint, FingerprintConnector, SslConnector};
    let connector = FingerprintConnector::new(
        SslConnector::builder(SslMethod::tls()).unwrap(),
        ClientFingerprint::Chrome133,
    )
    .unwrap();
    let make_client = |config: &RealityClientConfig| {
        let mut connection = connector.configure(b"").unwrap();
        connection
            .set_reality_client(&config.clone().require_x25519mlkem768())
            .unwrap();
        connection.into_ssl("reality.test").unwrap()
    };
    assert_eq!(
        memory_handshake_with_group(make_client, "X25519MLKEM768", false, false, false, false)
            .unwrap(),
        4588
    );
    let error =
        memory_handshake_with_group(make_client, "X25519", false, false, false, false).unwrap_err();
    assert!(error.contains("WRONG_CURVE"), "{error}");
    let error =
        memory_handshake_with_group(make_client, "P-384", false, false, false, false).unwrap_err();
    assert!(error.contains("UNEXPECTED_MESSAGE"), "{error}");
}

#[test]
fn hybrid_reality_keeps_certificate_authentication_and_native_proof_mandatory() {
    for (bad_hmac, bad_signature, extra, large, expected) in [
        (true, false, false, false, "CERTIFICATE_VERIFY_FAILED"),
        (false, true, false, false, "BAD_SIGNATURE"),
        (false, false, true, false, "CERTIFICATE_VERIFY_FAILED"),
        (false, false, false, true, "CERTIFICATE_VERIFY_FAILED"),
    ] {
        let error = memory_handshake_with_group(
            hybrid_only_client,
            "X25519MLKEM768",
            bad_hmac,
            bad_signature,
            extra,
            large,
        )
        .unwrap_err();
        assert!(error.contains(expected), "{error}");
    }
    for public in [[0; 32], {
        let mut public = [0; 32];
        public[0] = 1;
        public
    }] {
        let config = RealityClientConfig::new(public, &[], [1, 8, 0]).unwrap();
        let mut stream = capture(hybrid_only_client(&config));
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
        assert!(stream.get_ref().wire.is_empty());
    }
}

#[cfg(feature = "client-fingerprint")]
#[test]
fn incompatible_profiles_or_later_share_changes_cannot_disable_hybrid_requirement() {
    use boring::ssl::{ClientFingerprint, FingerprintConnector, SslConnector};
    use foreign_types::ForeignTypeRef;
    let (_, config) = parameters();
    for profile in [
        ClientFingerprint::Chrome120,
        ClientFingerprint::Firefox120,
        ClientFingerprint::Safari16,
    ] {
        let connector =
            FingerprintConnector::new(SslConnector::builder(SslMethod::tls()).unwrap(), profile)
                .unwrap();
        let mut connection = connector.configure(b"").unwrap();
        assert!(connection
            .set_reality_client(&config.clone().require_x25519mlkem768())
            .is_err());
        // A rejected config neither changes the template nor installs an
        // unusable half-identity. The original classic config still works.
        connection.set_reality_client(&config).unwrap();
        let mut stream = capture(connection.into_ssl("reality.test").unwrap());
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    }
    let mut ssl = hybrid_only_client(&config);
    ssl.set_curves_list("X25519").unwrap();
    let shares = [29];
    unsafe {
        assert_eq!(
            boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), 1),
            1
        );
    }
    let mut stream = capture(ssl);
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
    assert!(stream.get_ref().wire.is_empty());
}

#[test]
fn hybrid_retries_and_cancelled_connections_never_reuse_authentication() {
    let (server, config) = parameters();
    let mut identities = std::collections::HashSet::new();
    for _ in 0..20 {
        let mut stream = capture(hybrid_only_client(&config));
        stream.get_mut().budget = 7;
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_WRITE);
        stream.get_mut().budget = usize::MAX;
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
        let wire = stream.get_ref().wire.clone();
        let msg = hello(&wire);
        authenticate_hello(&server, &msg);
        assert!(identities.insert(msg[6..71].to_vec()));
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
        assert_eq!(stream.get_ref().wire, wire);
        assert!(stream.ssl_mut().set_reality_client(&config).is_err());
        drop(stream);
    }
}

#[test]
fn real_certificate_verify_is_required_after_hmac_authentication() {
    memory_handshake(client, false, false, false, false).unwrap();
    let error = memory_handshake(client, false, true, false, false).unwrap_err();
    assert!(error.contains("BAD_SIGNATURE"), "{error}");
}

#[test]
fn certificate_hmac_chain_and_size_cannot_be_bypassed() {
    for (bad_hmac, extra, large) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let error = memory_handshake(client, bad_hmac, false, extra, large).unwrap_err();
        assert!(error.contains("CERTIFICATE_VERIFY_FAILED"), "{error}");
    }
}

#[cfg(feature = "client-fingerprint")]
#[test]
fn each_profile_requires_temporary_certificate_hmac_and_native_proof() {
    use boring::ssl::{ClientFingerprint, FingerprintConnector, SslConnector};
    for profile in [
        ClientFingerprint::Chrome120,
        ClientFingerprint::Chrome133,
        ClientFingerprint::Firefox120,
        ClientFingerprint::Safari16,
    ] {
        let connector =
            FingerprintConnector::new(SslConnector::builder(SslMethod::tls()).unwrap(), profile)
                .unwrap();
        let make_client = |reality: &RealityClientConfig| {
            let mut configuration = connector.configure(b"\x02h2").unwrap();
            configuration.set_reality_client(reality).unwrap();
            configuration.into_ssl("reality.test").unwrap()
        };
        // Native peer obeys sigalgs, so memory_handshake advertises Ed25519 for
        // this crypto gate only. Separate wire vectors preserve the real list;
        // the later independent Mihomo gate uses that unmodified profile.
        memory_handshake(make_client, false, false, false, false).unwrap();
        for (bad_hmac, bad_signature, extra, large, expected) in [
            (true, false, false, false, "CERTIFICATE_VERIFY_FAILED"),
            (false, true, false, false, "BAD_SIGNATURE"),
            (false, false, true, false, "CERTIFICATE_VERIFY_FAILED"),
            (false, false, false, true, "CERTIFICATE_VERIFY_FAILED"),
        ] {
            let error =
                memory_handshake(make_client, bad_hmac, bad_signature, extra, large).unwrap_err();
            assert!(error.contains(expected), "{profile:?}: {error}");
        }
        for public in [[0; 32], {
            let mut public = [0; 32];
            public[0] = 1;
            public
        }] {
            let parameters = RealityClientConfig::new(public, &[], [1, 8, 0]).unwrap();
            let mut stream = capture(make_client(&parameters));
            assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::SSL);
            assert!(stream.get_ref().wire.is_empty());
        }
    }
}
