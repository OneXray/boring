//! Named, version-pinned ClientHello profiles. Authentication and IO are owned
//! by the caller; a profile never changes certificate verification or dials.
use super::{
    CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration, SslConnector,
    SslConnectorBuilder, SslRef,
};
use crate::{cvt, error::ErrorStack, ffi};
use foreign_types::ForeignTypeRef;
use std::io::{self, Read, Write};

/// Implemented ClientHello profiles, not aliases for the latest browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientFingerprint {
    /// Chrome 120's classic X25519 profile. Transport ALPN remains caller-owned.
    /// This does not emulate HTTP/2 settings, QUIC, actual ECH or browser runtime.
    Chrome120,
    /// Chrome 133 with native X25519MLKEM768 + X25519 shares and new h2 ALPS.
    /// REALITY requires a separate explicit config; this does not shape QUIC.
    Chrome133,
    /// Firefox 120, with X25519/P-256 shares and its fixed extension order.
    Firefox120,
    /// Safari 16.0's stream profile. The caller still owns the TLS version floor.
    Safari16,
}

// A closed, bounded catalog, not user-supplied extension/cipher data. The native
// ID selects only encoding rules that existing BoringSSL APIs cannot express.
// Real key generation, negotiation, transcript and certificate proof stay native.
struct Profile {
    native_id: u32,
    ciphers: &'static str,
    groups: &'static [u16],
    key_shares: &'static [u16],
    signatures: &'static str,
    grease: bool,
    shuffle: bool,
    sct: bool,
    ech_grease: bool,
    alps_new_codepoint: Option<bool>,
    compression: Compression,
}

enum Compression {
    None,
    Brotli,
    Zlib,
}

impl ClientFingerprint {
    fn profile(self) -> &'static Profile {
        match self {
            Self::Chrome120 => &CHROME120,
            Self::Chrome133 => &CHROME133,
            Self::Firefox120 => &FIREFOX120,
            Self::Safari16 => &SAFARI16,
        }
    }
}

const CHROME120: Profile = Profile {
    native_id: 1,
    ciphers: concat!(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
        "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
    ),
    groups: &[29, 23, 24],
    key_shares: &[29],
    signatures: concat!(
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
        "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512"
    ),
    grease: true,
    shuffle: true,
    sct: true,
    ech_grease: true,
    alps_new_codepoint: Some(false),
    compression: Compression::Brotli,
};

const CHROME133: Profile = Profile {
    native_id: 2,
    groups: &[4588, 29, 23, 24],
    key_shares: &[4588, 29],
    alps_new_codepoint: Some(true),
    ..CHROME120
};

const FIREFOX120: Profile = Profile {
    native_id: 3,
    ciphers: concat!(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
        "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:",
        "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
        "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
    ),
    groups: &[29, 23, 24, 25],
    key_shares: &[29, 23],
    signatures: concat!(
        "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:",
        "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:",
        "rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ecdsa_sha1:rsa_pkcs1_sha1"
    ),
    grease: false,
    shuffle: false,
    sct: false,
    ech_grease: true,
    alps_new_codepoint: None,
    compression: Compression::None,
};

const SAFARI16: Profile = Profile {
    native_id: 4,
    ciphers: concat!(
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:",
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:",
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:",
        "ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:",
        "AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA:AES128-SHA:",
        "ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA"
    ),
    groups: &[29, 23, 24, 25],
    key_shares: &[29],
    signatures: concat!(
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
        "ecdsa_secp384r1_sha384:ecdsa_sha1:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512:rsa_pkcs1_sha1"
    ),
    grease: true,
    shuffle: false,
    sct: true,
    ech_grease: false,
    alps_new_codepoint: None,
    compression: Compression::Zlib,
};

/// Immutable profile plus caller-configured TLS trust, versions and identity.
/// Each connection supplies its transport ALPN; no profile can override it.
#[derive(Debug, Clone)]
pub struct FingerprintConnector {
    connector: SslConnector,
    profile: ClientFingerprint,
}

impl FingerprintConnector {
    /// Finishes a caller-owned builder with the selected handshake profile.
    /// Configure trust, TLS versions, client identity and session callbacks on
    /// `builder` first. This does not enable resumption or bypass verification.
    pub fn new(
        mut builder: SslConnectorBuilder,
        profile: ClientFingerprint,
    ) -> Result<Self, ErrorStack> {
        let spec = profile.profile();
        builder.set_strict_cipher_list(spec.ciphers)?;
        builder.set_sigalgs_list(spec.signatures)?;
        builder.set_grease_enabled(spec.grease);
        builder.set_permute_extensions(spec.shuffle);
        if spec.sct {
            builder.enable_signed_cert_timestamps();
        }
        builder.enable_ocsp_stapling();
        match spec.compression {
            Compression::None => {}
            Compression::Brotli => builder.add_certificate_compression_algorithm(Brotli)?,
            Compression::Zlib => builder.add_certificate_compression_algorithm(Zlib)?,
        }
        // These setters copy bounded static values; native code validates IDs.
        unsafe {
            cvt(ffi::SSL_CTX_set1_group_ids(
                builder.as_ptr(),
                spec.groups.as_ptr(),
                spec.groups.len(),
            ))?;
            ffi::SSL_CTX_set_max_cert_list(builder.as_ptr(), MAX_CERTIFICATE_BYTES);
        }
        Ok(Self {
            connector: builder.build(),
            profile,
        })
    }

    /// Prepares one connection. `alpn` uses TLS length-prefixed wire encoding;
    /// an empty slice sends no ALPN. The returned configuration still accepts
    /// per-connection SNI/verification and opt-in REALITY through their normal
    /// interfaces. Do not subsequently override its ALPN/profile settings.
    pub fn configure(&self, alpn: &[u8]) -> Result<ConnectConfiguration, ErrorStack> {
        let mut config = self.connector.configure()?;
        let spec = self.profile.profile();
        unsafe {
            cvt(ffi::SSL_set_client_fingerprint(
                config.as_ptr(),
                spec.native_id,
            ))?;
            cvt(ffi::SSL_set1_client_key_shares(
                config.as_ptr(),
                spec.key_shares.as_ptr(),
                spec.key_shares.len(),
            ))?;
        }
        config.set_alpn_protos(alpn)?;
        config.set_enable_ech_grease(spec.ech_grease);
        let mut protocols = alpn;
        let mut offers_h2 = false;
        while let Some((&length, tail)) = protocols.split_first() {
            let Some((protocol, rest)) = tail.split_at_checked(usize::from(length)) else {
                // The public ALPN setter already rejects malformed input.
                return Err(ErrorStack::get());
            };
            offers_h2 |= protocol == b"h2";
            protocols = rest;
        }
        if let Some(new_codepoint) = spec.alps_new_codepoint.filter(|_| offers_h2) {
            unsafe {
                ffi::SSL_set_alps_use_new_codepoint(config.as_ptr(), new_codepoint.into());
                cvt(ffi::SSL_add_application_settings(
                    config.as_ptr(),
                    b"h2".as_ptr(),
                    2,
                    b"".as_ptr(),
                    0,
                ))?;
            }
        }
        Ok(config)
    }
}

impl SslRef {
    /// Returns the peer's negotiated ALPS bytes after a completed handshake.
    /// `None` is distinct from negotiated empty settings. TLS does not parse
    /// these application-owned bytes or configure an HTTP/2 implementation.
    /// The borrow cannot outlive or overlap mutation of this SSL connection.
    #[must_use]
    pub fn peer_application_settings(&self) -> Option<&[u8]> {
        // SAFETY: the native API returns SSL-owned storage. Its borrow is
        // bounded by &self. Avoid constructing a slice from a null empty buffer.
        unsafe {
            if ffi::SSL_has_application_settings(self.as_ptr()) != 1 {
                return None;
            }
            let mut data = std::ptr::null();
            let mut length = 0;
            ffi::SSL_get0_peer_application_settings(self.as_ptr(), &mut data, &mut length);
            Some(if length == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(data, length)
            })
        }
    }
}

const MAX_CERTIFICATE_BYTES: usize = 128 * 1024;

struct Zlib;
impl CertificateCompressor for Zlib {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        if input.len() > MAX_CERTIFICATE_BYTES {
            return Err(io::Error::other("compressed certificate limit"));
        }
        // Fixed bound, independent of the untrusted declared size. Require a
        // complete, checksummed stream and reject trailing concatenated data.
        let mut buffer = vec![0; MAX_CERTIFICATE_BYTES + 1];
        let mut decoder = flate2::Decompress::new(true);
        let status = decoder.decompress(input, &mut buffer, flate2::FlushDecompress::Finish)?;
        if status != flate2::Status::StreamEnd
            || decoder.total_in() != input.len() as u64
            || decoder.total_out() > MAX_CERTIFICATE_BYTES as u64
        {
            return Err(io::Error::other(
                "invalid or oversized certificate compression",
            ));
        }
        output.write_all(&buffer[..decoder.total_out() as usize])
    }
}

struct Brotli;
impl CertificateCompressor for Brotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        if input.len() > MAX_CERTIFICATE_BYTES {
            return Err(io::Error::other("compressed certificate limit"));
        }
        let mut decoder = brotli::Decompressor::new(input, 4096);
        let mut buffer = [0; 4096];
        let mut total = 0;
        loop {
            let count = decoder.read(&mut buffer)?;
            if count == 0 {
                return Ok(());
            }
            total += count;
            if total > MAX_CERTIFICATE_BYTES {
                return Err(io::Error::other("certificate output limit"));
            }
            output.write_all(&buffer[..count])?;
        }
    }
}
