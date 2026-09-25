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
}

/// Immutable profile plus caller-configured TLS trust, versions and identity.
/// Each connection supplies its transport ALPN; no profile can override it.
#[derive(Debug, Clone)]
pub struct FingerprintConnector {
    connector: SslConnector,
}

impl FingerprintConnector {
    /// Finishes a caller-owned builder with the selected handshake profile.
    /// Configure trust, TLS versions, client identity and session callbacks on
    /// `builder` first. This does not enable resumption or bypass verification.
    pub fn new(
        mut builder: SslConnectorBuilder,
        profile: ClientFingerprint,
    ) -> Result<Self, ErrorStack> {
        match profile {
            ClientFingerprint::Chrome120 => {
                builder.set_strict_cipher_list(concat!(
                    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
                    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
                    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
                    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
                    "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
                ))?;
                builder.set_curves_list("X25519:P-256:P-384")?;
                builder.set_sigalgs_list(concat!(
                    "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
                    "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
                    "rsa_pss_rsae_sha512:rsa_pkcs1_sha512"
                ))?;
                builder.set_grease_enabled(true);
                builder.set_permute_extensions(true);
                builder.enable_signed_cert_timestamps();
                builder.enable_ocsp_stapling();
                builder.add_certificate_compression_algorithm(Brotli)?;
                // Native checks the declared size before allocating decompression
                // output; the Rust decoder also enforces the same output bound.
                unsafe {
                    ffi::SSL_CTX_set_max_cert_list(builder.as_ptr(), MAX_CERTIFICATE_BYTES);
                }
            }
        }
        Ok(Self {
            connector: builder.build(),
        })
    }

    /// Prepares one connection. `alpn` uses TLS length-prefixed wire encoding;
    /// an empty slice sends no ALPN. The returned configuration still accepts
    /// per-connection SNI/verification and opt-in REALITY through their normal
    /// interfaces. Do not subsequently override its ALPN/profile settings.
    pub fn configure(&self, alpn: &[u8]) -> Result<ConnectConfiguration, ErrorStack> {
        let mut config = self.connector.configure()?;
        config.set_alpn_protos(alpn)?;
        config.set_enable_ech_grease(true);
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
        if offers_h2 {
            unsafe {
                ffi::SSL_set_alps_use_new_codepoint(config.as_ptr(), 0);
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
