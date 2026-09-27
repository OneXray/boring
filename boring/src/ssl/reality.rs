//! Opt-in REALITY, classic by default. Secrets stay in the native handshake.

use foreign_types::ForeignTypeRef;

use super::SslRef;
use crate::error::ErrorStack;
use crate::{cvt, ffi};

/// Immutable REALITY client parameters, reusable across connections.
///
/// This feature authenticates with the real X25519 share over TCP/TLS 1.3,
/// preserving the compatible shares from the selected ClientHello profile.
/// It does not provide browser profiles, name resolution, dialing or fallback.
/// Each fresh `Ssl` gets its own native, one-use authentication state.
#[derive(Clone)]
pub struct RealityClientConfig {
    server_public_key: [u8; 32],
    short_id: [u8; 8],
    client_version: [u8; 3],
    require_x25519mlkem768: bool,
}

impl RealityClientConfig {
    /// Creates parameters using the server's X25519 public key, a short ID of
    /// zero to eight bytes (right-padded with zeros), and a three-byte version.
    /// Low-order public keys are rejected during handshake before any hello is
    /// sent. The timestamp and ephemeral keys are generated per connection.
    pub fn new(
        server_public_key: [u8; 32],
        short_id: &[u8],
        client_version: [u8; 3],
    ) -> Result<Self, ErrorStack> {
        if short_id.len() > 8 {
            return Err(ErrorStack::internal_error_str(
                "REALITY short ID must contain at most eight bytes",
            ));
        }
        let mut padded = [0; 8];
        padded[..short_id.len()].copy_from_slice(short_id);
        Ok(Self {
            server_public_key,
            short_id: padded,
            client_version,
            require_x25519mlkem768: false,
        })
    }

    /// Requires an actual X25519MLKEM768 key share and negotiation.
    ///
    /// Classic X25519 remains the default. Configure a compatible group/share
    /// list (for example Chrome133) before setting this config on a fresh SSL.
    /// Missing hybrid shares and a peer selecting a classic group fail closed;
    /// this does not silently replace the selected ClientHello profile.
    #[must_use]
    pub fn require_x25519mlkem768(mut self) -> Self {
        self.require_x25519mlkem768 = true;
        self
    }
}

impl SslRef {
    /// Enables REALITY on a fresh client connection exactly once.
    ///
    /// Configure supported groups and any profile before calling. Classic mode
    /// removes X25519MLKEM768 from groups/shares, preserves other classic shares
    /// and requires X25519 for authentication. Without explicit shares it selects
    /// X25519 alone. An explicitly required hybrid config instead requires
    /// X25519MLKEM768 in both the offered shares and the negotiated connection.
    /// With no explicit shares it selects that hybrid group alone. When a
    /// standalone X25519 share exists, it authenticates REALITY; otherwise its
    /// key is the hybrid share's X25519 component, matching Mihomo's preference.
    /// Configure SNI separately. Negotiating TLS < 1.3, HRR, actual ECH, QUIC,
    /// DTLS, server mode, resumption and early data are rejected. ECH GREASE is
    /// permitted. Invalid configurations may fail here or during handshake.
    ///
    /// REALITY certificate authentication is mandatory even with `VERIFY_NONE`
    /// or a custom trust callback. It never falls back to ordinary PKI, and
    /// native TLS CertificateVerify still proves possession of the peer key.
    pub fn set_reality_client(&mut self, config: &RealityClientConfig) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_set1_reality_client_ex(
                self.as_ptr(),
                config.server_public_key.as_ptr(),
                config.short_id.as_ptr(),
                config.short_id.len(),
                config.client_version.as_ptr(),
                i32::from(config.require_x25519mlkem768),
            ))
        }
    }
}
