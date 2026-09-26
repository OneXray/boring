//! Connection-owned JLS hello authentication without a second TLS engine.

use super::SslRef;
use crate::error::ErrorStack;
use crate::{cvt, ffi};
use foreign_types::ForeignTypeRef;

impl SslRef {
    /// Enables JLS hello authentication on a fresh TLS client connection.
    ///
    /// Each nonempty credential, at most 65,535 bytes, is copied into native
    /// state. The native TLS engine authenticates the exact encoded hellos
    /// inside its transcript. JLS replaces PKI identity verification, but TLS
    /// CertificateVerify and Finished remain mandatory. No caller-supplied
    /// certificate callback or VERIFY_NONE option can bypass JLS authentication.
    ///
    /// Configure a fresh client SSL and a TLS-1.3-capable profile first. TLS 1.2
    /// is permitted in the advertised profile, never in the negotiated result.
    /// HRR, REALITY, ShadowTLS, actual ECH, QUIC, DTLS, server mode, sessions and
    /// early data are rejected. ECH GREASE is separate and allowed. No ordinary
    /// TLS fallback or probe request is sent after authentication fails.
    /// Credentials are erased after ServerHello verification or failure/drop.
    pub fn set_jls_client(&mut self, username: &[u8], password: &[u8]) -> Result<(), ErrorStack> {
        // The native setter copies both bounded credentials synchronously.
        unsafe {
            cvt(ffi::SSL_set1_jls_client(
                self.as_ptr(),
                username.as_ptr(),
                username.len(),
                password.as_ptr(),
                password.len(),
            ))
        }
    }
}
