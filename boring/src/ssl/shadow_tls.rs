//! Narrow opt-in ClientHello authentication for a caller-owned ShadowTLS v3 adapter.

use super::SslRef;
use crate::error::ErrorStack;
use crate::{cvt, ffi};
use foreign_types::ForeignTypeRef;

impl SslRef {
    /// Configures ShadowTLS v3 session-ID authentication on a fresh client SSL.
    ///
    /// The password is copied into connection-owned native state. This only
    /// authenticates the actual ClientHello before its transcript is committed.
    /// The caller must also implement/verify the ShadowTLS relay record layer
    /// and require a complete authenticated TLS handshake before switching IO.
    /// It never weakens certificate, CertificateVerify or Finished validation.
    ///
    /// Requires a nonempty password of at most 65,535 bytes. REALITY, actual
    /// ECH, resumption, early data, DTLS, QUIC and server mode are incompatible.
    /// TLS 1.2/1.3, named profiles and ordinary certificate policy remain native.
    /// The native password copy is erased after the first hello is sealed;
    /// failed/cancelled SSL owners must be dropped. HRR preserves that first ID.
    pub fn set_shadow_tls_v3_client(&mut self, password: &[u8]) -> Result<(), ErrorStack> {
        // The C entry copies the slice synchronously into this SSL's state and
        // validates the phase. Neither Rust nor the caller retains a raw pointer.
        unsafe {
            cvt(ffi::SSL_set1_shadow_tls_v3_client(
                self.as_ptr(),
                password.as_ptr(),
                password.len(),
            ))
        }
    }
}
