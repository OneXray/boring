//! Opt-in Restls authentication inside the native TLS transcript and record layer.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use foreign_types::ForeignTypeRef;

use super::{Ssl, SslRef};
use crate::error::ErrorStack;
use crate::{cvt, ffi};

/// Restls authentication format. This does not force the negotiated TLS version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RestlsVersionHint {
    /// Authenticate eager classic ECDHE public keys and an optional session ticket.
    Tls12 = 0x0303,
    /// Authenticate the exact wire key shares and PSK identities.
    Tls13 = 0x0304,
}

type HashFunction = dyn Fn(&[u8]) -> [u8; 32] + Send + Sync;

#[derive(Clone)]
struct RestlsHash(Arc<HashFunction>);

/// Immutable parameters for the minimal native Restls handshake hook.
///
/// The hash callback must compute keyed BLAKE3, using the 32-byte key obtained by
/// BLAKE3 derive-key with context `restls-traffic-key` and the password bytes.
/// It receives only bounded public wire bytes, never private TLS keys. Keeping
/// this primitive at the caller permits using the official Rust implementation
/// without introducing another native cryptographic implementation into boring.
/// The callback and captured key are connection-owned until the SSL is dropped;
/// callers are responsible for zeroizing their captured key on drop.
#[derive(Clone)]
pub struct RestlsClientConfig {
    hint: RestlsVersionHint,
    hash: RestlsHash,
}

impl RestlsClientConfig {
    /// Creates a configuration with the protocol's keyed BLAKE3 operation.
    /// A callback panic fails the handshake and never unwinds through native TLS.
    #[must_use]
    pub fn new<F>(hint: RestlsVersionHint, hash: F) -> Self
    where
        F: Fn(&[u8]) -> [u8; 32] + Send + Sync + 'static,
    {
        Self {
            hint,
            hash: RestlsHash(Arc::new(hash)),
        }
    }
}

unsafe extern "C" fn hash_wire(
    ssl: *mut ffi::SSL,
    bytes: *const u8,
    length: usize,
    output: *mut u8,
) -> libc::c_int {
    if ssl.is_null() || output.is_null() || length > 65_536 || (length != 0 && bytes.is_null()) {
        return 0;
    }
    // The native hook calls synchronously with a live SSL and a bounded span.
    // Empty C spans may use a null pointer; Rust slices must not.
    let result = catch_unwind(AssertUnwindSafe(|| {
        let ssl = unsafe { SslRef::from_ptr(ssl) };
        let hash = ssl.ex_data(Ssl::cached_ex_index::<RestlsHash>())?;
        let data = if length == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(bytes, length) }
        };
        Some((hash.0)(data))
    }));
    if let Ok(Some(digest)) = result {
        unsafe { std::ptr::copy_nonoverlapping(digest.as_ptr(), output, digest.len()) };
        1
    } else {
        0
    }
}

impl SslRef {
    /// Enables Restls on a fresh TCP client exactly once.
    ///
    /// Standard certificate policy, ServerKeyExchange, CertificateVerify and
    /// Finished remain native and unchanged. In addition, the first encrypted
    /// server record must authenticate the Restls key before the handshake can
    /// succeed. Ordinary cover TLS therefore fails closed instead of returning
    /// a usable unauthenticated tunnel. Early data, False Start, actual ECH,
    /// REALITY, ShadowTLS, JLS, QUIC, DTLS and server mode are incompatible.
    /// Named profiles and ECH GREASE remain independent of this authentication.
    pub fn set_restls_client(&mut self, config: &RestlsClientConfig) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_set_restls_client(
                self.as_ptr(),
                config.hint as u16,
                Some(hash_wire),
            ))?;
        }
        self.set_ex_data(Ssl::cached_ex_index::<RestlsHash>(), config.hash.clone());
        Ok(())
    }

    /// True only after Restls authentication and the complete native TLS handshake.
    #[must_use]
    pub fn restls_authenticated(&self) -> bool {
        unsafe { ffi::SSL_restls_authenticated(self.as_ptr()) == 1 }
    }
}
