# Classic REALITY client (opt-in)

This branch adds an opt-in `reality` feature on the existing 5.2.0 fork baseline.
It is not by itself a production migration or a published release.
The BoringSSL submodule remains pinned; an opt-in build-time patch is shipped
alongside the fork's existing patches. No private memory-layout assumptions,
global RNG replacement, exported ephemeral private keys, or BIO wire rewriting.

## Interface and invariants

The Rust interface configures one fresh `Ssl` with an immutable server X25519
public key, 0–8 byte short ID and three-byte client version. Only a stream already
created by the caller is used; the library never resolves or dials a destination.

```rust,ignore
let reality = RealityClientConfig::new(server_public_key, &short_id, [1, 8, 0])?;
// Configure SNI and use either ordinary TLS settings or FingerprintConnector.
ssl.set_reality_client(&reality)?;
```

Enable `boring/reality` or `tokio-boring/reality`. These forward to the same
`boring-sys/reality` feature; all are disabled by default. The version above is
an example of caller-provided wire data, not a built-in package version.

Inside the TLS handshake, the same X25519 key share derives the REALITY auth key.
The fully encoded ClientHello with its 32-byte session ID cleared is the AAD.
The sealed session ID is installed in both handshake state and outgoing bytes
before the transcript or outgoing flight takes ownership.

REALITY authentication replaces PKI/custom certificate trust, never TLS proof of
key possession: exactly one bounded Ed25519 temporary certificate must have the
correct HMAC-SHA512 signature. Its CertificateVerify must pass native Ed25519
verification. This narrow authenticated exception does not add Ed25519 to the
browser's wire signature list or relax ordinary TLS signature policy.

The implementation is classic X25519 authentication over TCP/TLS 1.3 only. The wire may advertise
TLS 1.2 to match a browser, but negotiation below TLS 1.3 fails closed. Actual
ECH, QUIC, DTLS, HRR, resumption, early data, server mode and PQ shares are
rejected. ECH GREASE is distinct and remains usable. FIPS, RPK and external
precompiled/native-source combinations are outside this slice.

The opt-in [named ClientHello profile](client-fingerprint.md) can be combined
with this interface. Authentication still owns the same native key share and
final ClientHello bytes; the profile cannot bypass the REALITY verifier.

With the selected-v1 templates, classic mode removes X25519MLKEM768 from both
advertised groups and actual shares, matching Mihomo's default classic behavior.
It preserves other classic shares (including Firefox120's P-256) in order and
binds authentication to the actual X25519 object, even if it is not first. Without
explicit share configuration it selects X25519 alone. It creates no second
identity key or global secret mapping; ordinary Chrome133 TLS still uses ML-KEM.

Auth state is connection-local, one-use and cleansed on authentication, native
state-machine failure or handshake-state destruction. A transport I/O failure
may retain it until the owning SSL is dropped; callers must drop failed/cancelled
handshakes. Nonblocking retries must not reseal the ClientHello.
There is no ordinary-site fallback after an authentication failure.

## Validation surface

Use the same public `Ssl`/stream interface that callers use:

1. Memory-only capture: valid initial hello; low-order keys/configuration errors
   rejected; session ID and X25519 wire key share authenticate together; retry,
   cancellation and independent connections do not reuse authentication state.
2. Official latest Mihomo REALITY listener and native TLS origin, all in owned
   isolated containers: valid end-to-end request plus wrong key, wrong short ID,
   wrong SNI, ordinary certificate and unsupported handshake negative cases.
3. Unconfigured ordinary TLS regression and browser ClientHello comparison.
4. Target compile checks, with device/product integration reported separately.

All socket servers, including negative fixtures, must be containerized. Pure
memory tests create no host listener. Upstream network tests are not run on the
host merely because they are called unit tests.

## Historical initial-slice result — 2026-09-25

This **classic REALITY feasibility slice passes locally**, not the complete
fingerprint rollout. Branch: `feat/reality-client-hello`; fork base:
`02c0298a`. The unmodified BoringSSL submodule is
`e2a57cfb4d915b4ba820585aef9fdee7bca13fe5`. The new patch applies after the
fork's existing `boring-pq.patch`. Its SHA-256 is
`0b55587d5950d3c35991aa5e37fe294ffea023cc9c9fb8a8478683aa113a55ab`.

- Public-interface memory tests: **7/7**. Same wire X25519 share / final AAD,
  zero-padded short ID / timestamp, low-order keys, write/read retries, drop and
  independent connections, DTLS / changed groups / server / version rejection.
  Native TLS 1.3 memory handshakes also reject incorrect certificate HMAC,
  multiple certificates, certificates over 16 KiB, and forged CertificateVerify
  after a valid HMAC. A permissive verify callback cannot bypass these checks.
- Existing offline HKDF tests: **9/9**. No host listening sockets are created.
- Official latest Mihomo **v1.19.31**, Linux ARM64, isolated Apple Container:
  **16/16**, including real VLESS-to-HTTP responses and authentication negative
  cases. Seven Chrome120 samples agree on normalized static ClientHello shape.
  This is sampled shape agreement, not complete browser emulation.
- Ordinary TLS regression, feature compiled but connection unconfigured:
  **46/46**. Repeated without the feature: **46/46**. Both include five TLS
  negotiation contexts, pin/name/skip, mTLS and invalid handshake signatures.
- `cargo fmt`, focused Clippy with `-D warnings`, macOS ARM64 / x64, iOS ARM64
  and iOS ARM64 simulator library builds pass. Cross-build is not device or
  final-product linking evidence. `reality+rpk` and external native libraries
  reject at the intended build-time guard.
- All seven containers across the three runs were stopped/deleted; captured
  process ownership was joined. VCore and rustls source/dependencies unchanged.

Reproduce the fork-local checks after `git submodule update --init`:

```sh
cargo test -p boring --features reality --test reality --test hkdf
cargo clippy -p boring -p tokio-boring --features reality --lib -- -D warnings
cargo clippy -p boring --features reality --test reality -- -D warnings
cargo fmt --all -- --check
```

The separate experiment runner and result report live in the workspace's
`references/fingerprint-boring-reality-f2` and
`references/vcore-tls-boring-reality-f2-results.md`. They are research tooling,
not dependencies of this fork. The public memory tests are fully self-contained.

## Integration gates

Later standalone experiments have exercised Vision record-to-raw switching /
backpressure and ALPS responses, actual certificate compression, ordinary-TLS
HRR/resumption. They need not be repeated as prerequisites to implementation.
The named profile now also has a wire-authentication regression through the
public connector; the original seven REALITY memory cases remain unchanged.

VCore transport integration / ownership / Stop, portable pinned Git dependency
resolution, affected target builds, physical devices, size and licensing/release
review remain application/release gates. Earlier cross-builds are historical
evidence and do not cover every later code change.
Actual ECH, QUIC, PQ REALITY and resumption are deliberately unsupported here.
No VCore production dependency change, commit, push or release is implied.

The later [selected-v1 CF4 fork checks](client-fingerprint-cf4-fork.md) cover the
new four-template binding. The historical container/device counts above are not
reused as acceptance for that change.
