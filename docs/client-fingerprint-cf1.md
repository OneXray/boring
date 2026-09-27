# Selected-v1 CF1: shared profile catalog and Chrome120 regression

2026-09-25, macOS ARM64. Base `b953b21e689bd2b6c9acb5af2f9cdaa053ce0284`;
branch `feat/client-fingerprint-selected`. This is a **fork-library** gate, not
VCore dependency integration, new-profile interoperability or release approval.

The only public profile remains Chrome120. The internal catalog separates
ciphers/signatures, supported groups, exact native key-share selection, extension
permutation, ECH GREASE, ALPS codepoint and certificate decompression. A bounded
native profile selector is the encoding seam for the later fixed-order templates;
their actual encoders and public IDs are not enabled in CF1. The existing
`FingerprintConnector` remains the sole Rust interface, with caller-owned trust,
ALPN, version restrictions and sessions.

Native changes are feature-gated and apply to a build-directory copy. The pinned
BoringSSL submodule remains `e2a57cfb4d915b4ba820585aef9fdee7bca13fe5`, unmodified.
The patch fixes Chrome's TLS1.3 order and ECH GREASE AEAD independent of host AES
acceleration; it does not change unconfigured connections or relax verification.
No sockets, caches, tasks, second key map or post-encoding rewrite were added.

Freshness: official crates.io sparse index on 2026-09-25 still lists **boring
5.2.0** and **brotli 9.0.0** as latest non-yanked stable versions. No dependency
upgrade or new package was needed. Local ignored Cargo.lock SHA-256:
`b9ba6f6711de5c2d564d5f967872b7f9a9ad90bedb48970fc2c3a96290ddc09d`.
Profile patch SHA-256:
`48f59701858e11429209c9a092d7056070765f2f067f7145178da687cc9c92cc`.

## Acceptance

- Public connector: 3 tests, including multiple complete ordered wire vectors
  against official Mihomo v1.19.31 / uTLS v1.8.7 literals, transport ALPN/ALPS,
  actual X25519 share/GREASE relationship, ECH and padding bounds, DTLS rejection.
- Existing REALITY: 8 tests, including wire-derived authentication, final AAD,
  repeated IO/drop/independent connections and failed key/certificate/proof paths.
- HKDF: 9 existing tests, independent RFC literals and size/error boundaries.
- Tokio memory peers: 3 tests (4 TLS1.2/1.3 request-response handshakes through
  reused connectors; absent/empty/nonempty ALPS; authentic Brotli decoding and
  accepting/rejecting caller certificate policy). No host listening sockets.
- Default/feature-off compile, fingerprint-only tests, REALITY-only tests, focused
  Clippy, formatting and diff checks are separate from the combined-feature run.

```sh
cargo test --locked -p boring --features client-fingerprint,reality --test client_fingerprint --test reality --test hkdf
cargo test --locked -p tokio-boring --features client-fingerprint,reality --test client_fingerprint
cargo check --locked -p boring -p tokio-boring --no-default-features
cargo test --locked -p boring --features client-fingerprint --test client_fingerprint
cargo test --locked -p boring --features reality --test reality
cargo clippy --locked -p boring -p tokio-boring --features client-fingerprint,reality --lib --test client_fingerprint -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Pure memory peers verify real native negotiation and bytes, not independent
network interoperability. No new container, cross-target or physical-device pass
is claimed here. CPU independence is implemented in the encoding path; the
Rust integration tests ran only on the stated host CPU, not an emulated no-AES
target. CF2/CF3 add other templates; CF4 handles their classic REALITY integration
and approved publication; CF5 performs application/platform gates.
