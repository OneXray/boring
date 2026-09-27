# Selected-v1 CF4: fork-local classic REALITY slice

2026-09-25, macOS ARM64; parent `39b00c49`. **Fork-local checks pass; CF4 as a
whole is IN PROGRESS.** This is not publication, VCore public-name integration,
independent VLESS data-path acceptance, target builds or a release result.

## Change

Classic mode removes X25519MLKEM768 from advertised groups and actual key-share
selection, as in Mihomo's `BuildRemovedX25519MLKEM768HandshakeState`. It preserves
the order of remaining classic shares, notably Firefox120's X25519 + P-256.
Authentication locates the real X25519 object by group ID; it does not assume
index zero, force every template to one share, or generate a separate identity
key. Group preference flags are preserved across the bounded filtering step.
No named-profile feature dependency is introduced into the REALITY-only build.

Final ClientHello encoding remains both the TLS transcript and REALITY AAD.
One-use sealing, secret cleanup, temporary Ed25519 HMAC authentication and native
CertificateVerify remain in their original boundaries. Additional classic shares
do not enable PQ REALITY, HRR, early data, resumption, ordinary-certificate trust
or site fallback. No third-party submodule source is changed.

## Executed local checks

- All four named templates authenticate from the observed X25519 public share
  and final wire AAD, across four fresh connections each. Partial writes and
  repeated nonblocking reads preserve a single sealed identity; repeated setter
  use fails. An independent P-256-first/X25519-second fixture verifies nonzero
  index binding.
- Full independent-literal wire vectors run for the new three templates in
  ordinary and classic REALITY modes. Chrome133 only loses ML-KEM group/share;
  ordinary TLS retains both real shares. Firefox/Safari keep their fixed shape.
  Original Chrome120 full wire and named REALITY regressions remain green.
- Four profiles each complete a temporary-certificate memory handshake and
  reject wrong HMAC, forged CertificateVerify, extra/oversized certificates and
  low-order static keys. The native test server obeys advertised signature
  schemes, so this **crypto-only memory fixture adds Ed25519 to its offer**.
  Separate wire tests do not add it. Only later independent Mihomo acceptance
  can prove real-server authentication with each unmodified browser offer.
- Four profiles reject TLS1.2 negotiation and native P-384 HRR even with a
  permissive trust callback. Reintroducing a PQ share or enabling early data
  after configuration fails before any ClientHello bytes. Missing X25519,
  changed groups, repeated configuration and DTLS/server mode still fail closed.
- **43 Rust test functions** in the combined suite pass, including ordinary
  TLS ML-KEM, real ticket resumption/rejection, classic ciphers, Zlib/Brotli,
  ALPS and original HKDF tests. No host listening sockets are used.
- REALITY-only: 9 tests; fingerprint-only: 6 wire tests; default/feature-off
  compile; focused Clippy with `-D warnings`, fmt and diff checks are separate.

```sh
cargo test --locked -p boring --features client-fingerprint,reality --test client_fingerprint --test selected_fingerprint --test reality --test hkdf
cargo test --locked -p tokio-boring --features client-fingerprint,reality --test client_fingerprint --test selected_fingerprint
cargo check --locked -p boring -p tokio-boring --no-default-features
cargo test --locked -p boring --features reality --test reality
cargo test --locked -p boring --features client-fingerprint --test client_fingerprint --test selected_fingerprint
cargo clippy --locked -p boring -p tokio-boring --features client-fingerprint,reality --lib --test client_fingerprint --test selected_fingerprint --test reality -- -D warnings
cargo fmt --all -- --check
git diff --check
```

REALITY patch SHA-256:
`a28e55298c3aa2efcc4bc66f3fb64e05583333811284d8c9abafe744d1370e30`.
Native submodule still `e2a57cfb4d915b4ba820585aef9fdee7bca13fe5`.
No further dependency changes since CF3.

## Required next gates

Publish an authorized immutable fork revision, then update VCore's Git dependency
and lockfile together. Implement the seven public values, schema revision and
download-leg rules; execute fresh isolated Mihomo public-config/VLESS business
acceptance and authentication negatives. Cache, resource/lifecycle, portable
dependency resolution and platform builds remain application gates. This local
slice cannot sign off CF4 or CF5.
