# Selected-v1 CF2: Chrome133 ordinary TLS

2026-09-25, macOS ARM64; CF1 parent `11e6aba5`. **Library CF2 DONE**, not VCore
integration or an independent proxy interoperability result. No publish/push.

`ClientFingerprint::Chrome133` is a separate fixed profile. Its native shares
are X25519MLKEM768 (0x11ec, 1216-byte client share) and X25519, in that order.
It uses new ALPS codepoint 17613; Chrome120 retains 17513 and a classic share.
Chrome133 does not emit the legacy padding extension. Neither profile enables
actual ECH or changes caller-owned authentication, ALPN or resumption policy.

## Executed gates

- `boring --test selected_fingerprint chrome`: **1 test**, 16 independent
  ClientHello samples, two SNI lengths. Literal expectations from official
  Mihomo v1.19.31 / uTLS v1.8.7, not the implementation's template table.
  Ordered ciphers/signatures/groups/shares, GREASE positions and correlation,
  allowed shuffled set, SNI, ALPN/ALPS, versions, compression, ECH shape, no padding.
- `tokio-boring --test selected_fingerprint chrome`: **5 tests**, bounded pure
  memory peers. Native TLS1.3 really selects ML-KEM and X25519 independently;
  P-256 requires and reports HRR. TLS1.2 also completes request/response bytes.
  Both endpoints assert the selected group, not just a successful handshake.
- New ALPS absent/empty/nonempty results are distinct; an old-codepoint server
  does not negotiate new ALPS. Applications still own nonempty ALPS policy.
- Real ticket callback, actual resumption, and fresh server ticket keys rejecting
  a prior ticket before a successful new full handshake are separately asserted.
- A rejected certificate, forged native CertificateVerify signature and malformed
  ServerHello share length all fail. Fault injection exists only in memory test
  IO; production BIO and handshake bytes are never rewritten after encoding.
- Chrome120 3 tests, existing REALITY 8, HKDF 9 and Tokio baseline 3 pass again:
  **29 total Rust test functions** across both crates. Focused Clippy, fmt and
  diff checks pass. Test counts are not claimed as network case counts.

```sh
cargo test --locked -p boring --features client-fingerprint,reality --test client_fingerprint --test selected_fingerprint --test reality --test hkdf
cargo test --locked -p tokio-boring --features client-fingerprint,reality --test client_fingerprint --test selected_fingerprint
cargo clippy --locked -p boring -p tokio-boring --features client-fingerprint,reality --lib --test client_fingerprint --test selected_fingerprint -- -D warnings
cargo fmt --all -- --check
git diff --check
```

All peers here use real native TLS on in-memory streams, never host listening
sockets. Independent wire references and library crypto tests are separate
evidence: no fresh OpenSSL/Mihomo network or device pass is inferred. VCore still
pins its previous revision and only exposes `chrome120`; six-name data paths,
classic REALITY template changes and platform delivery remain later gates.
