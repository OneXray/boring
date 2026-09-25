# Selected-v1 CF3: Firefox120 and Safari16.0

2026-09-25, macOS ARM64; CF2 parent `bcf7c9f7`. **Library CF3 DONE**, not VCore
integration, independent proxy interoperability, target builds or publication.

Both profiles use the existing public `FingerprintConnector`. Literal wire
expectations come from official Mihomo v1.19.31 / uTLS v1.8.7, not from the
implementation's profile catalog. No host listening sockets are created.

## Implementation and boundaries

- Firefox: fixed extension/cipher/signature order, native X25519 and P-256
  shares, no GREASE/SCT/ALPS/compression, its own ECH GREASE shape. FFDHE groups,
  delegated credentials and record-size-limit are fixed template declarations,
  not new negotiation implementations. Selected unsupported groups and
  ServerHello responses to the template-only extensions explicitly fail.
- Safari: fixed order, GREASE, duplicated signature scheme, conditional padding
  and real bounded Zlib. The TLS1.2 floor is caller-owned and intentionally trims
  TLS1.0/1.1. No ECH/ALPS and no cold session-ticket extension. Real TLS1.2 tickets
  may still be offered under the separate caller-owned warm policy.
- Safari's 0xc008 is explicitly FAKE/unimplemented in the source uTLS catalog;
  native selection rejects it. The selectable 0xc012 ECDHE-RSA-3DES reuses
  existing native key-exchange/cipher primitives, with the existing deprecated
  3DES default-off treatment. No RC4 or new cipher primitive is added.
- Feature-gated patches apply only to build copies; pinned BoringSSL submodule
  `e2a57cfb4d915b4ba820585aef9fdee7bca13fe5` remains unmodified. Default native
  builds do not include these additions.
- Official crates.io sparse index was checked for the new dependency:
  `flate2 1.1.10`, latest non-yanked stable on the execution date, with only the
  Rust backend. Crate checksum:
  `6e634e2e0ebac1ee034020da1ca582e17ffe4e0f5e985823721e168928136dcb`.
  Existing boring 5.2.0 / brotli 9.0.0 remain stable baselines.

## Executed gates

- Two new independent wire tests, eight connections per template, cover complete
  ordered vectors, extension data, dual shares, GREASE correlation, padding,
  ECH shape, Zlib advertisement and the TLS version floor.
- Actual memory peers individually select all 14 Firefox TLS1.2 suites and all
  16 real Safari TLS1.2 suites, using RSA/ECDSA certificates as appropriate.
  Both profiles negotiate TLS1.3 with X25519, P-256, P-384 and P-521 and exchange
  request/response bytes. TLS1.0/1.1-only peers fail for both profiles.
- Firefox rejects record-size-limit/delegated-credential ServerHello responses
  and a selected unsupported FFDHE share; Safari rejects selected fake 0xc008.
  Fault injection is confined to bounded memory fixture IO, never production BIO.
- Safari's actual Zlib certificate succeeds; truncated, corrupt, trailing,
  wrong-algorithm payload, oversized decoder output and oversized declared
  certificate all fail. Both native message size and decoder output stay bounded
  to 128 KiB. A rejecting caller verifier also fails after successful decoding.
- Both Chrome profiles pass real Brotli and reject truncated, corrupt,
  wrong-algorithm payloads and oversized decoded output. Existing Chrome120/133,
  REALITY and HKDF regressions remain green: **38 Rust test functions** in the
  combined feature suite. This is not a network interoperability case count.
- Default/feature-off compile, fingerprint-only vectors and REALITY-only tests,
  focused Clippy, fmt and diff checks pass separately.

```sh
cargo test --locked -p boring --features client-fingerprint,reality --test client_fingerprint --test selected_fingerprint --test reality --test hkdf
cargo test --locked -p tokio-boring --features client-fingerprint,reality --test client_fingerprint --test selected_fingerprint
cargo check --locked -p boring -p tokio-boring --no-default-features
cargo test --locked -p boring --features client-fingerprint --test client_fingerprint --test selected_fingerprint
cargo test --locked -p boring --features reality --test reality
cargo clippy --locked -p boring -p tokio-boring --features client-fingerprint,reality --lib --test client_fingerprint --test selected_fingerprint -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Local ignored Cargo.lock SHA-256:
`ee6523543d51017e753350b6a119e986605a7a1c19fc2de74d73f42e9375880a`.
Profile patch SHA-256:
`5d91f9d8a5200df1d8581b5fbbf53ad2435a293d75d21fd6820fa6a3772864ff`.

These native library peers verify real cryptography and bytes, but do not replace
the later independent Mihomo/container, VCore public-config, REALITY, cache,
platform and device gates. VCore's pinned dependency and public parser are still
unchanged; only `chrome120` is exposed there at this stage.
