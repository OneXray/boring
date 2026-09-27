# Restls retirement; JLS retained

2026-09-26. The final user decision is to remove **only Restls**. The earlier
`60ae6765` cleanup removed both protocols; this follow-up restores JLS without
rewriting published history. Restls Rust APIs, Cargo features, native patches,
build integration, examples and dedicated tests/interop probes remain removed.

The retained production code, tests and probes match the JLS baseline
`a859a66311c82a2f2bf2d0bc392e1475c8615b66`. JLS, REALITY, hybrid REALITY,
ShadowTLS v3, selected ClientHello profiles and public ML-KEM remain available.
The BoringSSL submodule stays at `e2a57cfb4d915b4ba820585aef9fdee7bca13fe5`
with a clean checkout. Only Restls evidence is archived under `docs/history/`;
its old commands and support claims are not current instructions.

## Executed final local regression

macOS ARM64, 2026-09-26. All test peers below use memory IO, not host listeners.

- Boring Debug and Release: 30/30 each (`jls`, `shadow_tls`, `reality`,
  `selected_fingerprint`, `client_fingerprint`).
- Tokio Debug: 21/21 (`jls`, `shadow_tls`, `selected_fingerprint`,
  `client_fingerprint`).
- Tokio Release: 5/5 (`jls`, `shadow_tls`).
- Selected-library/test Clippy with `-D warnings`, rustfmt and diff checks pass.
- Default boring/Tokio library check passed during the initial removal; the
  restored JLS code is opt-in. Cargo metadata retains JLS and omits Restls.

The initial `--locked` invocation correctly required refreshing the local
ignored lockfile after removing the Restls-only BLAKE3 dev-dependency. One
offline resolution pruned it without upgrading other dependencies; subsequent
commands use `--locked`. The resulting lockfile SHA-256 is
`ee6523543d51017e753350b6a119e986605a7a1c19fc2de74d73f42e9375880a`, identical
to the retained baseline. This ignored file is not a committed release lockfile.

This record is not new container interoperability, cross-platform, physical
device, remote CI or VCore integration evidence. VCore's new immutable pin and
its own consumer regression are recorded separately in VCore.
