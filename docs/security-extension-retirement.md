# JLS and Restls retirement

2026-09-26. On `chore/remove-jls-restls`, parent
`d8d6d92912a5e6bd1c43f4c8e1c78fd4a2d74544`, remove both owned extensions at the
user's request. The Rust APIs, Cargo features, native patches, build integration,
examples and dedicated tests/interop probes are gone. There is no compatibility
shim or disabled copy of their production implementation. Git history remains.

The retained production code, tests and probes are byte-identical to the
ShadowTLS baseline `de7bf4943ff9cd4b40e6f1d3ee98939284aa63b1`. REALITY, hybrid
REALITY, ShadowTLS v3, selected ClientHello profiles and public ML-KEM remain.
The BoringSSL submodule stays at `e2a57cfb4d915b4ba820585aef9fdee7bca13fe5`
with a clean checkout. Previous evidence is archived under `docs/history/`;
its old commands and support claims are not current instructions.

## Executed local regression

macOS ARM64, 2026-09-26. All test peers below use memory IO, not host listeners.

- Boring Debug and Release: 27/27 each (`shadow_tls`, `reality`,
  `selected_fingerprint`, `client_fingerprint`).
- Tokio Debug: 19/19 (`shadow_tls`, `selected_fingerprint`, `client_fingerprint`).
- Tokio Release: 3/3 (`shadow_tls`).
- Default boring/Tokio library check, selected-library/test Clippy with
  `-D warnings`, rustfmt and diff checks pass.
- Cargo metadata contains neither retired feature in any of the three crates.

The initial `--locked` invocation correctly required refreshing the local
ignored lockfile after removing the Restls-only BLAKE3 dev-dependency. One
offline resolution pruned it without upgrading other dependencies; subsequent
commands use `--locked`. The resulting lockfile SHA-256 is
`ee6523543d51017e753350b6a119e986605a7a1c19fc2de74d73f42e9375880a`, identical
to the retained baseline. This ignored file is not a committed release lockfile.

This record is not new container interoperability, cross-platform, physical
device, remote CI or VCore integration evidence. VCore's new immutable pin and
its own consumer regression are recorded separately in VCore.
