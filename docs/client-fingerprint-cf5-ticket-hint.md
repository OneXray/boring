# CF5 follow-up: expose the TLS1.2 ticket lifetime hint

2026-09-25, macOS ARM64; parent `e81c6837`.

A downstream independent rustls memory peer advertised a two-second TLS1.2
ticket lifetime. Its ticket remained offerable after three seconds because the
native session timeout and server ticket hint are distinct. BoringSSL retains
the hint without applying it to the TLS1.2 session timeout; TLS1.3 already clamps
its native timeout. This is not an authentication bypass or a native source fix.

Expose the existing read-only `SSL_SESSION_get_ticket_lifetime_hint` through
`SslSessionRef::ticket_lifetime_hint`. Zero retains its unspecified-hint meaning.
External node caches may conservatively expire at the shorter nonzero lifetime.
No BoringSSL submodule, native patch, dependency or wire-template change.

The native TLS1.2 memory test verifies a real two-second ticket has a two-second
hint and a longer session timeout. Both selected-profile suites, original wire,
REALITY and HKDF gates pass: **44 tests** (previous 43 plus this regression).
Commands are the two combined test commands recorded in
[CF4](client-fingerprint-cf4-fork.md). This is a library/API result, not downstream
cache-expiry, container interoperability or platform acceptance.
