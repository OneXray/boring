# Named ClientHello profiles

Enable `boring/client-fingerprint` or `tokio-boring/client-fingerprint` on this
fork. The implemented fixed profiles are `ClientFingerprint::Chrome120` (classic
X25519), `Chrome133` (ordinary TLS with native X25519MLKEM768 and X25519 shares,
new ALPS and no padding), `Firefox120` (X25519/P-256 shares and fixed order) and
`Safari16` (Safari 16.0, fixed order and Zlib). They are not aliases following a
browser release automatically. Unknown profile names
must be rejected by applications; this library does not silently map them to a
different browser.

## Interface

`FingerprintConnector` finishes a caller-configured `SslConnectorBuilder` with
the selected profile. It owns no sockets, DNS, tasks or session cache. Trust,
client identity, permitted TLS versions and session callbacks stay with the
caller. Each `configure` call creates a fresh connection with transport-owned
ALPN:

```rust
use boring::ssl::{ClientFingerprint, FingerprintConnector, SslConnector, SslMethod};

let builder = SslConnector::builder(SslMethod::tls())?;
// Set custom trust, client identity, version restrictions or bounded session
// callbacks on the builder here, if the application needs them.
let connector = FingerprintConnector::new(builder, ClientFingerprint::Chrome120)?;
let configuration = connector.configure(b"\x02h2\x08http/1.1")?;
// Pass configuration and an already connected stream to tokio_boring::connect,
// or use configuration.connect for blocking IO. No additional dial occurs.
# Ok::<(), boring::error::ErrorStack>(())
```

ALPN uses the existing TLS length-prefixed format. An empty list sends neither
ALPN nor ALPS; offering HTTP/1.1 alone does not advertise h2 ALPS. Callers must not
change the returned configuration's ALPN or profile fields afterwards. SNI,
verification and opt-in REALITY use their normal connection-level interfaces.
Restricting TLS versions or ALPN intentionally changes the resulting wire shape.

The profile configures ciphers, supported groups, signature algorithms, GREASE,
extension permutation, SCT/OCSP, ECH GREASE and template-specific h2 ALPS. Certificate
compression uses real Brotli for Chrome and Zlib for Safari; Firefox does not
advertise it. This is not an advertised-only extension. The
native certificate-message allocation and decoder output are bounded to 128 KiB.
The profile does not disable certificate verification, weaken handshake signature
verification, enable early data or create a resumption policy.

`SslRef::peer_application_settings()` returns borrowed negotiated ALPS data:
`None` means absent, `Some(&[])` means negotiated with empty peer settings. TLS
only transports these bytes; the application remains responsible for interpreting
them and enforcing its required ALPN before using or caching the connection.

## REALITY

With both features enabled, use the same connector and set
`RealityClientConfig` on its fresh connection before the handshake. The profile
does not add Ed25519 to the Chrome120 signature list. The authenticated REALITY
exception and native CertificateVerify checks remain in the native handshake.
The full connection-local invariants and deliberately unsupported combinations
are documented in [REALITY](reality-client.md).

The [CF4 fork-local checks](client-fingerprint-cf4-fork.md) cover all four
profiles' classic REALITY shape and authentication binding. Classic mode removes
Chrome133's ML-KEM group/share and preserves Firefox's additional P-256 share.
Independent VCore/Mihomo data paths still require application integration and
fresh container acceptance; ordinary-TLS ML-KEM is not PQ REALITY.

## Scope and verification

This is TLS ClientHello shaping, not HTTP/2/browser runtime impersonation, actual
ECH, QUIC/H3 shaping, or a claim that all Mihomo client-fingerprint names work.
Default builds do not enable either new feature.

The feature now forwards to `boring-sys/client-fingerprint`, which applies a
small bundled-source patch. It exposes only an implemented native profile ID,
never arbitrary extension bytes. Stream-client configuration is checked before
IO; DTLS, QUIC, already-started or repeated native selection fails. FIPS, RPK and
external/precompiled BoringSSL are rejected at build time. Profiles share one
bounded internal catalog for cipher/signature lists, ordered groups and separate
key shares, permutation, ECH, ALPS codepoint and compression.

Firefox's FFDHE groups, delegated-credential and record-size-limit declarations
are template-only, as in the source uTLS template, not new RFC implementations.
Selection of an unavailable group or a ServerHello response to these extensions
fails closed. Safari's 0xc008 cipher is likewise template-only in uTLS and is
rejected if selected. Its real 0xc012 ECDHE-RSA-3DES suite reuses native primitives
and is deprecated/default-off outside explicit cipher configuration. No RC4 was
restored. Safari's repeated signature scheme is a wire encoding detail; real
signature verification preferences remain unique.

Applications must set their TLS version floor (VCore uses TLS1.2), which trims
Safari's reference TLS1.0/1.1 advertisement. Safari omits the cold session-ticket
extension. Actual caller-supplied TLS1.2 tickets can still use it; warm connections
are not claimed as identical to the reference cold template. Zlib rejects
truncation, corrupt checksums, trailing bytes and oversized output before passing
the certificate to the unchanged verifier.

TLS1.3 cipher order and Chrome ECH GREASE AEAD are fixed by the named template,
not CPU AES acceleration. Real native cipher filtering, key generation,
transcript and proof-of-key remain intact. No BIO rewriting or global state is
introduced; the unconfigured native path is unchanged.

Targeted checks create only memory streams, including real native TLS peers:

```sh
cargo test -p boring --features reality,client-fingerprint --test client_fingerprint --test selected_fingerprint --test reality --test hkdf
cargo test -p tokio-boring --features reality,client-fingerprint --test client_fingerprint --test selected_fingerprint
cargo clippy -p boring -p tokio-boring --features reality,client-fingerprint --lib -- -D warnings
cargo fmt --all -- --check
```

The earlier isolated Mihomo, ordinary-TLS, Vision and handshake experiments are
selection/integration evidence, not reasons to repeat general backend feasibility
work. The tests above exercise the new named interface. Application wiring,
portable pinned Git dependency resolution, device behavior and release review are
separate gates; passing these library tests does not complete those gates.

### Historical initial-interface result — 2026-09-25

On macOS ARM64, the current named interface passed one wire-profile test, eight
REALITY tests (including the named-profile authentication case), nine existing
HKDF tests and two Tokio memory-handshake tests: 20 total. The Tokio tests cover
absent/empty/nonempty peer ALPS and actual Brotli certificate decoding with both
accepting and rejecting caller verification callbacks. The wire-profile test also
passed with `client-fingerprint` alone, without compiling REALITY. Focused library
and profile-test Clippy with `-D warnings`, formatting and diff checks passed.

These checks did not create a network listener. No new container interoperability,
cross-target or device result is claimed for this interface change. At the time
of this validation the fork branch was local/unpublished; the initial VCore
dependency-resolution attempt was removed rather than leaving a sibling path
dependency or an unresolved lockfile. Publishing this branch makes its interfaces
available for a pinned Git dependency; VCore integration is validated separately.
