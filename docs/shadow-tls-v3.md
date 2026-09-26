# ShadowTLS v3 ClientHello hook

2026-09-26. Independent owned-fork branch `feat/n7-security-handshakes`,
base `b7639ab7`. The user approved minimal per-protocol native extensions and
local tests, not publication or a new TLS engine. **The isolated fork capability
gate passes; not published or integrated into VCore.** VCore continues to use
the previously published revision. This is not N7.4 or full ShadowTLS acceptance.

The opt-in `shadow-tls-v3` feature exposes
`SslRef::set_shadow_tls_v3_client(password: &[u8])`. It copies a nonempty,
at-most-65,535-byte password into connection-owned native state. The actual
encoded ClientHello gets a 32-byte session ID containing 28 random bytes and
the first four bytes of HMAC-SHA1 over the full handshake message with the MAC
slot zeroed. Native state and wire bytes change together **before** transcript
commitment. The password copy is cleansed after sealing or when its SSL owner
is destroyed; nonblocking retries never reseal. HRR retains the first ID.

This is only a ClientHello hook, not a ShadowTLS stream implementation or an
authentication-success signal. A caller must restore and authenticate the relay
records, require the native TLS handshake to succeed, then switch to authenticated
ShadowTLS application records. Certificate policy, signature checks and Finished
remain native and unchanged. No private keys, TLS traffic secrets, mutable
transcript callback, global RNG replacement or external BIO hello rewrite.

Fresh TCP client TLS 1.2/1.3 only. REALITY, actual ECH, sessions/early data,
DTLS, QUIC and server mode are rejected; named profiles and ECH GREASE are
separate. The feature builds on the fork's existing `reality` patch baseline
so both setters can enforce per-SSL mutual exclusion. Compiling either
capability does not enable its authentication mode on ordinary connections.
The BoringSSL submodule stays unchanged; the new opt-in patch is owned here.

## Development evidence and remaining gates

The first memory test failed to compile because the fixture used the OpenSSL
binding's `PKey::hmac` name instead of boring's existing `hash::hmac_sha1`.
After correcting the owned test, the intended RED was the unimplemented public
hook. The first native implementation then failed to compile because its nested
state used BoringSSL's custom deleter without a corresponding specialization;
connection-owned `std::optional` removes that unnecessary allocation.

An additional owned fixture initially called a nonexistent `Ssl::set_accept_state`;
it now uses the actual public `setup_accept` interface. No original failure is
rewritten as a pass.

Current native memory gates pass: exact hello authentication (six fresh hellos),
owned password copying, duplicate/late/mutually exclusive configuration, early
data changes before/after setup, TLS floor, server mode, TLS 1.2/1.3 completion
with all four profiles and native controls, actual P-384 HRR, certificate trust,
name and forged TLS handshake signature rejection. Twenty cancelled handshakes
release their caller-owned memory IO and never reuse an authentication session ID.
No certificate bypass is used by the new memory tests.

Debug: boring 27 tests (3 new + 24 profile/REALITY regressions), Tokio 19 tests
(3 new + 16 profile regressions). Release: the same boring 27 and new Tokio 3.
Targeted Clippy with `-D warnings` and formatting pass. These counts are test
functions, not the number of negotiated connections. All peers are memory IO.
Hook-only 3 tests and default-feature 13 hash tests also pass, as do the default
boring/Tokio build and Rustdoc with `-D warnings`. No new dependency or lockfile
change is needed.

Apple four cross-target library checks and Android ARM64/x64 library checks pass
with `shadow-tls-v3,client-fingerprint`; native macOS arm64 is exercised above.
Android uses the explicit API-24 bindgen arguments and plain NDK clang paths
recorded in [the hybrid gate](reality-hybrid.md). Logs are in
`target/n7-shadow-gates/apple.log` and `android.log`. These are not VCore production
linking, Windows or device results.

Required gates remain: publication authorization, immutable VCore dependency
integration, controlled async record adapter and VCore main/download integration.
No host listening servers, no third-party test suite that opens host sockets.

`boring/examples/shadow_tls_v3.rs` is a bounded blocking client-only capability
probe, not a production transport. Its small record adapter uses public native
HMAC/SHA primitives and requires a fully successful certificate-verified TLS
handshake before any VLESS business request. The server-side decoder will be the
official latest Mihomo artifact; the cover/origin are container-only. The lab is
supplied explicitly with `--vcore-dir`, not discovered through a sibling path.
No result from this probe can establish VCore's runtime or Stop contract.

## Isolated official peer gate

`n7-shadow-hook-v3`: **25/25 PASS**, `source_unchanged=true`, `cleanup=true`.
The 20 regular positive cases cover native plus Chrome120, Chrome133, Firefox120
and Safari16, each with TLS 1.2/1.3 and IPv4/IPv6. Each completes native certificate
and handshake verification, reads a server-first greeting, then checks both
directions of 10 MiB byte-for-byte; the independent origin confirms the byte count.
A separate Chrome133/P-384 case proves actual HRR and the same data exchange.
Wrong password, untrusted cover, wrong verification name and a corrupt relay MAC
all fail explicitly before the business origin is connected. None uses timeout
as an authentication pass, disables TLS verification or accepts a failed handshake.

The two host-only Apple Container peers contain the official latest Mihomo
v1.19.31 / Go 1.26.8 and native OpenSSL 3.5.8 cover/origin respectively. Guest MTU
1500; no published ports or host servers. The decoder is Mihomo, not a custom
server. The test adapter restores the authenticated protocol record transform
before passing the actual TLS ciphertext to BoringSSL; it does not rewrite the
ClientHello or fake CertificateVerify/Finished. Both peer containers and their
owned log processes are removed at completion.

| Artifact | SHA-256 |
| --- | --- |
| `results.json` | `0dfe4330ad48effaf5b4227a83a46e766ed4b18c9bba7ae3cf5ffa598c2e5b6c` |
| Native hook patch | `0c89bcd209bf40ab9033c1cd7f4e12388c1d44a6684a7c874e772a1ee1fa8138` |
| Probe executable | `1249d584deb97bec2b3ab693e702f09be87abf742e639dbf5b411eb000c00cd6` |
| Unchanged fork lockfile | `ee6523543d51017e753350b6a119e986605a7a1c19fc2de74d73f42e9375880a` |
| Mihomo archive | `9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4` |
| Mihomo executable | `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3` |
| Container image | `9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01` |

Raw reports are in the explicitly supplied lab's ignored
`target/interop/runs/n7-shadow-hook-v{1,2,3}/`. The final report binds each owned
source file, the immutable probe, and the lab CODE_PATHS digest
`0d0b4b58dcadc140276bb2cfa8083b363e640951ab9d89405917f0ca9c57be10` at lab parent
`f83968e9595bcb8f8c0cb61695edc10b179134cc`. BoringSSL's submodule and the previous
REALITY/profile patches are unchanged. No future commit SHA is backfilled into
pre-commit evidence.

Preserved failures: v1 never reached protocol cases because the listener was not
ready; its fixture incorrectly supplied the v1/v2 password field instead of the
v3 users list required by the official server. v2 then completed the first native
TLS 1.3 and 10 MiB exchange but failed the report predicate: OpenSSL reports
`TLSv1.3`, while the client reports `TLS1.3`. v3 uses an explicit two-value label
mapping and reruns every case. Neither earlier report is changed to PASS; no
third-party code or authentication/data assertion was weakened.

```sh
cargo build --locked -p boring --features shadow-tls-v3,client-fingerprint --example shadow_tls_v3
cargo test --locked -p boring --features shadow-tls-v3,client-fingerprint --test shadow_tls --test reality --test selected_fingerprint --test client_fingerprint
cargo test --locked -p tokio-boring --features shadow-tls-v3,client-fingerprint --test shadow_tls --test selected_fingerprint --test client_fingerprint
# Repeat the boring tests and the new Tokio test with --release.
n7_core=/absolute/path/to/VCore
uv run --project "$n7_core/scripts" --locked python tests/interop/shadow_tls_v3.py \
  --vcore-dir "$n7_core" --run-dir "$n7_core/target/interop/runs/n7-shadow-hook-fresh"
```

This gate establishes the minimal hook's capability. The blocking synthetic probe
is not a production API and has no runtime DNS, protected Dialer, proxy-group,
asynchronous cancellation/Stop or download-leg implementation. Restls and JLS are
separate hooks/gates; no success here signs off those protocols or full N7.
