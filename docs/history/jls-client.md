# JLS native client authentication

> Retired on 2026-09-26. JLS support, public APIs, native patches, features and
> probes have been removed. The following is historical evidence for the old
> revision, not a current contract or runnable test guide.

2026-09-26. Owned branch `feat/n7-security-handshakes`, parent
`de7bf4943ff9cd4b40e6f1d3ee98939284aa63b1`. The user approved a minimal native
JLS extension and local validation. **This new hook is not published or used
by VCore.** Publication of the preceding ShadowTLS commit does not authorize
publishing subsequent changes. This is a fork capability gate, not N7.4 acceptance.

## Contract and implementation

The opt-in `jls` feature exposes
`SslRef::set_jls_client(username: &[u8], password: &[u8])`. Each nonempty credential
is limited to 65,535 bytes and copied into connection-owned native memory.
The build patch layers on the existing REALITY/ShadowTLS baseline so all three
setters enforce mutual exclusion in either order. It does not modify the checked-out
BoringSSL submodule, add a dependency, or change the lockfile.

JLS authenticates the exact encoded ClientHello and ServerHello with their random
field zeroed. Native SHA-256 derives the AES-256-GCM key from password plus hello
and the 32-byte nonce from username plus hello. Native variable-nonce GCM seals
a fresh 16-byte seed and tag into the 32-byte ClientHello random. The actual native
random and encoded message change together before transcript commitment; a
nonblocking retry cannot reseal it. Reserved random suffixes are excluded with a
bounded retry count. The ServerHello is authenticated before transcript/record-key
progress and consumes the copied credentials. Error and destruction paths also
cleanse them; temporary derived secrets are native, scoped and cleansed.

Only a fresh TCP client with a TLS-1.3-capable profile is accepted. A profile may
advertise TLS 1.2, but negotiation of it fails closed. HRR, actual ECH, QUIC, DTLS,
server mode, REALITY, ShadowTLS, sessions, PSK and early data are rejected. ECH
GREASE is not actual ECH. Configuration is checked both by the setter and at
handshake start to catch later incompatible changes.

JLS hello authentication replaces WebPKI identity, **not** TLS authentication of
the handshake. A native X.509 certificate/public key must exist, and native
CertificateVerify and Finished remain mandatory. Neither VERIFY_NONE nor a
custom certificate callback can bypass the JLS check. This matches the stricter
Mihomo named-uTLS path. It does not copy the ordinary `jls-tls` branch's differing
CertificateVerify behavior, send a fallback HTTP probe, or permit ordinary TLS
success after JLS authentication fails. There is no additional TLS engine, mutable
message callback, external BIO hello rewrite, private-key export or traffic-secret
export. The caller still owns its IO, deadline and cancellation.

Protocol references, inspected rather than linked as dependencies:

- [Mihomo JLS uTLS adapter](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/jls/utls.go)
- [Mihomo JLS selection](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/jls/jls.go)
- [Meow JLS source](https://github.com/meow-rs/meow-rs/tree/53933f070ccaec6aeec5de159ebf6f0802d8c7ce/crates/meow-transport/src/jls)

## Memory and regression gates

The first hook test reached the deliberate unimplemented-interface RED; the native
implementation makes it pass. One initial patch used zero-context hunks, which the
existing build's `git apply` correctly refused. The owned patch was regenerated
with normal context rather than weakening patch application. A subsequent ordinary
TLS 1.2 control lacked P-256 in its groups list for the P-256 ECDSA fixture
certificate; fixing that test list restored the independent native control. These
were test/build-fixture failures, not reasons to weaken authentication.

Three new boring test functions cover exact native hello authentication, wrong
credentials/tampering, fresh randomness, copied credential ownership, bounds,
duplicate/late/incompatible setup, all four profiles, and retry stability.
Two new Tokio tests cover mandatory JLS authentication against ordinary TLS 1.2,
TLS 1.3 and actual HRR even with permissive PKI callbacks, plus twenty cancelled
handshakes that release bounded memory IO and use fresh randoms. No test here opens
a listening socket.

Debug and Release boring regression sets pass 30 test functions each: JLS 3,
ShadowTLS 3, REALITY 17 and named-profile 7. Tokio Debug passes 18 JLS/profile tests
plus 3 explicit ShadowTLS tests; Tokio Release passes JLS 2 plus ShadowTLS 3.
The first Tokio selection did not activate its own `shadow-tls-v3` wrapper feature
and ran zero ShadowTLS tests; the explicit reruns correct that coverage gap rather
than counting zero tests as a pass. Targeted Clippy with `-D warnings` and formatting
pass. Hook-only 2 tests, default hash 13 tests, default boring/Tokio build, Rustdoc
with `-D warnings` and Python Ruff checks pass. Final logs are in
`target/n7-jls-gates/`; the combined Tokio rerun passes Debug 21 and Release 5.

Apple four cross-target library checks (ARM64 iOS device and simulator, x64 iOS
simulator and x64 macOS) and Android ARM64/x64 library checks pass with
`jls,shadow-tls-v3,client-fingerprint`. Native macOS ARM64 is covered above. Android
uses the explicit API-24 bindgen arguments and plain NDK clang paths recorded in
[the hybrid gate](../reality-hybrid.md). These are not VCore production linking,
Windows or physical-device results.

## Independent official server gate

`n7-jls-hook-v1`: **17/17 PASS**, `source_unchanged=true`, `cleanup=true`.
The official latest Mihomo v1.19.31 / Go 1.26.8 runs in one host-only Apple Container;
the independent origin and OpenSSL 3.5.8 controls run in another. Guest MTU 1500,
no published ports or host listeners. The harness accepts an explicit `--vcore-dir`
lab location and does not infer a sibling checkout or link production code to it.

Native plus Chrome120, Chrome133, Firefox120 and Safari16, each over IPv4 and IPv6,
give ten positive cases. Each requires TLS 1.3, one native CertificateVerify and
Finished, a server-first greeting, and both directions of 10 MiB byte-for-byte with
independent origin counts. Wrong username/password, modified ServerHello random,
modified encrypted handshake flight and three ordinary-TLS controls explicitly
reject before opening the business origin. Timeouts never count as authentication
rejection; the two corruption cases require proof the fault was actually injected.

`boring/examples/jls.rs` is only a bounded blocking client probe. Its read-only native
message callback counts handshake types; it does not change their bytes. Its
negative-only IO faults alter one bounded record on input, not the ClientHello or
TLS engine. Credentials arrive on stdin, not argv/logs. VLESS framing in the probe
uses synthetic credentials; the independent official listener is the decoder.

| Artifact | SHA-256 |
| --- | --- |
| `results.json` | `7c8ed8dc0a2c5311c4302bb235c64739601ddb1cfef7a5fd78ecafefabf3d23a` |
| Native JLS patch | `204879d971b95a30534cea9a3a2b723238857f24884236ab3139da9307761914` |
| Probe executable | `085ef86f299b3fef0ad2482004bf6526132fdd97d0f94a93d04f4de8443f727a` |
| Unchanged fork lockfile | `ee6523543d51017e753350b6a119e986605a7a1c19fc2de74d73f42e9375880a` |
| Mihomo executable | `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3` |
| Mihomo archive | `9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4` |
| Container image | `9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01` |

The report binds 18 fork input files, the probe, and lab CODE_PATHS digest
`f9135c707340340504304b6eea88ffd522e9379a29de15593a8d4875bec1cff8` at lab parent
`faa37235ad53b24002a2f1223c2167d2550f3fa2`. The lab was testing its separately
published ShadowTLS dependency; it did not compile this JLS hook into VCore.
Both peers and their owned log processes were removed. Raw reports remain in the
selected lab's ignored `target/interop/runs/n7-jls-hook-v1/` directory.

```sh
cargo build --locked -p boring --features jls,client-fingerprint --example jls
cargo test --locked -p boring --features jls,shadow-tls-v3,client-fingerprint --test jls --test shadow_tls --test reality --test selected_fingerprint --test client_fingerprint
cargo test --locked -p tokio-boring --features jls,shadow-tls-v3,client-fingerprint --test jls --test shadow_tls --test selected_fingerprint --test client_fingerprint
# Release gates: all selected boring tests and Tokio jls/shadow_tls.
n7_core=/absolute/path/to/VCore
uv run --project "$n7_core/scripts" --locked python tests/interop/jls.py \
  --vcore-dir "$n7_core" --run-dir "$n7_core/target/interop/runs/n7-jls-hook-fresh"
```

Remaining: authorized publication, immutable VCore
dependency integration and its controlled async adapter, public main/download
configuration, runtime DNS/proxy graph/Stop gates and N7 combinations. Success
here does not sign off Restls, VCore JLS, N7.4 or complete N7.
