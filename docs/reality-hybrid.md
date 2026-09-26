# Explicit hybrid REALITY — fork-local acceptance

2026-09-26. **Fork-local gate PASS; VCore N7/S03/D16 production acceptance is
not complete.** Work branch: `feat/reality-hybrid`; tested parent:
`67581195fd6388a8bfd42c4e39e945f73c99a2b2`. The user approved this narrowly scoped
owned-fork extension, not other TLS hooks, a new backend or publication.

## Implemented boundary

The [public contract](reality-client.md#explicit-required-hybrid-mode) adds
`RealityClientConfig::require_x25519mlkem768()` and an additive native C entry.
Existing callers remain classic by default. Explicit hybrid mode requires actual
group 4588 in both ClientHello and ServerHello, rejects downgrade/HRR, and
authenticates against the actual share's X25519 component when no standalone
X25519 share exists. With both shares, authentication uses standalone X25519,
as Mihomo does. TLS key exchange itself uses native ML-KEM + X25519.

No new dependency, provider, private-key export, BIO rewriting, global state or
ordinary-site success fallback. The native temporary-certificate HMAC and
CertificateVerify remain mandatory, even with a permissive user trust callback.
BoringSSL submodule `e2a57cfb4d915b4ba820585aef9fdee7bca13fe5` is unchanged;
the extension remains an opt-in build patch.

## Offline checks

Executed on macOS ARM64 with Rust 1.98.1. All peers below use in-memory streams;
none opens a host listening socket.

| Check | Result |
| --- | --- |
| boring, both features: REALITY + fingerprint + selected templates + HKDF | Debug 33/33, Release 33/33 |
| tokio-boring, both features: fingerprint + selected templates | 17/17 |
| boring, REALITY alone: REALITY + HKDF | 21/21 |
| boring, fingerprint alone: fingerprint + selected templates + HKDF | 15/15 |
| tokio-boring, fingerprint alone: fingerprint + selected templates | 16/16 |
| boring without either feature: HKDF | 9/9 |
| boring + tokio-boring, no default features | compile PASS |
| Focused library / changed test and example Clippy, `-D warnings` | PASS |
| Rustdoc generation, rustfmt, Ruff check/format, diff checks | PASS |
| Apple cross-checks: iOS ARM64, ARM64 simulator, x64 simulator, macOS x64 | PASS |
| Android cross-checks: ARM64 and x64 | PASS with explicit API target; see correction below |

The six new REALITY tests cover hybrid-only and Chrome133 dual-share
authentication, actual hybrid negotiation, classical selection/HRR rejection,
certificate HMAC/proof/chain/size failures, low-order keys, incompatible profiles,
late share changes, and 20 retry/cancel cycles with non-reused authentication.
Existing classic and ordinary TLS tests still pass. TDD initially exposed the
missing API, successful classic selection in required mode, and inability to
authenticate hybrid-only shares; each was fixed at its actual native boundary.

Commands from this fork root (separate invocations):

```sh
cargo test --locked -p boring --features reality,client-fingerprint --test reality --test client_fingerprint --test selected_fingerprint --test hkdf
cargo test --locked --release -p boring --features reality,client-fingerprint --test reality --test client_fingerprint --test selected_fingerprint --test hkdf
cargo test --locked -p tokio-boring --features reality,client-fingerprint --test client_fingerprint --test selected_fingerprint
cargo test --locked -p boring --features reality --test reality --test hkdf
cargo test --locked -p boring --features client-fingerprint --test client_fingerprint --test selected_fingerprint --test hkdf
cargo test --locked -p tokio-boring --features client-fingerprint --test client_fingerprint --test selected_fingerprint
cargo test --locked -p boring --test hkdf
cargo check --locked -p boring -p tokio-boring --no-default-features
cargo clippy --locked -p boring -p tokio-boring --features reality,client-fingerprint --lib -- -D warnings
cargo clippy --locked -p boring --features reality,client-fingerprint --test reality --example reality_hybrid -- -D warnings
cargo doc --locked -p boring --features reality,client-fingerprint --no-deps
cargo fmt --all -- --check
cargo check --locked -p boring -p tokio-boring --features reality,client-fingerprint --target aarch64-apple-ios --target aarch64-apple-ios-sim --target x86_64-apple-ios --target x86_64-apple-darwin
git diff --check
```

The [official current stable NDK](https://developer.android.com/ndk/downloads),
r30 `30.0.16248370`, was installed alongside existing SDKs. The first Android
check, using only `ANDROID_NDK_HOME`, failed during binding generation:
`Unversioned target triples are not supported!`. A minimal Clang invocation
including only `sys/cdefs.h` reproduced it for both targets. Adding API 24 to
`--target` alone made both header checks and the original Cargo check pass.
Selecting API-suffixed NDK compiler wrappers produced a second, distinct failure:
CMake's second configure lost the Android toolchain and passed macOS `-arch`
options to the Android compiler. This also reproduced in a fresh Cargo target
directory, ruling out a pre-existing stale cache. The NDK toolchain selects plain
`clang`/`clang++`, while the repeated explicit wrapper setting changes the compiler
again on the next configure. Keep these paths consistent with the NDK and let its
toolchain select the native target; set bindgen's API target separately. The old
outputs are preserved. No NDK, bindgen, BoringSSL or protocol source was patched
for either environment error. The final command below passed both ABIs in a
fresh directory, without compiler-discovery warnings. Reproduce with your
installed toolchain:

```sh
n7_ndk=/absolute/path/to/ndk/30.0.16248370
n7_compilers="$n7_ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
n7_build_dir=$(mktemp -d "$PWD/target/n7-android-XXXXXX")
env CARGO_TARGET_DIR="$n7_build_dir" ANDROID_NDK_HOME="$n7_ndk" \
  CC_aarch64_linux_android="$n7_compilers/clang" \
  CXX_aarch64_linux_android="$n7_compilers/clang++" \
  AR_aarch64_linux_android="$n7_compilers/llvm-ar" \
  CC_x86_64_linux_android="$n7_compilers/clang" \
  CXX_x86_64_linux_android="$n7_compilers/clang++" \
  AR_x86_64_linux_android="$n7_compilers/llvm-ar" \
  BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android=--target=aarch64-linux-android24 \
  BINDGEN_EXTRA_CLANG_ARGS_x86_64_linux_android=--target=x86_64-linux-android24 \
  cargo check --locked -p boring -p tokio-boring --features reality,client-fingerprint \
  --target aarch64-linux-android --target x86_64-linux-android
```

These are library compile checks, not product linking, device or Windows results.

## Isolated Mihomo interoperability

Final run: `n7-hybrid-fork-20260926-v3`, **13/13 PASS** with
`source_unchanged=true` and `cleanup=true`. Each positive case compares every
byte of 10 MiB uploaded and echoed; the origin independently records the exact
10 MiB count. Group observation is independent of the client's live SSL query.

| Cases | Actual result |
| --- | --- |
| Native hybrid-only × IPv4/IPv6 | `[(4588, 1216)]`, negotiated 4588, data PASS |
| Chrome133 dual-share × IPv4/IPv6 | `[(4588, 1216), (29, 32)]`, negotiated 4588, data PASS |
| Classic native / Chrome133 controls | `[(29, 32)]`, negotiated 29, data PASS |
| Peer selects classic / sends HRR | Explicit native failure, not timeout; no origin data |
| Wrong short ID / public key / SNI | Explicit native failure, not timeout; no origin data |
| Ordinary certificate / TLS 1.2 peer | Explicit native failure, not timeout; no origin data |

Apple Container CLI 1.4.1; two owned host-only containers (Mihomo, and
cover/origin/observer), guest MTU 1500, no published ports, no host servers.
Both containers and their owned processes were joined and removed. The peer is
OpenSSL 3.5.8, not a BoringSSL self-interoperability proof. Observers only record
share IDs/lengths, selected group and byte counts; fixture identities, private
configs and raw ClientHellos are not retained in reports.

Mihomo was downloaded anew through the official latest release downloader and
identified by the container binary's `-v`: **v1.19.31**, Linux ARM64, Go 1.26.8,
`with_gvisor`. No API query, local Mihomo compilation or old-cache fallback.
This version is an observed run identity, not a fixed downloader version.

| Input/artifact | SHA-256 / identity |
| --- | --- |
| Mihomo archive | `9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4` |
| Mihomo binary | `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3` |
| Container image | `sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01` |
| Fork Cargo.lock, unchanged | `ee6523543d51017e753350b6a119e986605a7a1c19fc2de74d73f42e9375880a` |
| Client probe binary | `98e75f0b0ae8263f5badd56180ca6ce0d0fcb4764c9b8c517a214507c3fa59a4` |
| Final results.json | `b6c586d8aeb99ba42aafe16680fae1b9f88b5e91d626ef3a5b4fe31d92370fc7` |

The preserved first run `n7-hybrid-fork-20260926-v1` **failed before any protocol
case**, with successful container cleanup. A subsecond isolated reproduction
showed Python's EC-NID setter rejects the name `X25519MLKEM768` even when its
OpenSSL is 3.5.8. The owned cover fixture now leaves the native hybrid-capable
default list intact; the test still requires actual group 4588 on the wire and
in the finished connection. No peer source or assertion was weakened. Run v2
then passed 13/13; after script formatting and build-message/API-comment updates,
the complete v3 run passed independently. The first failure is not reclassified.

## Reproduce the container gate

The host probe is client-only, not a VCore runtime or protected socket path.
The fork harness explicitly receives a VCore checkout for its existing isolated
lab and official downloader; it does not discover an implicit sibling directory.
The tested lab source baseline is `def0e19cb0945614397c884388a9ee561818a19a`.
Use a fresh direct child under that checkout's ignored `target/interop/runs`:

```sh
cargo build --locked -p boring --features reality,client-fingerprint --example reality_hybrid
n7_core=/absolute/path/to/VCore
uv run --project "$n7_core/scripts" --locked ruff check tests/interop
uv run --project "$n7_core/scripts" --locked ruff format --check tests/interop
uv run --project "$n7_core/scripts" --locked python tests/interop/reality_hybrid.py \
  --vcore-dir "$n7_core" --run-dir "$n7_core/target/interop/runs/n7-hybrid-fork-new-run"
```

Raw v1/v2/v3 results remain in the lab checkout's ignored
`target/interop/runs/<run-name>/results.json`. Do not commit downloaded binaries,
temporary identities or container caches.

## Tested-source binding and remaining gates

The final run froze the following inputs before/after execution. Documentation
is evidence metadata; committing after the tests does not mean a future SHA was
already tested. Commit these exact inputs and compare their hashes.

| Source | SHA-256 |
| --- | --- |
| `boring-sys/patches/reality-client.patch` | `308b0fabbf8651656d4e853e0f789746b4125033dd9bb398903f6bae31ade4da` |
| `boring-sys/build/main.rs` | `f87f1ff35f1b19aea96183f2eeb2cb8f8b6b84d7654aee006ebdfc73083f8ed2` |
| `boring/src/ssl/reality.rs` | `ea86bb18e375d737f1eb1070c6c1a231d73c4a3b52f1ee9a83cdf0dadfcaf043` |
| `boring/src/ssl/fingerprint.rs` | `510f8b9d9cec12b55431eb839b3576fa5bcaa011158a17ba1eebc24be543c91d` |
| `boring/examples/reality_hybrid.rs` | `4b274344f13253f5ee0a9804ec87507d2d90e368a0d06e6af31777666402bee5` |
| `boring/tests/reality.rs` | `439cbc93a27e1f28fb20d759ec5f8b7f94122ca8111c9ce8a78498093895f6c6` |
| `tests/interop/reality_hybrid.py` | `d958683ff41f10d9de9047029c8be1a9f32d01bb7cc170be19e88c499be71f09` |
| `tests/interop/reality_hybrid_peer.py` | `5f42d74b64a32f3fb19d32862d792b14dd1b0961757d6b57e165220978946b4c` |

VCore still pins `67581195`: no production schema, Cargo dependency or public
capability changed here. Publication of this fork branch needs separate user
authorization, followed by immutable Git revision integration and portable
resolution. Then validate VCore's controlled IO, main/download legs, profile
selection, authentication, cancellation/Stop and affected N4/N5 data paths.
Other N7 security packages, N7 final acceptance, physical devices, Windows,
remote CI and release/license delivery review remain independent.
