# Restls native hook — fork-local acceptance

2026-09-26. Branch `feat/n7-restls-handshake`, based on published JLS revision
`a859a66311c82a2f2bf2d0bc392e1475c8615b66`. The **fork-local native hook gate passes**.
This is unpublished work, not VCore integration, N7.4 acceptance, or permission
to publish another revision.
The separate JLS publication approval does not authorize this branch's push.

## Boundary

The opt-in `restls` feature exposes `RestlsClientConfig`, `RestlsVersionHint`,
`SslRef::set_restls_client`, and `SslRef::restls_authenticated`. It adds an owned
build-time patch and included implementation file, without modifying the bundled
BoringSSL checkout. The caller supplies keyed BLAKE3 over bounded public wire
bytes. Private ECDHE keys, cipher state, certificate signatures, transcript and
Finished remain inside native BoringSSL; there is no second TLS engine or key
export interface. The callback is owned by the SSL and panic-contained at FFI.

The protocol hash is keyed BLAKE3, **not HMAC-BLAKE3**. Its key derives from the
password using the literal UTF-8 context `restls-traffic-key`. The probe's only
new dependency is the unmodified official Rust `blake3` 1.8.7 as a dev-dependency.
Version selection was checked against [the current package][BLAKE3] and the
registry on 2026-09-26. The production boring library adds no hash dependency.
The caller owns and must arrange zeroization of captured key material.

- TLS13-hint authenticates all encoded key shares, including GREASE and their
  group codes, then offered PSK identities. The session ID is set before the
  native transcript and binder construction; no BIO rewriting is used.
- TLS12-hint creates native X25519/P-256/P-384 key objects before ClientHello,
  authenticates their public keys into the 11/11/10 session-ID slots, and reuses
  the negotiated private key in ClientKeyExchange. A ticket adds a fourth slot.
  This hint selects an authentication format, not a forced TLS version.
- Only the first encrypted server record is probed with the derived mask.
  Candidate plaintext, native error queue, original ciphertext and sequence
  number are kept separate. A failed candidate retries the original record.
  TLS1.2 explicit-IV CBC reinitializes the cipher at each record; TLS1.0/1.1
  remain forbidden, avoiding implicit-IV rollback semantics.
- Restls authentication is required at final handshake completion. Legitimate
  ordinary cover TLS can complete its native verification but cannot return a
  usable tunnel. This is an intentional fail-closed boundary versus the Go
  client's ordinary-cover fallback; it matches the approved VCore plan.
- PKI policy, ServerKeyExchange, CertificateVerify and Finished are unchanged.
  REALITY, ShadowTLS, JLS, actual ECH, QUIC, DTLS, server role, early data and
  False Start are incompatible. ECH GREASE and named profiles remain separate.

The experimental blocking consumer in `boring/examples/restls.rs` retains SSL
after authentication, captures the real final client-flight record, and feeds
delayed cover records back to native TLS. It is not VCore's controlled async
record adapter. TLS1.2 ticket resumption and mTLS are independently tested; a
complete client script/async adapter still belongs to the VCore implementation.

## Local gates

- Public hook tests: exact hello/share input, all four named profiles, strict
  mutual exclusion and late server-role rejection, and an independent Go/Rust
  BLAKE3 vector agree.
- Bounded memory peers: TLS1.3 X25519 and P-384 HRR; TLS1.2 X25519/P-256/P-384
  with AES128-GCM, ChaCha20-Poly1305 and AES128-CBC; masked record success, plain
  cover rejection at the final authentication gate, and corrupted record
  rejection. TLS1.2 session-ID slots are checked against the actual native
  ClientKeyExchange public key. These are not independent Restls servers.
- Native TLS1.2 tickets: both peers complete the full and resumed handshakes;
  the actual wire ticket matches the fourth session-ID authentication slot.
  A malicious native signing callback proves bad TLS1.2 ServerKeyExchange and
  TLS1.3 CertificateVerify are rejected, even with a valid Restls mask. Altering
  the TLS1.2 ticket after key derivation produces a real encrypted Finished with
  an incorrect transcript and is rejected by native `DIGEST_CHECK_FAILED`.
- Callback unwind containment, early-data rejection before/after configuration,
  DTLS rejection and late lowering of the TLS floor are covered before IO.
- Selected Debug and Release: **40/40 each**, across Restls 10, existing
  REALITY/JLS/ShadowTLS 23 and named-profile 7. Hook-only: **9/9**.
- Tokio Debug: **22/22**; Release Restls/JLS/ShadowTLS: **6/6**. Restls cancellation
  separately covers 40 cycles in each profile, exact callback-owner drop counts,
  fresh hello authentication and EOF after the owned task joins.
- Apple library checks: ARM64 iOS, ARM64 simulator, x64 simulator and x64 macOS.
  Android library checks: ARM64/x64 with NDK r30 `30.0.16248370`, explicit API24
  bindgen targets and plain NDK compiler paths from [the hybrid gate](reality-hybrid.md).
  Native macOS ARM64 is covered by the executed tests. These are not device,
  Windows or VCore production-linking results.
- Library/probe Clippy with `-D warnings`, Rustdoc with `-D warnings`, rustfmt,
  Ruff and diff checks pass. Default-only hash tests: **13/13**; boring/Tokio
  builds without default features pass. Logs are in `target/n7-restls-gates/`.

The first Tokio selection omitted its own `jls` wrapper feature and ran zero JLS
tests. The explicit reruns above include it; zero tests receive no coverage credit.
A default-hash command initially named a nonexistent integration target. The
correct command is `cargo test --locked -p boring --lib hash::tests`; the failed
invocation is retained, not treated as a protocol or compilation failure.

Development failures retained as context: initial patch lacked trailing context;
one C++ mutable span required explicit construction; the new hook initially
treated `ERR_save_state()`'s empty-queue null as allocation failure; a memory
fixture incorrectly classified the post-HRR plaintext ServerHello as encrypted;
late switching to server mode initially bypassed the shared role guard. Tight
public tests reproduced the latter three and now pass after narrowly scoped
owned-code/fixture corrections. No third-party implementation was changed.

## Independent official server gate

`n7-restls-hook-matrix-v2`: **40/40 PASS**, `source_unchanged=true`, `cleanup=true`.
The official latest Mihomo **v1.19.31 / Go 1.26.8** and native **OpenSSL 3.5.8**
run in two host-only Apple Containers, guest MTU1500, no published ports and no
host-side listener. Both owned containers and log processes were joined/removed.
The lab location is explicit `--vcore-dir`, never an inferred sibling dependency.

Twenty positive cases cover TLS1.2/TLS1.3 × native/four named profiles × IPv4/IPv6.
Seven more cover TLS1.2 full→ticket resumption, TLS1.2/TLS1.3 mTLS, TLS1.2
ChaCha20/CBC and P-256/P-384. Every successful connection requires real native
authentication, a server-first greeting and byte-for-byte 10 MiB each way,
with an independent origin byte count. Resumption requires two data-bearing
connections and proves the second really resumed; it does not claim a new
certificate signature in a PSK-resumed handshake. mTLS observes a real client
CertificateVerify, not just configuration of a client certificate.

Thirteen negative cases cover wrong key/name, ordinary cover-only TLS, corrupted
encrypted record/ServerHello random, HRR and both mismatched version hints.
They must explicitly reject with no business-origin connection; a timeout is not
authentication rejection, and corruption cases must prove injection occurred.
The engine-only HRR success does not imply Restls HRR interoperability: the
current Mihomo server relays ordinary cover TLS on HRR, so the Restls client
correctly fails its final authentication gate.

### mTLS record-accounting correction

`n7-restls-mtls-v1` failed after a successful native TLS handshake, at server-first
data. The unchanged server had completed client-certificate authentication and
opened the origin, ruling out PKI and first-client-record authentication failures.
Two bounded diagnostic runs showed valid cover tails followed by a Restls MAC
that authenticated only at counter+1. These failed reports remain separate.

The source explains the result: Mihomo's `accountTLS13EarlyTargetRecords` uses
the number of **client records**, not handshake messages, to predict the server
flight. BoringSSL coalesces this mTLS client flight into one record; OpenSSL sends
five encrypted server records. The server therefore starts its Restls counter
at one, while the first probe incorrectly started at zero. The consumer now
counts actual encrypted wire records before handshake completion and mirrors
that deterministic server accounting. It never searches counters to accept a MAC,
skips TLS validation, or changes the third-party server. The corrected isolated
mTLS run and the fresh complete 40-case run both pass. Temporary diagnostics were
removed before the complete run. The future VCore adapter must preserve this rule.

The initial 2-case smoke and 28-case matrix pass only their earlier inputs;
the final 40-case result is one fresh execution, not a union of old results.
The resume/mTLS test-first red runs rejected newly unsupported probe input modes;
these are distinct from the real mTLS record-accounting failure above.

| Artifact | SHA-256 |
| --- | --- |
| Final `results.json` | `00b6c9ccc4b2be5cfbf83230556c2041d5a2d891734b586fae0ac46ccbbcb5a4` |
| Native patch | `8719b57e5ab5c1404efa07ec2ba22dafb5fcdce13e4bd054d5ae995ac2fa375f` |
| Native included implementation | `5678cc4ffbb3cfe400839d76dadebbc733a611f3112d4112243e69337bfe8125` |
| Probe binary | `995005f1360bce69a4c19c4b7b7ed66c3978da28545f15a9820af7c6e8b20393` |
| Local fork lockfile | `c90dc6b27bcb48de82415dec5027b303740e5447536de82cf766acf3a4e569f2` |
| Mihomo binary | `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3` |
| Mihomo archive | `9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4` |

The report binds 21 fork inputs plus the binary and the unchanged lab source
digest `ff34c4042a318043b5575b109b92250af5c0667be143199294abb2d218d14b2a` at
lab commit `94c05f18dab4efc7002221d2004331c373d7083b`. Raw reports are in the
explicit lab's ignored `target/interop/runs/`; local build logs are in this fork's
ignored `target/n7-restls-gates/`. The workspace lockfile is preserved locally
under the existing upstream ignore policy; it is not a committed lockfile or a
claim that an unconstrained future resolution reproduces this graph.

## Remaining boundary

Publication needs separate approval for the new fork revision. After that,
VCore must pin an immutable revision and implement the controlled async adapter,
full script pacing/response semantics, main/download configuration, cancellation,
group/DNS ownership and N7 transport combinations. This blocking consumer only
answers the native-interface feasibility question. It does not sign off Restls
public fields, N7.4 or complete N7. TLS1.3 PSK/resumption is not covered by this
container gate; Mihomo's normal tls13 Restls client disables tickets.

```sh
cargo test --locked -p boring --features restls,client-fingerprint --test restls --test restls_peer
cargo test --locked -p tokio-boring --features restls,client-fingerprint --test restls
cargo build --locked -p boring --features restls,client-fingerprint --example restls
# Regression selection must explicitly enable the Tokio wrapper features too.
cargo test --locked -p tokio-boring --features restls,jls,shadow-tls-v3,client-fingerprint --test restls --test jls --test shadow_tls --test selected_fingerprint --test client_fingerprint
# Container lab must be idle; never bypass its exclusive lock.
restls_core=/absolute/path/to/VCore
uv run --project "$restls_core/scripts" --locked python tests/interop/restls.py \
  --vcore-dir "$restls_core" --run-dir "$restls_core/target/interop/runs/n7-restls-hook-fresh"
# --smoke selects two basic cases; --case-prefix selects an explicit diagnostic.
```

[BLAKE3]: https://docs.rs/crate/blake3/1.8.7

Protocol references: [Mihomo Restls wrapper](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/restls/restls.go),
[exact Restls Go server](https://github.com/MetaCubeX/restls-client-go/blob/6566c5f8a24420fbaeb27bc74deea2597a30f4a7/restls_server.go).
