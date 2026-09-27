# Owned-fork interop gates

`jls.py`, `shadow_tls_v3.py` and `reality_hybrid.py` retain their independent
protocol cases and assertions. Each uses `gate_report.py` for the same final
evidence checks:

- Freeze and recheck the gate's selected fork inputs, `Cargo.lock`, the shared
  verifier, the probe executable, and the explicitly selected VCore lab source.
- Check that owned containers are gone and their log processes have joined.
- Save `results.json` with `status=FAIL` on identity or cleanup failure, even if
  every protocol case passed. Missing inputs or failed identity/cleanup queries
  are not a pass. Preserve any original protocol failure reason.

The lab path is supplied with `--vcore-dir`; it is test tooling, not a production
dependency. Servers and origins run in isolated containers with no host listeners.
The report is fork-only interoperability evidence, not VCore stage acceptance or
physical-device validation. See the corresponding protocol document in `docs/`
for the build and run commands.

The shared report regressions need only Python's standard library, no lab checkout
or containers:

```sh
python3 -B -m unittest discover -s tests/interop -p 'test_*.py' -v
```

They cover stable identity, changes limited to the lab, fork/lock/probe/verifier
changes, removed inputs, identity query errors, owned versus unrelated containers,
unjoined processes, cleanup query errors, missing lab, and preserved protocol
failures.

## PR #1 review-fix validation (2026-09-27)

The 10 shared-report tests passed. Fresh official Mihomo v1.19.31 / Go 1.26.8
container gates passed all 55 cases below; every run reports
`source_unchanged=true` and `cleanup=true`. All six owned containers were removed.
The independent peers use a host-only network, guest MTU 1500 and no published
ports. This validation does not add ShadowTLS to VCore's protocol scope.

Reports are under the selected lab's ignored `target/interop/runs/` directory:

| Run directory | Passed cases | `results.json` SHA-256 |
| --- | --- | --- |
| `boring-pr1-jls-fix-20260927` | 17/17 | `703d3ff9f1d2fc2185591d1bf48a5c08be4e673a91a0bf141dcb0b58fb7d6fac` |
| `boring-pr1-shadow-fix-20260927` | 25/25 | `cfedd07a23ce9652c6cc306a4f2e0b2be891ac0a18cc3e618d677492329bb256` |
| `boring-pr1-hybrid-fix-20260927` | 13/13 | `cfb069b117d803d4572ee73d22b391839781cce91afb01eba8ad32b467b8b485` |

The JLS native patch SHA-256 was
`024e6c3724af18b9a714e8da34956e00503055b8c0b3548b600f49f4cc8b2028`;
the shared verifier SHA-256 was
`6e1cab775b4b53c7242a0bda9e4d0e18db06d394e40bbb3411f8a5666ee19ead`.
Each report also records before/after lab source identity, selected fork input
hashes, probe hashes, downloaded Mihomo hashes, cases and owned resource cleanup.
The lab checkout had existing dependency edits; its recorded source digest, not
its parent commit alone, identifies the tooling used. VCore was not rebuilt or
switched to this fork revision by these tests.
