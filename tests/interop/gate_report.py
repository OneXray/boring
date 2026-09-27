"""Shared frozen-input and cleanup verdict for owned-fork interop gates."""

import hashlib
import json


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture_inputs(fork, paths, binary, source_identity):
    # Every gate includes the lockfile and this verifier, not only its own script.
    paths = {*paths, fork / "Cargo.lock", fork / "tests/interop/gate_report.py"}
    inputs = {str(p.relative_to(fork)): digest(p) for p in sorted(paths)}
    return dict(
        inputs=inputs,
        probe_sha256=digest(binary),
        lock_sha256=inputs["Cargo.lock"],
        lab_source=source_identity(),
    )


def finalize_run(record, *, fork, binary, source_identity, lab, listing, output):
    """Write the final verdict even if inputs disappear or cleanup cannot be read."""
    record.update(source_unchanged=False, cleanup=False)
    try:
        record["inputs_after"] = {
            name: digest(fork / name) for name in record["inputs"]
        }
        record["probe_sha256_after"] = digest(binary)
        record["lab_source_after"] = source_identity()
        record["source_unchanged"] = (
            record["inputs"] == record["inputs_after"]
            and record["probe_sha256"] == record["probe_sha256_after"]
            and record["lab_source"] == record["lab_source_after"]
        )
    except Exception as error:
        record["identity_error"] = type(error).__name__
    try:
        if lab is not None:
            remaining = [
                peer["id"]
                for peer in listing()
                if peer["configuration"].get("labels", {}).get("vcore-run")
                == lab.run_id
            ]
            record["cleanup"] = not remaining and all(
                peer.get("joined") for peer in record["isolation"]["peers"]
            )
    except Exception as error:
        record["cleanup_error"] = type(error).__name__
    failed = not record["cleanup"] or not record["source_unchanged"]
    if failed:
        record["status"] = "FAIL"
        record.setdefault("failure", "cleanup or input identity failed")
    (output / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(
        json.dumps(
            dict(
                status=record["status"],
                cleanup=record["cleanup"],
                source_unchanged=record["source_unchanged"],
                cases=len(record["cases"]),
            )
        ),
        flush=True,
    )
    if failed:
        raise RuntimeError("cleanup or input identity failed")
