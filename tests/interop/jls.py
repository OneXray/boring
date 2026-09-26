"""Owned-fork JLS hook gate; not VCore integration or stage acceptance."""

import argparse
import contextlib
import hashlib
import json
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FORK = HERE.parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vcore-dir", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    core, output = args.vcore_dir.resolve(), args.run_dir.resolve()
    if output.exists() or output.parent != core / "target/interop/runs":
        raise ValueError(
            "fresh direct child of selected lab target/interop/runs required"
        )
    sys.path.insert(0, str(core / "scripts/src"))
    from vcore_scripts.mihomo_isolation import exclusive_run
    from vcore_scripts.mihomo_release import download_mihomo
    from vcore_scripts.protocol_containers import ContainerLab, command, listing
    from vcore_scripts.protocol_inputs import redact, source_identity
    from vcore_scripts.protocol_streams import certificates

    def interrupted(_sig, _frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, interrupted)
    output.mkdir(parents=True)
    binary = FORK / "target/debug/examples/jls"
    inputs = [
        FORK / name
        for name in (
            "Cargo.lock",
            "boring/Cargo.toml",
            "boring-sys/Cargo.toml",
            "boring-sys/build/config.rs",
            "boring-sys/build/main.rs",
            "boring-sys/patches/shadow-tls-v3.patch",
            "boring-sys/patches/jls-client.patch",
            "boring-sys/patches/reality-client.patch",
            "boring/src/ssl/mod.rs",
            "boring/src/ssl/shadow_tls.rs",
            "boring/src/ssl/jls.rs",
            "boring/src/ssl/fingerprint.rs",
            "boring/examples/jls.rs",
            "boring/tests/jls.rs",
            "tokio-boring/tests/jls.rs",
            "tokio-boring/Cargo.toml",
            "tests/interop/jls.py",
            "tests/interop/shadow_tls_peer.py",
        )
    ]
    record = dict(
        scope=__doc__,
        cases=[],
        status="NOT RUN",
        cleanup=False,
        inputs={str(p.relative_to(FORK)): digest(p) for p in inputs},
        probe_sha256=digest(binary),
    )
    record["lab_source"] = source_identity()
    lab = None
    try:
        with exclusive_run(), contextlib.ExitStack() as stack:
            identity = {}
            mihomo = download_mihomo(
                "linux-arm64", directory=output / "mihomo", identity=identity
            )
            record["mihomo"] = identity
            root = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(prefix="jls-", dir=output)
                )
            )
            origin_root, server_root = root / "origin", root / "server"
            origin_root.mkdir()
            server_root.mkdir()
            certificates(origin_root)
            shutil.copy2(HERE / "shadow_tls_peer.py", origin_root / "peer.py")
            shutil.copy2(mihomo, server_root / "mihomo")
            lab = ContainerLab(record.setdefault("isolation", {}), mtu=1500)
            origin = lab.start(
                stack,
                origin_root,
                "n7-jls-origin",
                ["python", "-B", "-u", "/data/fixture/peer.py"],
            )
            username = "synthetic-jls-user"
            password = "synthetic-jls-password"
            listeners = [
                dict(
                    name="jls",
                    type="vless",
                    listen="::",
                    port=23001,
                    users=[dict(uuid="07070707-0707-0707-0707-070707070707")],
                    **{
                        "jls-config": dict(
                            enable=True,
                            sni="jls.invalid",
                            dest=f"{origin.ipv4}:24431",
                            users=[dict(username=username, password=password)],
                        )
                    },
                )
            ]
            (server_root / "config.json").write_text(
                json.dumps(
                    dict(
                        listeners=listeners,
                        rules=["MATCH,DIRECT"],
                        **{"log-level": "warning"},
                    )
                )
            )
            server = lab.start(
                stack,
                server_root,
                "n7-jls-mihomo",
                [
                    "/data/fixture/mihomo",
                    "-d",
                    "/data/mihomo",
                    "-f",
                    "/data/fixture/config.json",
                ],
            )

            def retain_logs():
                for peer, role in ((origin, "origin"), (server, "server")):
                    if peer.log.exists():
                        (output / f"{role}.log").write_text(
                            redact(peer.log.read_text()[-65536:])
                        )

            stack.callback(retain_logs)
            origin.release()
            for port in (9000, 24431, 24432, 24433):
                origin.wait_tcp(port)
            server.release()
            for port in (23001,):
                server.wait_tcp(port)
            identity["version"] = command(
                "exec", server.name, "/data/fixture/mihomo", "-v"
            ).strip()
            if (
                command(
                    "exec", server.name, "sha256sum", "/data/fixture/mihomo"
                ).split()[0]
                != identity["binary_sha256"]
            ):
                raise RuntimeError("peer binary identity mismatch")
            record["openssl"] = command(
                "exec",
                origin.name,
                "python",
                "-c",
                "import ssl; print(ssl.OPENSSL_VERSION)",
            ).strip()

            def events():
                text = command(
                    "exec",
                    origin.name,
                    "python",
                    "-c",
                    "from pathlib import Path; print(Path('/data/events.jsonl').read_text(),end='')",
                )
                return [json.loads(line) for line in text.splitlines()]

            def probe(
                label,
                *,
                profile="none",
                v6=False,
                supplied_username=username,
                supplied_password=password,
                fault="none",
                plain_port=None,
                expected=True,
            ):
                before = len(events())
                host = origin if plain_port else server
                port = plain_port or 23001
                endpoint = f"[{host.ipv6}]:{port}" if v6 else f"{host.ipv4}:{port}"
                target = f"[{origin.ipv6}]:9000" if v6 else f"{origin.ipv4}:9000"
                size = 10 * 1024 * 1024
                stdin = (
                    "\n".join(
                        (
                            endpoint,
                            "jls.invalid",
                            supplied_username,
                            supplied_password,
                            profile,
                            target,
                            fault,
                            str(size),
                        )
                    )
                    + "\n"
                )
                process = subprocess.Popen(
                    [str(binary)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                try:
                    stdout, stderr = process.communicate(stdin.encode(), timeout=65)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=3)
                if len(stdout) + len(stderr) > 16384:
                    raise RuntimeError(f"probe output limit: {label}")
                result = json.loads(stdout)
                record["last_probe"] = dict(
                    id=label, returncode=process.returncode, result=result
                )
                if process.returncode:
                    raise RuntimeError(f"probe process failed: {label}")
                until = time.monotonic() + 3
                while True:
                    observed = events()[before:]
                    if (
                        not expected
                        or any(e.get("event") == "origin-complete" for e in observed)
                        or time.monotonic() >= until
                    ):
                        break
                    time.sleep(0.05)
                if expected:
                    passed = (
                        result.get("status") == "passed"
                        and result.get("version") == "TLS1.3"
                        and result.get("certificate_verify") == 1
                        and result.get("finished") == 1
                        and result.get("bytes_each_way") == size
                        and [
                            e["bytes"]
                            for e in observed
                            if e.get("event") == "origin-complete"
                        ]
                        == [size]
                    )
                else:
                    passed = (
                        result.get("status") == "rejected"
                        and not any(e.get("event") == "origin-open" for e in observed)
                        and (fault == "none" or result.get("fault_injected") is True)
                    )
                record["cases"].append(
                    dict(
                        id=label,
                        passed=bool(passed),
                        result=result,
                        observed=observed,
                    )
                )
                print(
                    json.dumps(dict(id=label, passed=bool(passed), result=result)),
                    flush=True,
                )
                if not passed:
                    raise RuntimeError(f"case failed: {label}")

            for profile in ("none", "chrome120", "chrome133", "firefox120", "safari16"):
                for v6 in (False, True):
                    probe(f"{profile}-v{6 if v6 else 4}", profile=profile, v6=v6)
            probe(
                "wrong-user", supplied_username="synthetic-other-user", expected=False
            )
            probe(
                "wrong-password",
                supplied_password="synthetic-other-password",
                expected=False,
            )
            probe("server-random-authentication", fault="server-random", expected=False)
            probe("corrupt-encrypted-flight", fault="encrypted-record", expected=False)
            for port in (24431, 24432, 24433):
                probe(f"ordinary-tls-{port}", plain_port=port, expected=False)
            origin.ensure_alive()
            server.ensure_alive()
            record["status"] = "PASS"
    except BaseException as error:
        record.update(status="FAIL", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        record["lab_source_after"] = source_identity()
        record["source_unchanged"] = record["inputs"] == {
            str(p.relative_to(FORK)): digest(p) for p in inputs
        } and record["probe_sha256"] == digest(binary)
        record["source_unchanged"] &= record["lab_source"] == record["lab_source_after"]
        if lab:
            remaining = [
                p["id"]
                for p in listing()
                if p["configuration"].get("labels", {}).get("vcore-run") == lab.run_id
            ]
            record["cleanup"] = not remaining and all(
                p.get("joined") for p in record["isolation"]["peers"]
            )
        (output / "results.json").write_text(json.dumps(record, indent=2) + "\n")
        print(
            json.dumps(
                dict(
                    status=record["status"],
                    cleanup=record["cleanup"],
                    cases=len(record["cases"]),
                )
            ),
            flush=True,
        )
    if not record["cleanup"] or not record["source_unchanged"]:
        raise RuntimeError("cleanup or input identity failed")


if __name__ == "__main__":
    main()
