"""Owned-fork ShadowTLS v3 hook gate; not VCore integration or stage acceptance."""

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
    binary = FORK / "target/debug/examples/shadow_tls_v3"
    inputs = [
        FORK / name
        for name in (
            "Cargo.lock",
            "boring/Cargo.toml",
            "boring-sys/Cargo.toml",
            "boring-sys/build/config.rs",
            "boring-sys/build/main.rs",
            "boring-sys/patches/shadow-tls-v3.patch",
            "boring-sys/patches/reality-client.patch",
            "boring/src/ssl/mod.rs",
            "boring/src/ssl/shadow_tls.rs",
            "boring/src/ssl/fingerprint.rs",
            "boring/examples/shadow_tls_v3.rs",
            "boring/tests/shadow_tls.rs",
            "tokio-boring/tests/shadow_tls.rs",
            "tests/interop/shadow_tls_v3.py",
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
                    tempfile.TemporaryDirectory(prefix="shadow-v3-", dir=output)
                )
            )
            origin_root, server_root = root / "origin", root / "server"
            origin_root.mkdir()
            server_root.mkdir()
            cert, _, _ = certificates(origin_root)
            shutil.copy2(HERE / "shadow_tls_peer.py", origin_root / "peer.py")
            shutil.copy2(mihomo, server_root / "mihomo")
            lab = ContainerLab(record.setdefault("isolation", {}), mtu=1500)
            origin = lab.start(
                stack,
                origin_root,
                "n7-shadow-cover",
                ["python", "-B", "-u", "/data/fixture/peer.py"],
            )
            password = "synthetic-shadow-v3-password"
            listeners = [
                dict(
                    name=f"shadow-{port}",
                    type="vless",
                    listen="::",
                    port=port,
                    users=[dict(uuid="07070707-0707-0707-0707-070707070707")],
                    **{
                        "shadow-tls": dict(
                            enable=True,
                            version=3,
                            users=[dict(name="synthetic", password=password)],
                            handshake=dict(dest=f"{origin.ipv4}:{cover}"),
                        )
                    },
                )
                for port, cover in ((23001, 24431), (23002, 24432), (23003, 24433))
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
                "n7-shadow-mihomo",
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
            for port in (23001, 23002, 23003):
                server.wait_tcp(port)
            identity["version"] = command(
                "exec", server.name, "/data/fixture/mihomo", "-v"
            ).strip()
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
                profile="none",
                version="TLS1.3",
                port=23001,
                v6=False,
                supplied_password=password,
                trust=True,
                sni="localhost",
                corrupt=False,
                hrr=False,
                expected=True,
            ):
                before = len(events())
                endpoint = f"[{server.ipv6}]:{port}" if v6 else f"{server.ipv4}:{port}"
                target = f"[{origin.ipv6}]:9000" if v6 else f"{origin.ipv4}:9000"
                size = 10 * 1024 * 1024
                stdin = (
                    "\n".join(
                        (
                            endpoint,
                            sni,
                            supplied_password,
                            profile,
                            str(cert) if trust else "-",
                            target,
                            str(size),
                            "corrupt" if corrupt else "no-fault",
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
                    raise RuntimeError(f"probe process failed: {label}")
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
                passed = (result.get("status") == "passed") == expected and result.get(
                    "status"
                ) != "timeout"
                if expected:
                    passed &= (
                        result.get("version") == version
                        and result.get("hrr") == hrr
                        and result.get("bytes_each_way") == size
                    )
                    passed &= [
                        e["bytes"]
                        for e in observed
                        if e.get("event") == "origin-complete"
                    ] == [size]
                    passed &= any(
                        e.get("event") == "cover-complete"
                        and e.get("version")
                        == {"TLS1.2": "TLSv1.2", "TLS1.3": "TLSv1.3"}[version]
                        for e in observed
                    )
                else:
                    passed &= result.get("status") == "rejected" and not any(
                        e.get("event") == "origin-open" for e in observed
                    )
                record["cases"].append(
                    dict(
                        id=label, passed=bool(passed), result=result, observed=observed
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
                    for version, port in (("TLS1.3", 23001), ("TLS1.2", 23002)):
                        probe(
                            f"{profile}-{version}-v{6 if v6 else 4}",
                            profile=profile,
                            version=version,
                            port=port,
                            v6=v6,
                        )
            probe("chrome133-hrr", profile="chrome133", port=23003, hrr=True)
            probe(
                "wrong-password",
                supplied_password="synthetic-wrong-password",
                expected=False,
            )
            probe("untrusted-cover", trust=False, expected=False)
            probe("wrong-cover-name", sni="wrong.invalid", expected=False)
            probe("corrupt-relay-authentication", corrupt=True, expected=False)
            origin.ensure_alive()
            server.ensure_alive()
            record["status"] = "PASS"
    except BaseException as error:
        record.update(status="FAIL", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        record["source_unchanged"] = record["inputs"] == {
            str(p.relative_to(FORK)): digest(p) for p in inputs
        } and record["probe_sha256"] == digest(binary)
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
