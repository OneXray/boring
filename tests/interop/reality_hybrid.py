"""Fork-only N7 hybrid REALITY gate, using explicitly supplied VCore lab tools."""

import argparse
import base64
import contextlib
import hashlib
import json
import signal
import shutil
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--vcore-dir", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    core, output = args.vcore_dir.resolve(), args.run_dir.resolve()
    if output.exists() or output.parent != core / "target/interop/runs":
        raise ValueError("fresh direct child of VCore target/interop/runs required")
    sys.path.insert(0, str(core / "scripts/src"))
    from vcore_scripts.mihomo_extended import PRIVATE_KEY, PUBLIC_KEY, SHORT_ID
    from vcore_scripts.mihomo_isolation import exclusive_run
    from vcore_scripts.mihomo_release import download_mihomo
    from vcore_scripts.protocol_containers import ContainerLab, command, listing
    from vcore_scripts.protocol_streams import certificates

    def stop(_sig, _frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, stop)
    output.mkdir(parents=True)
    binary = FORK / "target/debug/examples/reality_hybrid"
    record = dict(
        scope="N7 owned boring hybrid REALITY, not VCore stage acceptance",
        cases=[],
        cleanup=False,
        probe_sha256=digest(binary),
        lock_sha256=digest(FORK / "Cargo.lock"),
        patch_sha256=digest(FORK / "boring-sys/patches/reality-client.patch"),
    )
    source_paths = [
        FORK / name
        for name in (
            "boring-sys/patches/reality-client.patch",
            "boring-sys/build/main.rs",
            "boring/src/ssl/reality.rs",
            "boring/src/ssl/fingerprint.rs",
            "boring/examples/reality_hybrid.rs",
            "boring/tests/reality.rs",
            "tests/interop/reality_hybrid.py",
            "tests/interop/reality_hybrid_peer.py",
        )
    ]
    record["inputs"] = {
        str(path.relative_to(FORK)): digest(path) for path in source_paths
    }
    lab = None
    try:
        with exclusive_run(), contextlib.ExitStack() as stack:
            identity = {}
            mihomo = download_mihomo(
                "linux-arm64", directory=output / "mihomo", identity=identity
            )
            record["mihomo"] = identity
            temporary = Path(
                stack.enter_context(tempfile.TemporaryDirectory(prefix="n7-reality-"))
            )
            origin_root, server_root = temporary / "origin", temporary / "server"
            origin_root.mkdir()
            server_root.mkdir()
            certificates(origin_root)
            shutil.copy2(HERE / "reality_hybrid_peer.py", origin_root / "peer.py")
            shutil.copy2(mihomo, server_root / "mihomo")
            lab = ContainerLab(record.setdefault("isolation", {}), mtu=1500)
            origin = lab.start(
                stack,
                origin_root,
                "n7-hybrid-origin",
                ["python", "-u", "/data/fixture/peer.py"],
            )

            def origin_log():
                # This owned fixture logs only bounded startup diagnostics;
                # it never prints configurations, credentials or raw traffic.
                if origin.log.exists():
                    (output / "origin-startup.log").write_bytes(
                        origin.log.read_bytes()[:16384]
                    )

            stack.callback(origin_log)
            listeners = []
            for port, cover in [(23001, 24431), (23002, 24432), (23003, 24433)]:
                listeners.append(
                    dict(
                        name=f"reality-{port}",
                        type="vless",
                        listen="::",
                        port=port,
                        users=[
                            dict(
                                username="fixture",
                                uuid="07070707-0707-0707-0707-070707070707",
                            )
                        ],
                        **{
                            "reality-config": dict(
                                dest=f"{origin.ipv4}:{cover}",
                                **{
                                    "private-key": PRIVATE_KEY,
                                    "short-id": [SHORT_ID],
                                    "server-names": ["localhost"],
                                },
                            )
                        },
                    )
                )
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
                "n7-hybrid-mihomo",
                [
                    "/data/fixture/mihomo",
                    "-d",
                    "/data/mihomo",
                    "-f",
                    "/data/fixture/config.json",
                ],
            )
            (origin_root / "routes.json").write_text(
                json.dumps({str(24435 + i): [server.ipv4, 23001 + i] for i in range(3)})
            )
            origin.release()
            for port in (9000, 24431, 24432, 24433, 24434, 24435):
                origin.wait_tcp(port)
            server.release()
            server.wait_tcp(23001)
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

            public = base64.urlsafe_b64decode(PUBLIC_KEY + "=").hex()

            def probe(
                label,
                *,
                mode="hybrid",
                profile="chrome",
                port=24435,
                key=public,
                short_id=SHORT_ID,
                sni="localhost",
                expected=True,
                v6=False,
                direct=False,
            ):
                before = len(events())
                endpoint = f"[{origin.ipv6}]:{port}" if v6 else f"{origin.ipv4}:{port}"
                target = (
                    "-"
                    if direct
                    else (f"[{origin.ipv6}]:9000" if v6 else f"{origin.ipv4}:9000")
                )
                size = 10 * 1024 * 1024 if expected and not direct else 1
                payload = (
                    "\n".join(
                        [endpoint, sni, key, short_id, mode, profile, target, str(size)]
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
                    stdout, stderr = process.communicate(payload.encode(), timeout=65)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=3)
                if process.returncode or len(stdout) + len(stderr) > 16384:
                    raise RuntimeError("probe process failure")
                result = json.loads(stdout)
                observed = []
                until = time.monotonic() + 3
                while time.monotonic() < until:
                    observed = events()[before:]
                    if not expected or any(
                        e.get("event") == "origin-complete" for e in observed
                    ):
                        break
                    time.sleep(0.05)
                success = result.get("status") == "passed"
                passed = success == expected and result.get("status") != "timeout"
                if expected:
                    group = 4588 if mode == "hybrid" else 29
                    passed &= (
                        result.get("group") == group
                        and result.get("bytes_each_way") == size
                    )
                    passed &= any(
                        e.get("event") == "server-hello" and e.get("group") == group
                        for e in observed
                    )
                    passed &= [
                        e["bytes"]
                        for e in observed
                        if e.get("event") == "origin-complete"
                    ] == [size]
                else:
                    passed &= not any(
                        e.get("event") in ("origin-data", "origin-complete")
                        for e in observed
                    )
                case = dict(
                    id=label,
                    expected=expected,
                    passed=bool(passed),
                    result=result,
                    observed=observed,
                )
                record["cases"].append(case)
                print(
                    json.dumps(dict(id=label, passed=bool(passed), result=result)),
                    flush=True,
                )
                if not passed:
                    raise RuntimeError(f"case failed: {label}")

            for profile in ("native", "chrome"):
                for v6 in (False, True):
                    probe(f"hybrid-{profile}-v{6 if v6 else 4}", profile=profile, v6=v6)
                probe(f"classic-{profile}", mode="classic", profile=profile, port=24436)
            probe("reject-classic-selection", port=24436, expected=False)
            probe("reject-hrr", port=24437, expected=False)
            probe("reject-wrong-short-id", short_id="00" * 8, expected=False)
            probe("reject-wrong-public-key", key="11" * 32, expected=False)
            probe("reject-wrong-sni", sni="wrong.invalid", expected=False)
            probe("reject-ordinary-cert", port=24431, direct=True, expected=False)
            probe("reject-tls12", port=24434, direct=True, expected=False)
            for peer in (origin, server):
                peer.ensure_alive()
            record["status"] = "PASS"
    except BaseException as error:
        record.update(status="FAIL", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        record["source_unchanged"] = (
            record["inputs"]
            == {str(path.relative_to(FORK)): digest(path) for path in source_paths}
            and record["probe_sha256"] == digest(binary)
            and record["lock_sha256"] == digest(FORK / "Cargo.lock")
        )
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
                    status=record.get("status"),
                    cleanup=record["cleanup"],
                    cases=len(record["cases"]),
                )
            ),
            flush=True,
        )
    if not record["cleanup"] or not record["source_unchanged"]:
        raise RuntimeError("container cleanup or frozen source check failed")


if __name__ == "__main__":
    main()
