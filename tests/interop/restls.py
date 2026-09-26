"""Restls owned-hook experiment; not VCore integration or complete N7 acceptance."""

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
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--case-prefix", default="")
    args = parser.parse_args()
    core, output = args.vcore_dir.resolve(), args.run_dir.resolve()
    if output.exists() or output.parent != core / "target/interop/runs":
        raise ValueError("fresh direct child of selected lab runs required")
    sys.path.insert(0, str(core / "scripts/src"))
    from vcore_scripts.mihomo_isolation import exclusive_run
    from vcore_scripts.mihomo_release import download_mihomo
    from vcore_scripts.protocol_containers import ContainerLab, command, listing
    from vcore_scripts.protocol_inputs import redact, source_identity
    from vcore_scripts.protocol_streams import certificates

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, interrupted)
    output.mkdir(parents=True)
    binary = FORK / "target/debug/examples/restls"
    inputs = [
        FORK / name
        for name in (
            "Cargo.lock",
            "boring/Cargo.toml",
            "boring-sys/Cargo.toml",
            "boring-sys/build/config.rs",
            "boring-sys/build/main.rs",
            "boring-sys/patches/reality-client.patch",
            "boring-sys/patches/shadow-tls-v3.patch",
            "boring-sys/patches/jls-client.patch",
            "boring-sys/patches/client-fingerprint.patch",
            "boring-sys/patches/restls-client.patch",
            "boring-sys/patches/restls_client.inc",
            "boring/src/ssl/mod.rs",
            "boring/src/ssl/restls.rs",
            "boring/examples/restls.rs",
            "boring/tests/restls.rs",
            "boring/tests/restls_peer.rs",
            "tokio-boring/Cargo.toml",
            "tokio-boring/tests/restls.rs",
            "tests/interop/restls.py",
            "tests/interop/restls_peer.py",
            "tests/interop/shadow_tls_peer.py",
        )
    ]
    result = dict(
        scope=__doc__,
        status="NOT RUN",
        cases=[],
        cleanup=False,
        inputs={str(p.relative_to(FORK)): digest(p) for p in inputs},
        probe_sha256=digest(binary),
        lab_source=source_identity(),
    )
    lab = None
    try:
        with exclusive_run(), contextlib.ExitStack() as stack:
            identity = {}
            mihomo = download_mihomo(
                "linux-arm64", directory=output / "mihomo", identity=identity
            )
            result["mihomo"] = identity
            root = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(prefix="restls-", dir=output)
                )
            )
            origin_root, server_root = root / "origin", root / "server"
            origin_root.mkdir()
            server_root.mkdir()
            cert, _, _ = certificates(origin_root)
            shutil.copy2(
                HERE / "shadow_tls_peer.py", origin_root / "shadow_tls_peer.py"
            )
            shutil.copy2(HERE / "restls_peer.py", origin_root / "peer.py")
            shutil.copy2(mihomo, server_root / "mihomo")
            lab = ContainerLab(result.setdefault("isolation", {}), mtu=1500)
            origin = lab.start(
                stack,
                origin_root,
                "n7-restls-origin",
                ["python", "-B", "-u", "/data/fixture/peer.py"],
            )
            password = "synthetic-restls-password"
            listeners = []
            for index in range(1, 10):
                port, cover = 23000 + index, 24430 + index
                listeners.append(
                    dict(
                        name=f"restls-{port}",
                        type="vless",
                        listen="::",
                        port=port,
                        users=[dict(uuid="07070707-0707-0707-0707-070707070707")],
                        **{
                            "res-tls": dict(
                                enable=True,
                                dest=f"{origin.ipv4}:{cover}",
                                password=password,
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
                "n7-restls-mihomo",
                [
                    "/data/fixture/mihomo",
                    "-d",
                    "/data/mihomo",
                    "-f",
                    "/data/fixture/config.json",
                ],
            )

            def logs():
                for peer, role in [(origin, "origin"), (server, "server")]:
                    if peer.log.exists():
                        (output / f"{role}.log").write_text(
                            redact(peer.log.read_text()[-65_536:])
                        )

            stack.callback(logs)
            origin.release()
            for port in (9000, *range(24431, 24440)):
                origin.wait_tcp(port)
            server.release()
            for port in range(23001, 23010):
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
                raise RuntimeError("binary identity mismatch")
            result["openssl"] = command(
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
                hint="tls13",
                profile="none",
                v6=False,
                secret=password,
                fault="none",
                plain=False,
                expected=True,
                hostname="localhost",
                mode="normal",
                server_port=None,
            ):
                if args.case_prefix and not label.startswith(args.case_prefix):
                    return
                before = len(events())
                host = origin if plain else server
                port = server_port or (
                    (24432 if hint == "tls12" else 24431)
                    if plain
                    else (23002 if hint == "tls12" else 23001)
                )
                endpoint = f"[{host.ipv6}]:{port}" if v6 else f"{host.ipv4}:{port}"
                target = f"[{origin.ipv6}]:9000" if v6 else f"{origin.ipv4}:9000"
                size = 10 * 1024 * 1024
                stdin = (
                    "\n".join(
                        [
                            endpoint,
                            hostname,
                            str(cert),
                            secret,
                            hint,
                            profile,
                            target,
                            fault,
                            str(size),
                            mode,
                        ]
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
                if len(stdout) + len(stderr) > 16_384:
                    raise RuntimeError("probe output limit")
                observed_result = json.loads(stdout)
                result["last_probe"] = dict(
                    id=label, returncode=process.returncode, result=observed_result
                )
                if stderr:
                    result["last_probe"]["diagnostics"] = redact(stderr.decode())
                if process.returncode:
                    result["last_probe"]["observed"] = events()[before:]
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
                    rounds = observed_result.get("rounds", [])
                    passed = (
                        observed_result.get("status") == "passed"
                        and len(rounds) == (2 if mode == "resume" else 1)
                        and all(
                            r.get("version")
                            == ("TLS1.2" if hint == "tls12" else "TLS1.3")
                            and r.get("finished") == 1
                            and r.get(
                                "certificate_verify"
                                if hint == "tls13"
                                else "server_key_exchange"
                            )
                            == (0 if index else 1)
                            and r.get("session_reused") == bool(index)
                            and r.get("bytes_each_way") == size
                            and r.get("client_certificate_verify")
                            == (1 if mode == "mtls" else 0)
                            and r.get("initial_received_counter")
                            == (1 if mode == "mtls" and hint == "tls13" else 0)
                            for index, r in enumerate(rounds)
                        )
                        and [
                            e["bytes"]
                            for e in observed
                            if e.get("event") == "origin-complete"
                        ]
                        == [size] * (2 if mode == "resume" else 1)
                    )
                else:
                    passed = (
                        observed_result.get("status") == "rejected"
                        and not any(e.get("event") == "origin-open" for e in observed)
                        and (
                            fault == "none"
                            or observed_result.get("fault_injected") is True
                        )
                    )
                result["cases"].append(
                    dict(
                        id=label,
                        passed=bool(passed),
                        result=observed_result,
                        observed=observed,
                    )
                )
                print(
                    json.dumps(
                        dict(id=label, passed=bool(passed), result=observed_result)
                    ),
                    flush=True,
                )
                if not passed:
                    raise RuntimeError(f"case failed: {label}")

            for hint in ("tls13", "tls12"):
                for profile in (
                    ("none",)
                    if args.smoke
                    else ("none", "chrome120", "chrome133", "firefox120", "safari16")
                ):
                    for v6 in (False,) if args.smoke else (False, True):
                        probe(
                            f"{hint}-{profile}-v{6 if v6 else 4}",
                            hint=hint,
                            profile=profile,
                            v6=v6,
                        )
                if not args.smoke:
                    probe(
                        f"{hint}-wrong-key",
                        hint=hint,
                        secret="synthetic-wrong-password",
                        expected=False,
                    )
                    probe(
                        f"{hint}-wrong-name",
                        hint=hint,
                        hostname="wrong.invalid",
                        expected=False,
                    )
                    probe(f"{hint}-cover-only", hint=hint, plain=True, expected=False)
                    probe(
                        f"{hint}-corrupt-record",
                        hint=hint,
                        fault="encrypted-record",
                        expected=False,
                    )
                    probe(
                        f"{hint}-corrupt-server-random",
                        hint=hint,
                        fault="server-random",
                        expected=False,
                    )
            if not args.smoke:
                probe("tls12-resume", hint="tls12", mode="resume")
                probe("tls13-mtls", mode="mtls", server_port=23004)
                probe("tls12-mtls", hint="tls12", mode="mtls", server_port=23005)
                probe("tls13-hrr-cover-fallback", server_port=23003, expected=False)
                probe(
                    "tls12-hint-with-tls13-cover",
                    hint="tls12",
                    server_port=23001,
                    expected=False,
                )
                probe("tls13-hint-with-tls12-cover", server_port=23002, expected=False)
                probe("tls12-chacha20", hint="tls12", server_port=23006)
                probe("tls12-cbc", hint="tls12", mode="cbc", server_port=23007)
                probe("tls12-p256", hint="tls12", server_port=23008)
                probe("tls12-p384", hint="tls12", server_port=23009)
            if not result["cases"]:
                raise RuntimeError("case selection matched no tests")
            origin.ensure_alive()
            server.ensure_alive()
            result["status"] = "PASS"
    except BaseException as error:
        result.update(status="FAIL", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        result["lab_source_after"] = source_identity()
        result["source_unchanged"] = (
            result["inputs"] == {str(p.relative_to(FORK)): digest(p) for p in inputs}
            and result["probe_sha256"] == digest(binary)
            and result["lab_source"] == result["lab_source_after"]
        )
        if lab:
            remaining = [
                p["id"]
                for p in listing()
                if p["configuration"].get("labels", {}).get("vcore-run") == lab.run_id
            ]
            result["cleanup"] = not remaining and all(
                p.get("joined") for p in result["isolation"]["peers"]
            )
        (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
        print(
            json.dumps(
                {key: result[key] for key in ("status", "cleanup", "source_unchanged")}
            ),
            flush=True,
        )
    if not result["cleanup"] or not result["source_unchanged"]:
        raise RuntimeError("cleanup or input identity failed")


if __name__ == "__main__":
    main()
