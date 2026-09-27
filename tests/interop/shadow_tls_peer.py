"""Container-only native OpenSSL cover and bounded server-first TCP origin."""

import json
import socket
import ssl
import threading
from pathlib import Path

ROOT = Path("/data/fixture")
EVENTS = Path("/data/events.jsonl")
LOCK = threading.Lock()
SLOTS = threading.BoundedSemaphore(32)


def emit(**event):
    with LOCK, EVENTS.open("a") as output:
        output.write(json.dumps(event) + "\n")


def handle(raw, port, context):
    try:
        with raw:
            raw.settimeout(15)
            if port == 9000:
                emit(event="origin-open")
                raw.sendall(b"hello")
                received = 0
                while part := raw.recv(16384):
                    received += len(part)
                    if received > 10 * 1024 * 1024:
                        raise ValueError("bounded origin")
                    raw.sendall(part)
                emit(event="origin-complete", bytes=received)
                return
            with context.wrap_socket(raw, server_side=True) as tls:
                emit(event="cover-complete", port=port, version=tls.version())
                # Keep the cover alive until the real ShadowTLS relay switches.
                # No fabricated handshake, Finished, record or certificate.
                while tls.recv(16384):
                    pass
    except (OSError, ValueError):
        emit(event="closed", port=port)
    finally:
        SLOTS.release()


def serve(port, context):
    with socket.socket(socket.AF_INET6) as listener:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        listener.bind(("::", port))
        listener.listen(32)
        while True:
            raw, _ = listener.accept()
            SLOTS.acquire()
            threading.Thread(
                target=handle, args=(raw, port, context), daemon=True
            ).start()


if __name__ == "__main__":
    EVENTS.touch()
    for port, version, curve in (
        (24431, ssl.TLSVersion.TLSv1_3, None),
        (24432, ssl.TLSVersion.TLSv1_2, None),
        (24433, ssl.TLSVersion.TLSv1_3, "secp384r1"),
    ):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ROOT / "cert.pem", ROOT / "key.pem")
        context.minimum_version = context.maximum_version = version
        if curve:
            context.set_ecdh_curve(curve)
        threading.Thread(target=serve, args=(port, context), daemon=True).start()
    serve(9000, None)
