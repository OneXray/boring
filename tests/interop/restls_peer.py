"""Container-only native OpenSSL Restls cover variants; no TLS emulation."""

import ssl
import threading

from shadow_tls_peer import EVENTS, ROOT, serve


if __name__ == "__main__":
    EVENTS.touch()
    for port, version, curve, mutual, cipher in (
        (24431, ssl.TLSVersion.TLSv1_3, None, False, None),
        (24432, ssl.TLSVersion.TLSv1_2, None, False, None),
        (24433, ssl.TLSVersion.TLSv1_3, "secp384r1", False, None),
        (24434, ssl.TLSVersion.TLSv1_3, None, True, None),
        (24435, ssl.TLSVersion.TLSv1_2, None, True, None),
        (24436, ssl.TLSVersion.TLSv1_2, None, False, "ECDHE-RSA-CHACHA20-POLY1305"),
        (24437, ssl.TLSVersion.TLSv1_2, None, False, "ECDHE-RSA-AES128-SHA"),
        (24438, ssl.TLSVersion.TLSv1_2, "prime256v1", False, None),
        (24439, ssl.TLSVersion.TLSv1_2, "secp384r1", False, None),
    ):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ROOT / "cert.pem", ROOT / "key.pem")
        context.minimum_version = context.maximum_version = version
        if curve:
            context.set_ecdh_curve(curve)
        if cipher:
            context.set_ciphers(cipher)
        if mutual:
            context.load_verify_locations(ROOT / "cert.pem")
            context.verify_mode = ssl.CERT_REQUIRED
        threading.Thread(target=serve, args=(port, context), daemon=True).start()
    serve(9000, None)
