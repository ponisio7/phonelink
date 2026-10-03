"""Ejemplo: PC como servidor WiFi con TLS.

Protocolo v2: challenge-response (HMAC-SHA256). El token no sale al cable.
Sin certificados en certs/, usa loopback sin TLS para pruebas locales.
"""

import asyncio
import logging
import ssl
from pathlib import Path
from typing import Optional

from phonelink import Peer, WiFiServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

CERT_DIR = Path(__file__).parent.parent / "certs"
TOKEN = "tu-token-de-32-chars-minimo"


def build_ssl_context() -> Optional[ssl.SSLContext]:
    cert = CERT_DIR / "server.crt"
    key = CERT_DIR / "server.key"
    if not cert.exists() or not key.exists():
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    ctx.options |= (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )
    return ctx


async def main() -> None:
    ssl_ctx = build_ssl_context()
    host = "0.0.0.0" if ssl_ctx is not None else "127.0.0.1"
    peer = Peer(WiFiServer(
        token=TOKEN,
        host=host,
        port=8888,
        ssl_context=ssl_ctx,
    ))

    async def on_chat(msg):
        texto = msg.get("payload", {}).get("text")
        print(f"Teléfono dice: {texto}")
        await peer.send("chat", {"text": f"PC recibió: {texto}"})

    peer.on("chat", on_chat)
    await peer.start()
    print(
        f"Esperando al teléfono (protocolo v2, TLS={'sí' if ssl_ctx else 'no'})... "
        "(Ctrl+C para salir)"
    )
    try:
        await asyncio.Event().wait()
    finally:
        await peer.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
