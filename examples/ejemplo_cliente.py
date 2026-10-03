"""Ejemplo: cliente WiFi que se conecta al servidor del ejemplo_pc.

Protocolo v2: el token no viaja en claro; se usa HMAC-SHA256 sobre un nonce.
El token debe coincidir con el del servidor (mín. 16 caracteres).
"""

import asyncio
import logging

from phonelink import Peer, WiFiClient

logging.basicConfig(level=logging.INFO)

import ssl
from pathlib import Path

# Mismo token que ejemplo_pc (mín. 16 chars; mejor 32+)
TOKEN = "tu-token-de-32-chars-minimo"

CERT_DIR = Path(__file__).parent.parent / "certs"

def build_client_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Confía en tu cert autofirmado (o en su CA).
    ctx.load_verify_locations(cafile=str(CERT_DIR / "server.crt"))
    # Si el CN/SAN del cert no coincide con "127.0.0.1", esto fallará:
    ctx.check_hostname = True
    return ctx

async def main() -> None:
    peer = Peer(WiFiClient(
        "127.0.0.1",
        token=TOKEN,
        port=8888,
        ssl_context=build_client_ssl_context(),
    ))

    async def on_chat(msg):
        print(f"PC dice: {msg.get('payload', {}).get('text')}")

    peer.on("chat", on_chat)
    await peer.start(timeout=5.0)
    await peer.send("chat", {"text": "Hola desde el cliente"})
    await asyncio.sleep(2)
    await peer.stop()


if __name__ == "__main__":
    asyncio.run(main())
