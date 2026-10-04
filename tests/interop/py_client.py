"""Cliente Python para interop con servidor Kotlin.

Uso:
    python py_client.py <PORT> <TOKEN>

Imprime en stdout la respuesta del servidor (JSON compacto) o "ERROR: ...".
Protocolo v2, handshake HMAC-SHA256, loopback sin TLS.
"""

import asyncio
import json
import sys
from phonelink import Peer, WiFiClient


async def main() -> None:
    if len(sys.argv) < 3:
        print("uso: py_client.py <PORT> <TOKEN>", file=sys.stderr)
        sys.exit(2)
    port = int(sys.argv[1])
    token = sys.argv[2]

    peer = Peer(
        WiFiClient("127.0.0.1", token=token, port=port, reconnect=False),
        heartbeat=0,
    )

    response_future: asyncio.Future = asyncio.get_running_loop().create_future()

    async def on_chat(msg):
        if not response_future.done():
            response_future.set_result(msg)

    peer.on("chat", on_chat)
    await peer.start(timeout=5.0)
    try:
        await peer.send("chat", {"text": "hola desde Python"})
        msg = await asyncio.wait_for(response_future, timeout=5.0)
        payload = msg.get("payload", {})
        print(json.dumps(payload, ensure_ascii=False), flush=True)
    finally:
        await peer.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        print(f"ERROR: {exc}", flush=True)
        sys.exit(1)
