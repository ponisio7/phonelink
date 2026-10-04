"""Servidor Python para interop con cliente Kotlin.

Uso:
    python py_server.py <TOKEN>

Imprime en stdout una línea con el puerto real (ej: "PORT=54321"),
luego se queda escuchando hasta recibir "stop\n" por stdin.

Protocolo v2, handshake HMAC-SHA256, loopback sin TLS.
"""

import asyncio
import sys
from phonelink import Peer, WiFiServer


async def main() -> None:
    if len(sys.argv) < 2:
        print("uso: py_server.py <TOKEN>", file=sys.stderr)
        sys.exit(2)
    token = sys.argv[1]

    srv = WiFiServer(token=token, host="127.0.0.1", port=0)
    peer = Peer(srv, heartbeat=0)

    async def on_chat(msg):
        texto = msg.get("payload", {}).get("text", "")
        # Eco con prefijo "echo:"
        await peer.send("chat", {"text": f"echo:{texto}"})

    peer.on("chat", on_chat)
    await peer.start()

    # Imprime el puerto real para que el test Kotlin lo lea
    print(f"PORT={srv.bound_port}", flush=True)

    # Espera "stop\n" por stdin para terminar limpiamente
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _watch_stdin() -> None:
        for line in sys.stdin:
            if line.strip() == "stop":
                loop.call_soon_threadsafe(stop_event.set)
                return
        loop.call_soon_threadsafe(stop_event.set)

    loop.run_in_executor(None, _watch_stdin)

    try:
        await stop_event.wait()
    finally:
        await peer.stop()


if __name__ == "__main__":
    asyncio.run(main())
