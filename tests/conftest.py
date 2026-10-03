"""Fixtures y utilidades compartidas para la suite de tests de phonelink.

Contrato de fixtures:
  - server / client: NO arrancan el transporte. El test debe llamar a
    `await peer.start()` (y `await peer.stop()` o dejar que el fixture limpie).
  - server_port: puerto libre en 127.0.0.1.
  - TOKEN: token válido (>= 16 caracteres) para WiFiServer/WiFiClient.

Helpers:
  - free_port(), Collector, raw_connect, raw_handshake, raw_auth.
"""

import asyncio
import contextlib
import socket
from typing import Any, List, Optional

import pytest

from phonelink import Peer, WiFiClient, WiFiServer
from phonelink.protocol import HANDSHAKE_MAX, PROTOCOL_VERSION, MessageStream
from phonelink.wifi import _mac_hex

TOKEN = "test-token-12345678901234567890"   # 32 caracteres, > 16


def free_port() -> int:
    """Devuelve un puerto TCP libre en localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Collector:
    """Recoge mensajes por evento para aserciones."""

    def __init__(self) -> None:
        self.messages: List[Any] = []
        self._event = asyncio.Event()

    async def handler(self, msg: Any) -> None:
        self.messages.append(msg)
        self._event.set()

    async def wait_for(self, predicate, timeout: float = 2.0) -> Any:
        """Espera hasta que algún mensaje cumpla predicate."""
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            for m in self.messages:
                if predicate(m):
                    return m
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise AssertionError(f"No llegó mensaje. Recibidos: {self.messages}")
            self._event.clear()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._event.wait(), timeout=remaining)


async def raw_connect(port: int, host: str = "127.0.0.1") -> MessageStream:
    reader, writer = await asyncio.open_connection(host, port)
    return MessageStream(reader, writer)


async def raw_handshake(
    port: int,
    token: str = TOKEN,
    *,
    host: str = "127.0.0.1",
    protocol_version: int = PROTOCOL_VERSION,
    stream: Optional[MessageStream] = None,
) -> tuple:
    """Handshake v2 completo. Devuelve (stream, reply)."""
    if stream is None:
        stream = await raw_connect(port, host)
    await stream.send({
        "type": "hello",
        "protocol_version": protocol_version,
    })
    first = await asyncio.wait_for(
        stream.recv(max_size=HANDSHAKE_MAX), timeout=5.0
    )
    if not isinstance(first, dict) or first.get("type") != "challenge":
        return stream, first
    nonce = bytes.fromhex(first["nonce"])
    mac = _mac_hex(token, nonce)
    if mac is None:
        await stream.send({"type": "auth", "mac": "00" * 32})
    else:
        await stream.send({"type": "auth", "mac": mac})
    reply = await asyncio.wait_for(
        stream.recv(max_size=HANDSHAKE_MAX), timeout=5.0
    )
    return stream, reply


async def raw_auth(
    port: int,
    token: str = TOKEN,
    *,
    host: str = "127.0.0.1",
    protocol_version: int = PROTOCOL_VERSION,
) -> MessageStream:
    """Handshake v2 y asume éxito (auth_ok). Lanza si no."""
    stream, reply = await raw_handshake(
        port, token, host=host, protocol_version=protocol_version
    )
    if not isinstance(reply, dict) or reply.get("type") != "auth_ok":
        await stream.close()
        raise AssertionError(f"Auth esperada, recibido: {reply}")
    return stream


@pytest.fixture
async def server_port() -> int:
    return free_port()


@pytest.fixture
async def server(server_port: int):
    """Servidor WiFi listo para usar. Se detiene al final del test."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer = Peer(srv, heartbeat=0)
    yield peer, srv, server_port
    with contextlib.suppress(Exception):
        await peer.stop()


@pytest.fixture
async def client(server_port: int):
    """Cliente WiFi. Se detiene al final del test."""
    cli = WiFiClient(
        "127.0.0.1", token=TOKEN, port=server_port, reconnect=False
    )
    peer = Peer(cli, heartbeat=0)
    yield peer, cli
    with contextlib.suppress(Exception):
        await peer.stop()
