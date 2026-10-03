"""Parche C: timeout de inactividad (no de duración total) en la lectura."""

import asyncio
import hashlib
import hmac
import json
import struct

import pytest

from phonelink import Peer, WiFiServer
from phonelink.protocol import (
    HANDSHAKE_MAX,
    READ_CHUNK,
    MessageStream,
    ProtocolError,
    encode,
    read_message,
)
from phonelink.protocol import PROTOCOL_VERSION

from .conftest import TOKEN, Collector


def _frame(size_chars: int) -> bytes:
    return encode({"type": "evt", "payload": {"d": "x" * size_chars}})


async def _feed_slowly(reader: asyncio.StreamReader, data: bytes,
                       piece: int, pause: float, eof: bool = True) -> None:
    for i in range(0, len(data), piece):
        reader.feed_data(data[i:i + piece])
        await asyncio.sleep(pause)
    if eof:
        reader.feed_eof()


async def _handshake_v2(stream: MessageStream, token: str) -> None:
    """Handshake v2 completo (hello -> challenge -> auth -> auth_ok).

    El token nunca viaja por el cable: solo el HMAC-SHA256 sobre el nonce.
    """
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    challenge = await stream.recv(max_size=HANDSHAKE_MAX)
    assert challenge.get("type") == "challenge", challenge
    nonce = bytes.fromhex(challenge["nonce"])
    mac = hmac.new(token.encode("utf-8"), nonce, hashlib.sha256).hexdigest()
    await stream.send({"type": "auth", "mac": mac})
    reply = await stream.recv(max_size=HANDSHAKE_MAX)
    assert reply.get("type") == "auth_ok", reply


# ------------------------------------------------------------------ C1
async def test_mensaje_grande_que_fluye_no_se_aborta():
    """160 KB en ~1 s con idle_timeout=0,5 s: antes -> Timeout de lectura."""
    data = _frame(160_000)
    reader = asyncio.StreamReader()
    feeder = asyncio.create_task(_feed_slowly(reader, data, piece=8192, pause=0.05))
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    msg = await read_message(reader, idle_timeout=0.5)
    elapsed = loop.time() - t0
    await feeder
    assert elapsed > 0.5  # tardó más que el idle_timeout: era el caso a cubrir
    assert msg["payload"]["d"] == "x" * 160_000


# ------------------------------------------------------------------ C2
async def test_silencio_a_mitad_de_mensaje_se_aborta():
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack(">I", 1000) + b"0123456789")  # promete 1000
    with pytest.raises(ProtocolError, match="inactividad"):
        await read_message(reader, idle_timeout=0.3)


async def test_silencio_entre_mensajes_se_aborta():
    reader = asyncio.StreamReader()
    with pytest.raises(ProtocolError, match="inactividad"):
        await read_message(reader, idle_timeout=0.3)


# ------------------------------------------------------------------ C3
async def test_goteo_lento_no_retiene_la_conexion():
    """1 byte cada 0,2 s con idle_timeout=0,5 s: cada byte llega 'a tiempo'
    pero el bloque no se completa nunca -> debe abortarse (Slowloris)."""
    data = _frame(100_000)
    reader = asyncio.StreamReader()
    feeder = asyncio.create_task(
        _feed_slowly(reader, data[:200], piece=1, pause=0.2, eof=False)
    )
    try:
        with pytest.raises(ProtocolError, match="inactividad"):
            await read_message(reader, idle_timeout=0.5)
    finally:
        feeder.cancel()
        await asyncio.gather(feeder, return_exceptions=True)


# ------------------------------------------------------------------ C4
@pytest.mark.parametrize("idle", [None, 1.0])
async def test_incomplete_read_conserva_partial_y_expected(idle):
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack(">I", 100) + b"0123456789")
    reader.feed_eof()
    with pytest.raises(asyncio.IncompleteReadError) as info:
        await read_message(reader, idle_timeout=idle)
    assert info.value.partial == b"0123456789"
    assert info.value.expected == 100


async def test_incomplete_read_multibloque_acumula_partial():
    n = READ_CHUNK * 2 + 500
    body = b"a" * (READ_CHUNK + 123)
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack(">I", n) + body)
    reader.feed_eof()
    with pytest.raises(asyncio.IncompleteReadError) as info:
        await read_message(reader, idle_timeout=1.0)
    assert info.value.partial == body
    assert info.value.expected == n


# ------------------------------------------------------------------ C5
async def test_on_activity_se_invoca_por_bloque():
    data = _frame(READ_CHUNK * 3)
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    cuenta = []
    await read_message(reader, idle_timeout=1.0, on_activity=lambda: cuenta.append(1))
    assert len(cuenta) >= 4  # cabecera + >=3 bloques de payload


async def test_message_stream_actualiza_last_rx():
    a, b = __import__("socket").socketpair()
    r1, w1 = await asyncio.open_connection(sock=a)
    r2, w2 = await asyncio.open_connection(sock=b)
    s1, s2 = MessageStream(r1, w1), MessageStream(r2, w2)
    # M5: sin bytes recibidos, last_rx es None.
    assert s2.last_rx is None
    await asyncio.sleep(0.05)
    await s1.send({"k": 1})
    await s2.recv(idle_timeout=1.0)
    assert s2.last_rx is not None
    assert isinstance(s2.last_rx, float)
    await s1.close()
    await s2.close()


# ------------------------------------------------------------------ C6
async def test_heartbeat_no_mata_una_transferencia_lenta(server_port):
    """Mensaje de ~1,5 s con heartbeat_timeout=0,6 s: antes, el heartbeat
    cerraba la conexión a mitad (_last_seen solo cuenta mensajes completos)."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer = Peer(srv, heartbeat=0.2, heartbeat_timeout_factor=3.0)
    recibidos = Collector()
    peer.on("evt", recibidos.handler)
    await peer.start()
    stream = None
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server_port)
        stream = MessageStream(reader, writer)
        await _handshake_v2(stream, TOKEN)

        data = _frame(120_000)
        for i in range(0, len(data), 8192):
            writer.write(data[i:i + 8192])
            await writer.drain()
            await asyncio.sleep(0.1)

        msg = await recibidos.wait_for(lambda m: m.get("type") == "evt", timeout=3.0)
        assert len(msg["payload"]["d"]) == 120_000
        assert srv.is_connected()
    finally:
        if stream is not None:
            await stream.close()
        await peer.stop()


async def test_heartbeat_sigue_cortando_un_enlace_realmente_muerto(server_port):
    """El cambio no debe desactivar el heartbeat: sin bytes, se cierra."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer = Peer(srv, heartbeat=0.2, heartbeat_timeout_factor=3.0)
    await peer.start()
    stream = None
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server_port)
        stream = MessageStream(reader, writer)
        await _handshake_v2(stream, TOKEN)
        # El cliente crudo no responde a pings ni envía nada.
        deadline = asyncio.get_running_loop().time() + 3.0
        while srv.is_connected() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.1)
        assert not srv.is_connected()
    finally:
        if stream is not None:
            await stream.close()
        await peer.stop()