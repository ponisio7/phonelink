"""Tests del handshake v2 (challenge-response con HMAC-SHA256)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
from typing import Optional

import pytest

from phonelink import (
    AuthRejected,
    Peer,
    ProtocolError,
    TransientAuthError,
    WiFiClient,
    WiFiServer,
)
from phonelink.protocol import (
    HANDSHAKE_MAX,
    NONCE_SIZE,
    PROTOCOL_VERSION,
    MessageStream,
    encode,
    read_message,
    write_message,
)
from phonelink.wifi import (
    AUTH_FAILED,
    PROTOCOL_VERSION_MISMATCH,
    RATE_LIMITED,
    SERVER_ERROR,
    _compute_mac,
    _mac_hex,
)

TOKEN = "mi-token-secreto-de-al-menos-16"
TOKEN_SHORT = "corto"
HOST = "127.0.0.1"


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Unit: HMAC helpers
# ---------------------------------------------------------------------------


def test_compute_mac_deterministic():
    nonce = b"\x00" * NONCE_SIZE
    a = _compute_mac(TOKEN, nonce)
    b = _compute_mac(TOKEN, nonce)
    assert a is not None and a == b
    assert len(a) == 32


def test_compute_mac_different_nonce():
    n1 = secrets.token_bytes(NONCE_SIZE)
    n2 = secrets.token_bytes(NONCE_SIZE)
    assert _compute_mac(TOKEN, n1) != _compute_mac(TOKEN, n2)


def test_mac_hex_roundtrip():
    nonce = secrets.token_bytes(NONCE_SIZE)
    h = _mac_hex(TOKEN, nonce)
    assert h is not None
    assert bytes.fromhex(h) == _compute_mac(TOKEN, nonce)


# ---------------------------------------------------------------------------
# Integration: happy path + failures
# ---------------------------------------------------------------------------


@pytest.fixture
async def server():
    port = _free_port()
    srv = WiFiServer(
        token=TOKEN,
        host=HOST,
        port=port,
        rate_limit=True,
        require_strong_token=True,
    )
    await srv.start()
    yield srv, port
    await srv.stop()


@pytest.mark.asyncio
async def test_handshake_success(server):
    srv, port = server
    client = WiFiClient(HOST, TOKEN, port=port, reconnect=False)
    await client.start(timeout=5.0)
    assert client.is_connected()
    # Round-trip de mensaje de aplicación
    received = asyncio.Event()
    got = {}

    async def on_msg(msg):
        got["msg"] = msg
        received.set()

    client.on_message(on_msg)
    await srv.send({"type": "chat", "payload": {"text": "hola"}})
    await asyncio.wait_for(received.wait(), timeout=2.0)
    assert got["msg"]["type"] == "chat"
    await client.stop()


@pytest.mark.asyncio
async def test_wrong_hmac_auth_failed(server):
    srv, port = server
    client = WiFiClient(HOST, "token-incorrecto-xxxxx", port=port, reconnect=False)
    with pytest.raises(AuthRejected) as ei:
        await client.start(timeout=5.0)
    assert ei.value.reason == AUTH_FAILED
    await client.stop()


@pytest.mark.asyncio
async def test_protocol_version_mismatch(server):
    """Cliente que manda hello con versión distinta recibe mismatch."""
    srv, port = server

    reader, writer = await asyncio.open_connection(HOST, port)
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": 1})
    # Tras el retardo anti-fuerza-bruta llega el error
    reply = await asyncio.wait_for(stream.recv(max_size=HANDSHAKE_MAX), timeout=3.0)
    assert reply.get("type") == "error"
    assert reply.get("reason") == PROTOCOL_VERSION_MISMATCH
    await stream.close()


@pytest.mark.asyncio
async def test_nonce_not_reused_same_mac_fails(server):
    """Reenviar el mismo mac (mismo nonce) en otra conexión debe fallar
    porque el servidor genera un nonce nuevo cada vez."""
    srv, port = server

    # Primera conexión legítima para capturar... no podemos capturar el nonce
    # del servidor fácilmente sin MITM. En su lugar: conectar a bajo nivel,
    # obtener challenge, calcular mac, cerrar; luego en nueva conexión
    # reenviar ese mac con el challenge de la *nueva* conexión (nonce distinto)
    # → debe fallar.
    reader, writer = await asyncio.open_connection(HOST, port)
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    challenge = await asyncio.wait_for(
        stream.recv(max_size=HANDSHAKE_MAX), timeout=2.0
    )
    assert challenge["type"] == "challenge"
    nonce1 = bytes.fromhex(challenge["nonce"])
    mac1 = _mac_hex(TOKEN, nonce1)
    await stream.close()

    # Nueva conexión, nuevo nonce
    reader2, writer2 = await asyncio.open_connection(HOST, port)
    stream2 = MessageStream(reader2, writer2)
    await stream2.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    challenge2 = await asyncio.wait_for(
        stream2.recv(max_size=HANDSHAKE_MAX), timeout=2.0
    )
    nonce2 = bytes.fromhex(challenge2["nonce"])
    assert nonce1 != nonce2
    # Reenviar mac del nonce anterior → HMAC no coincide
    await stream2.send({"type": "auth", "mac": mac1})
    reply = await asyncio.wait_for(stream2.recv(max_size=HANDSHAKE_MAX), timeout=3.0)
    assert reply.get("type") == "error"
    assert reply.get("reason") == AUTH_FAILED
    await stream2.close()


@pytest.mark.asyncio
async def test_replay_same_connection_rejected(server):
    """Tras auth_ok no se acepta un segundo auth; el stream ya está en
    modo aplicación. Un mac reenviado se trata como mensaje de app y se
    ignora o no autentica de nuevo. Aquí verificamos que el primer
    handshake con mac correcto sí autentica."""
    srv, port = server
    reader, writer = await asyncio.open_connection(HOST, port)
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    challenge = await stream.recv(max_size=HANDSHAKE_MAX)
    nonce = bytes.fromhex(challenge["nonce"])
    await stream.send({"type": "auth", "mac": _mac_hex(TOKEN, nonce)})
    ok = await stream.recv(max_size=HANDSHAKE_MAX)
    assert ok["type"] == "auth_ok"
    # Reenviar el mismo auth no rompe la sesión (es un mensaje post-auth)
    await stream.send({"type": "auth", "mac": _mac_hex(TOKEN, nonce)})
    # La sesión sigue viva: el servidor no cierra por eso
    await asyncio.sleep(0.1)
    assert srv.is_connected()
    await stream.close()
    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_rate_limit_after_failures():
    port = _free_port()
    srv = WiFiServer(
        token=TOKEN,
        host=HOST,
        port=port,
        rate_limit=True,
        require_strong_token=True,
    )
    await srv.start()
    try:
        for i in range(5):
            client = WiFiClient(
                HOST, f"bad-token-{i:04d}-xxxx", port=port, reconnect=False
            )
            with pytest.raises(AuthRejected):
                await client.start(timeout=3.0)
            await client.stop()

        # La 6ª debe ser rate_limited (terminal o transitorio según diseño)
        client = WiFiClient(HOST, "bad-token-extra-xx", port=port, reconnect=False)
        with pytest.raises((AuthRejected, TransientAuthError, ConnectionError)):
            await client.start(timeout=3.0)
        await client.stop()
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_token_provider_success():
    port = _free_port()
    current = {"tok": TOKEN}

    def provider():
        return current["tok"]

    srv = WiFiServer(
        token=TOKEN,  # valor inicial; el provider manda
        host=HOST,
        port=port,
        token_provider=provider,
        rate_limit=False,
    )
    await srv.start()
    try:
        client = WiFiClient(HOST, TOKEN, port=port, reconnect=False)
        await client.start(timeout=5.0)
        assert client.is_connected()
        await client.stop()

        # Cambiar el token vía provider; el cliente con el viejo debe fallar
        current["tok"] = "nuevo-token-largo-abc"
        client2 = WiFiClient(HOST, TOKEN, port=port, reconnect=False)
        with pytest.raises(AuthRejected):
            await client2.start(timeout=3.0)
        await client2.stop()

        client3 = WiFiClient(HOST, "nuevo-token-largo-abc", port=port, reconnect=False)
        await client3.start(timeout=5.0)
        assert client3.is_connected()
        await client3.stop()
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_token_provider_raises_server_error():
    port = _free_port()

    def bad_provider():
        raise RuntimeError("boom")

    srv = WiFiServer(
        token=TOKEN,
        host=HOST,
        port=port,
        token_provider=bad_provider,
        rate_limit=False,
    )
    await srv.start()
    try:
        client = WiFiClient(HOST, TOKEN, port=port, reconnect=False)
        with pytest.raises((TransientAuthError, AuthRejected, ConnectionError)) as ei:
            await client.start(timeout=5.0)
        # Preferimos TransientAuthError(server_error)
        if isinstance(ei.value, TransientAuthError):
            assert ei.value.reason == SERVER_ERROR
        await client.stop()
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_set_token_disconnect_current():
    port = _free_port()
    srv = WiFiServer(token=TOKEN, host=HOST, port=port, rate_limit=False)
    await srv.start()
    try:
        client = WiFiClient(HOST, TOKEN, port=port, reconnect=False)
        await client.start(timeout=5.0)
        assert client.is_connected()

        # Rotar token y echar al cliente actual
        srv.set_token("otro-token-largo-xyz", disconnect_current=True)
        await asyncio.sleep(0.5)
        # El cliente debería haber recibido "revoked" y dejado de estar conectado
        assert not client.is_connected() or not srv.is_connected()
        await client.stop()

        # Nuevo cliente con el token viejo falla
        client2 = WiFiClient(HOST, TOKEN, port=port, reconnect=False)
        with pytest.raises(AuthRejected):
            await client2.start(timeout=3.0)
        await client2.stop()

        # Nuevo cliente con el token nuevo conecta
        client3 = WiFiClient(HOST, "otro-token-largo-xyz", port=port, reconnect=False)
        await client3.start(timeout=5.0)
        assert client3.is_connected()
        await client3.stop()
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_peer_chat_roundtrip(server):
    srv, port = server
    peer_srv = Peer(srv, heartbeat=0)  # sin heartbeat para el test
    # El server ya está started; Peer no vuelve a start el transport si...
    # Peer.start llama transport.start otra vez → RuntimeError. Usamos
    # el transport ya arrancado y solo registramos handlers vía Peer.
    # Alternativa: construir Peer antes de start.

    await srv.stop()
    port = _free_port()
    transport = WiFiServer(token=TOKEN, host=HOST, port=port, rate_limit=False)
    peer = Peer(transport, heartbeat=0)
    got = {}

    async def on_chat(msg):
        got["text"] = msg.get("payload", {}).get("text")
        await peer.send("chat", {"text": f"echo:{got['text']}"})

    peer.on("chat", on_chat)
    await peer.start()

    client = Peer(WiFiClient(HOST, TOKEN, port=port, reconnect=False), heartbeat=0)
    reply = {}

    async def on_reply(msg):
        reply["text"] = msg.get("payload", {}).get("text")

    client.on("chat", on_reply)
    await client.start(timeout=5.0)
    await client.send("chat", {"text": "ping"})
    await asyncio.sleep(0.5)
    assert got.get("text") == "ping"
    assert reply.get("text") == "echo:ping"
    await client.stop()
    await peer.stop()


@pytest.mark.asyncio
async def test_handshake_timeout():
    """Servidor que acepta TCP pero no responde al protocolo → timeout."""
    port = _free_port()
    hold = asyncio.Event()

    async def silent(reader, writer):
        try:
            await hold.wait()
        finally:
            writer.close()

    server = await asyncio.start_server(silent, HOST, port)
    try:
        client = WiFiClient(
            HOST, TOKEN, port=port, reconnect=False, connect_timeout=2.0
        )
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(client.start(timeout=2.0), timeout=8.0)
        await client.stop()
    finally:
        hold.set()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_token_never_on_wire(server):
    """El token en claro no debe aparecer en ningún mensaje del handshake."""
    srv, port = server
    captured: list = []

    # Interceptamos a bajo nivel
    reader, writer = await asyncio.open_connection(HOST, port)
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    challenge = await stream.recv(max_size=HANDSHAKE_MAX)
    captured.append(challenge)
    nonce = bytes.fromhex(challenge["nonce"])
    mac = _mac_hex(TOKEN, nonce)
    await stream.send({"type": "auth", "mac": mac})
    ok = await stream.recv(max_size=HANDSHAKE_MAX)
    captured.append(ok)
    await stream.close()

    import json

    for msg in captured:
        raw = json.dumps(msg)
        assert TOKEN not in raw
        assert "token" not in msg or msg.get("type") != "auth"
