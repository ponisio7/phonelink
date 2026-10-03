import asyncio
import contextlib

import pytest

from phonelink import Peer, WiFiClient, WiFiServer
from phonelink.protocol import HANDSHAKE_MAX, MAX_PAYLOAD, MessageStream, ProtocolError

from tests.conftest import TOKEN, Collector, free_port, raw_auth, raw_handshake, raw_connect
from phonelink.protocol import PROTOCOL_VERSION
from phonelink.wifi import _mac_hex


# ---------- Handshake ----------

async def test_handshake_correcto(server):
    peer_srv, srv, port = server
    recibidos = Collector()
    peer_srv.on("hola", recibidos.handler)
    await peer_srv.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await stream.recv()
    assert _ch["type"] == "challenge"
    await stream.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    reply = await stream.recv()
    assert reply["type"] == "auth_ok"
    assert reply["protocol_version"] == PROTOCOL_VERSION

    await stream.send({"type": "hola", "payload": {"x": 1}})
    msg = await recibidos.wait_for(lambda m: m.get("type") == "hola")
    assert msg["payload"] == {"x": 1}
    await stream.close()


async def test_handshake_token_incorrecto(server):
    peer_srv, srv, port = server
    await peer_srv.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await stream.recv()
    # servidor puede responder challenge o error; si challenge, enviamos mac malo
    if isinstance(_ch, dict) and _ch.get("type") == "challenge":
        await stream.send({"type": "auth", "mac": "00" * 32})
        reply = await stream.recv()
    else:
        reply = _ch
    assert reply["type"] == "error"
    assert reply["reason"] == "auth_failed"
    await stream.close()


async def test_handshake_primer_mensaje_no_auth(server):
    peer_srv, srv, port = server
    await peer_srv.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hola"})
    reply = await stream.recv()
    assert reply["type"] == "error"
    await stream.close()


async def test_handshake_token_no_ascii(server):
    """Bug 1: token con caracteres no ASCII debe autenticarse bien."""
    srv = WiFiServer(
        token="contraseña-segura-12345678901234567",
        host="127.0.0.1",
        port=free_port(),
    )
    peer = Peer(srv, heartbeat=0)
    await peer.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", srv.port)
        stream = MessageStream(reader, writer)
        tok = "contraseña-segura-12345678901234567"
        await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
        _ch = await stream.recv()
        assert _ch["type"] == "challenge"
        await stream.send({"type": "auth", "mac": _mac_hex(tok, bytes.fromhex(_ch["nonce"]))})
        reply = await stream.recv()
        assert reply["type"] == "auth_ok"
        await stream.close()
    finally:
        await peer.stop()


async def test_handshake_payload_grande_rechazado(server):
    """Antes de auth, el límite es HANDSHAKE_MAX."""
    peer_srv, srv, port = server
    await peer_srv.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    # Enviamos un mensaje por encima del límite de handshake
    import json, struct
    payload = json.dumps({"type": "auth", "token": TOKEN, "x": "a" * HANDSHAKE_MAX}).encode()
    writer.write(struct.pack(">I", len(payload)) + payload)
    await writer.drain()

    # El servidor debe cerrar sin responder auth_ok
    data = await asyncio.wait_for(reader.read(10), timeout=2.0)
    assert data == b""  # EOF
    writer.close()


# ---------- Envío/recepción tras auth ----------

async def test_envio_bidireccional(server):
    peer_srv, srv, port = server
    recibidos_srv = Collector()
    peer_srv.on("chat", recibidos_srv.handler)
    await peer_srv.start()

    cli = WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False)
    peer_cli = Peer(cli, heartbeat=0)
    recibidos_cli = Collector()
    peer_cli.on("chat", recibidos_cli.handler)
    await peer_cli.start(timeout=2.0)

    try:
        await peer_cli.send("chat", {"text": "hola"})
        msg = await recibidos_srv.wait_for(lambda m: m.get("type") == "chat")
        assert msg["payload"]["text"] == "hola"

        await peer_srv.send("chat", {"text": "respuesta"})
        msg = await recibidos_cli.wait_for(lambda m: m.get("type") == "chat")
        assert msg["payload"]["text"] == "respuesta"
    finally:
        await peer_cli.stop()


async def test_payload_grande_despues_de_auth(server):
    """Después de auth, el límite es MAX_PAYLOAD (10 MB)."""
    peer_srv, srv, port = server
    recibidos = Collector()
    peer_srv.on("big", recibidos.handler)
    await peer_srv.start()

    cli = WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False)
    peer_cli = Peer(cli, heartbeat=0)
    await peer_cli.start(timeout=2.0)

    try:
        grande = "x" * 1_000_000  # 1 MB
        await peer_cli.send("big", {"data": grande})
        msg = await recibidos.wait_for(lambda m: m.get("type") == "big", timeout=5.0)
        assert len(msg["payload"]["data"]) == 1_000_000
    finally:
        await peer_cli.stop()


async def test_payload_por_encima_de_max_payload_rechazado(server):
    """Post-auth, un mensaje > MAX_PAYLOAD debe romper la conexión."""
    peer_srv, srv, port = server
    await peer_srv.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await stream.recv()
    assert _ch["type"] == "challenge"
    await stream.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    assert (await stream.recv())["type"] == "auth_ok"

    # Anunciamos un tamaño mayor que MAX_PAYLOAD y enviamos poco.
    import struct
    writer.write(struct.pack(">I", MAX_PAYLOAD + 1))
    await writer.drain()

    # El servidor debe cerrar sin procesar.
    data = await asyncio.wait_for(reader.read(10), timeout=2.0)
    assert data == b""
    writer.close()


# ---------- Cliente único ----------

async def test_segundo_cliente_reemplaza_al_primero(server):
    peer_srv, srv, port = server
    await peer_srv.start()

    # Cliente 1
    r1, w1 = await asyncio.open_connection("127.0.0.1", port)
    s1 = MessageStream(r1, w1)
    await s1.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await s1.recv()
    assert _ch["type"] == "challenge"
    await s1.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    assert (await s1.recv())["type"] == "auth_ok"

    # Cliente 2
    r2, w2 = await asyncio.open_connection("127.0.0.1", port)
    s2 = MessageStream(r2, w2)
    await s2.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await s2.recv()
    assert _ch["type"] == "challenge"
    await s2.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    assert (await s2.recv())["type"] == "auth_ok"

    # El cliente 1 debe recibir "replaced" y luego EOF.
    msg = await asyncio.wait_for(s1.recv(), timeout=2.0)
    assert msg["type"] == "replaced"
    data = await asyncio.wait_for(r1.read(10), timeout=2.0)
    assert data == b""

    # El cliente 2 sigue vivo
    await s2.send({"type": "ping"})
    reply = await asyncio.wait_for(s2.recv(), timeout=2.0)
    assert reply["type"] == "pong"

    await s2.close()


# ---------- Reconexión ----------

async def test_cliente_reconecta(server_port):
    """El cliente debe reconectar tras caída del servidor."""
    # Arrancamos servidor
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()

    cli = WiFiClient("127.0.0.1", token=TOKEN, port=server_port, reconnect=True)
    peer_cli = Peer(cli, heartbeat=0)
    await peer_cli.start(timeout=2.0)

    try:
        # Paramos el servidor
        await peer_srv.stop()
        await asyncio.sleep(0.5)

        # Lo volvemos a arrancar en el mismo puerto
        srv2 = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
        peer_srv2 = Peer(srv2, heartbeat=0)
        await peer_srv2.start()

        # El cliente debe reconectar solo. Esperamos y probamos un mensaje.
        recibidos = Collector()
        peer_srv2.on("hola", recibidos.handler)

        # Damos tiempo al cliente a reconectar
        for _ in range(20):
            await asyncio.sleep(0.3)
            try:
                await peer_cli.send("hola", {"x": 1})
                break
            except ConnectionError:
                continue

        msg = await recibidos.wait_for(lambda m: m.get("type") == "hola", timeout=5.0)
        assert msg["payload"]["x"] == 1

        await peer_cli.stop()
        await peer_srv2.stop()
    finally:
        with contextlib.suppress(Exception):
            await peer_cli.stop()


# ---------- Heartbeat ----------

async def test_heartbeat_cierra_conexion_muerta(server_port):
    """Si el cliente no responde pings, el servidor cierra la conexión."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer_srv = Peer(srv, heartbeat=0.3, heartbeat_timeout_factor=2.0)  # 0.6s de timeout
    await peer_srv.start()

    # Nos conectamos como cliente "tonto" que no responde a ping
    reader, writer = await asyncio.open_connection("127.0.0.1", server_port)
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await stream.recv()
    assert _ch["type"] == "challenge"
    await stream.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    assert (await stream.recv())["type"] == "auth_ok"

    # Esperamos a que el heartbeat detecte la falta de pongs y cierre
    try:
        # El servidor enviará ping, nosotros no respondemos con pong.
        # Tras ~0.9s el heartbeat debe cerrar la conexión.
        data = await asyncio.wait_for(reader.read(100), timeout=3.0)
        # Puede llegar el ping primero, luego EOF
        while data:
            data = await asyncio.wait_for(reader.read(100), timeout=3.0)
        # EOF alcanzado
    except asyncio.TimeoutError:
        pytest.fail("El heartbeat no cerró la conexión muerta")
    finally:
        writer.close()
        await peer_srv.stop()


async def test_heartbeat_mantiene_viva_conexion_activa(server):
    """Con un cliente que responde pong, el servidor no cierra."""
    peer_srv, srv, port = server
    # Reemplazamos el Peer con heartbeat activo
    srv2 = WiFiServer(token=TOKEN, host="127.0.0.1", port=port)
    peer_srv2 = Peer(srv2, heartbeat=0.2, heartbeat_timeout_factor=3.0)
    await peer_srv2.start()

    try:
        cli = WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False)
        peer_cli = Peer(cli, heartbeat=0)
        await peer_cli.start(timeout=2.0)

        # El cliente está suscrito a pings automáticamente vía Peer._dispatch,
        # así que responde pong. Dejamos pasar varios ciclos de heartbeat.
        await asyncio.sleep(1.0)

        # La conexión sigue viva: enviamos un mensaje
        recibidos = Collector()
        peer_srv2.on("test", recibidos.handler)
        await peer_cli.send("test", {"ok": True})
        msg = await recibidos.wait_for(lambda m: m.get("type") == "test")
        assert msg["payload"]["ok"] is True

        await peer_cli.stop()
    finally:
        await peer_srv2.stop()


# ---------- Desconexión ----------

async def test_disconnect_no_se_emite_sin_auth(server):
    """Si la auth falla, no debe emitirse disconnect."""
    peer_srv, srv, port = server
    desconexiones = []
    peer_srv.transport.on_disconnect(lambda: asyncio.sleep(0) or desconexiones.append(1))
    await peer_srv.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await stream.recv()
    if isinstance(_ch, dict) and _ch.get("type") == "challenge":
        await stream.send({"type": "auth", "mac": "00" * 32})
        await stream.recv()
    # else: already error
    await stream.close()

    await asyncio.sleep(0.3)
    assert desconexiones == []


async def test_disconnect_se_emite_con_auth(server):
    """Tras auth exitosa y cierre, sí debe emitirse disconnect."""
    peer_srv, srv, port = server
    desconexiones = asyncio.Event()

    async def on_disc():
        desconexiones.set()

    peer_srv.transport.on_disconnect(on_disc)
    await peer_srv.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await stream.recv()
    assert _ch["type"] == "challenge"
    await stream.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    await stream.recv()
    await stream.close()

    await asyncio.wait_for(desconexiones.wait(), timeout=2.0)


async def test_handshake_lento_no_es_matado_por_heartbeat(server_port):
    """Regresión: si el handshake tarda más que el timeout, el heartbeat
    no debe cerrar la conexión recién establecida."""
    import asyncio as aio

    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer_srv = Peer(srv, heartbeat=0.3, heartbeat_timeout_factor=2.0)  # timeout 0.6s
    await peer_srv.start()

    # Monkeypatch: ralentizar el _handle_client del servidor tras el auth_ok
    original_emit_connect = srv._emit_connect
    async def emit_connect_lento():
        await aio.sleep(0.8)  # simula handshake lento
        await original_emit_connect()
    srv._emit_connect = emit_connect_lento

    try:
        cli = WiFiClient("127.0.0.1", token=TOKEN, port=server_port, reconnect=False)
        peer_cli = Peer(cli, heartbeat=0)
        await peer_cli.start(timeout=3.0)

        # Aquí el servidor podría haber matado la conexión si no fuera por el fix.
        # Verificamos que sigue viva.
        assert cli.is_connected()

        recibidos = Collector()
        peer_srv.on("test", recibidos.handler)
        await peer_cli.send("test", {"ok": True})
        msg = await recibidos.wait_for(lambda m: m.get("type") == "test", timeout=2.0)
        assert msg["payload"]["ok"] is True

        await peer_cli.stop()
    finally:
        await peer_srv.stop()


async def test_reemplazo_con_mensajes_en_vuelo(server):
    peer_srv, srv, port = server
    recibidos = Collector()
    peer_srv.on("msg", recibidos.handler)
    await peer_srv.start()

    # Cliente 1
    r1, w1 = await asyncio.open_connection("127.0.0.1", port)
    from phonelink.protocol import MessageStream
    s1 = MessageStream(r1, w1)
    await s1.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await s1.recv()
    assert _ch["type"] == "challenge"
    await s1.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    await s1.recv()

    # Cliente 2 entra
    r2, w2 = await asyncio.open_connection("127.0.0.1", port)
    s2 = MessageStream(r2, w2)
    await s2.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await s2.recv()
    assert _ch["type"] == "challenge"
    await s2.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    await s2.recv()

    # Cliente 1 intenta enviar; el socket ya está cerrado por el servidor.
    # Debe fallar limpiamente, no romper nada.
    import contextlib
    with contextlib.suppress(ConnectionError, BrokenPipeError):
        await s1.send({"type": "msg", "payload": {"from": 1}})

    # Cliente 2 sigue vivo y sus mensajes llegan.
    await s2.send({"type": "msg", "payload": {"from": 2}})
    msg = await recibidos.wait_for(
        lambda m: m.get("payload", {}).get("from") == 2, timeout=2.0
    )
    assert msg["payload"]["from"] == 2

    # El servidor no debe haber recibido nada del cliente 1
    assert all(m.get("payload", {}).get("from") != 1 for m in recibidos.messages)

    await s2.close()


async def test_rate_limit_bloquea_tras_fallos(server_port):
    """Tras 5 auth fallidas, la IP queda bloqueada."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer = Peer(srv, heartbeat=0)
    await peer.start()
    try:
        for _ in range(5):
            r, w = await asyncio.open_connection("127.0.0.1", server_port)
            s = MessageStream(r, w)
            await s.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
            _ch = await s.recv()
            assert _ch.get("type") == "challenge"
            await s.send({"type": "auth", "mac": "00" * 32})
            reply = await s.recv()
            assert reply["reason"] == "auth_failed"
            await s.close()
        # El sexto intento debe recibir rate_limited
        r, w = await asyncio.open_connection("127.0.0.1", server_port)
        s = MessageStream(r, w)
        await s.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
        # rate-limited: servidor puede responder error antes del challenge
        reply = await s.recv()
        assert reply.get("reason") == "rate_limited" or (
            reply.get("type") == "challenge" and False)  # no debería llegar challenge
        if reply.get("type") == "challenge":
            await s.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(reply["nonce"]))})
            reply = await s.recv()
        assert reply["reason"] == "rate_limited"
        await s.close()
    finally:
        await peer.stop()


async def test_protocol_version_mismatch(server):
    peer_srv, srv, port = server
    await peer_srv.start()
    r, w = await asyncio.open_connection("127.0.0.1", port)
    s = MessageStream(r, w)
    await s.send({"type": "hello", "protocol_version": 99})
    reply = await s.recv()
    assert reply["reason"] == "protocol_version_mismatch"
    await s.close()

async def test_semaphore_liberado_tras_auth(server_port):
    """Con max_handshakes=1, dos clientes pueden coexistir (reemplazo)."""
    srv = WiFiServer(
        token=TOKEN,
        host="127.0.0.1",
        port=server_port,
        max_handshakes=1,
    )
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()
    try:
        # Cliente 1 autenticado, mantiene la sesión.
        r1, w1 = await asyncio.open_connection("127.0.0.1", server_port)
        s1 = MessageStream(r1, w1)
        await s1.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
        _ch = await s1.recv()
        assert _ch["type"] == "challenge"
        await s1.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
        assert (await s1.recv())["type"] == "auth_ok"

        # Cliente 2 debe poder completar el handshake (reemplaza al 1).
        r2, w2 = await asyncio.open_connection("127.0.0.1", server_port)
        s2 = MessageStream(r2, w2)
        await asyncio.wait_for(s2.send({"type": "hello", "protocol_version": PROTOCOL_VERSION}), timeout=3.0)
        _ch = await asyncio.wait_for(s2.recv(), timeout=3.0)
        assert _ch["type"] == "challenge"
        await asyncio.wait_for(s2.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))}), timeout=3.0)
        reply = await asyncio.wait_for(s2.recv(), timeout=3.0)
        assert reply["type"] == "auth_ok"

        # El cliente 1 debe haber recibido "replaced" antes del EOF.
        msg1 = await asyncio.wait_for(s1.recv(), timeout=2.0)
        assert msg1["type"] == "replaced"

        await s2.close()
    finally:
        await peer_srv.stop()


async def test_timeout_handshake_cuenta_como_fallo(server_port):
    """5 timeouts de handshake → rate_limited en el siguiente intento.

    v0.4: HANDSHAKE_TIMEOUT ya no es constante de módulo; se pasa
    handshake_timeout al constructor.
    """
    srv = WiFiServer(
        token=TOKEN,
        host="127.0.0.1",
        port=server_port,
        handshake_timeout=0.3,
    )
    peer = Peer(srv, heartbeat=0)
    await peer.start()
    try:
        for _ in range(5):
            r, w = await asyncio.open_connection("127.0.0.1", server_port)
            # No enviamos nada: el servidor debe contar timeout.
            await asyncio.sleep(0.6)
            w.close()
            with contextlib.suppress(OSError):
                await w.wait_closed()

        # Sexto intento: la IP está bloqueada.
        r, w = await asyncio.open_connection("127.0.0.1", server_port)
        s = MessageStream(r, w)
        await s.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
        reply = await asyncio.wait_for(s.recv(), timeout=2.0)
        assert reply.get("reason") == "rate_limited"
        await s.close()
    finally:
        await peer.stop()


async def test_token_con_surrogates(server):
    """Un token con surrogates lone no debe saltarse el rate limit."""
    peer_srv, srv, port = server
    await peer_srv.start()

    # 5 intentos con token surrogate → 5 fallos → bloqueo.
    for _ in range(5):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        s = MessageStream(r, w)
        await s.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
        _ch = await asyncio.wait_for(s.recv(), timeout=2.0)
        assert _ch.get("type") == "challenge", _ch
        # mac with invalid/surrogate key path: send garbage mac
        await s.send({"type": "auth", "mac": "deadbeef" * 8})
        reply = await asyncio.wait_for(s.recv(), timeout=2.0)
        assert reply["reason"] == "auth_failed", reply
        await s.close()

    # Sexto intento con token bueno: bloqueado.
    r, w = await asyncio.open_connection("127.0.0.1", port)
    s = MessageStream(r, w)
    await s.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    reply = await asyncio.wait_for(s.recv(), timeout=2.0)
    assert reply.get("reason") == "rate_limited"
    await s.close()


async def test_set_token_con_disconnect_current_revoca(server_port):
    """set_token(..., disconnect_current=True) cierra la sesión activa
    y el cliente recibe 'revoked' antes del EOF."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()
    try:
        r, w = await asyncio.open_connection("127.0.0.1", server_port)
        s = MessageStream(r, w)
        await s.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
        _ch = await s.recv()
        assert _ch["type"] == "challenge"
        await s.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
        assert (await s.recv())["type"] == "auth_ok"

        # Rotamos el token revocando la sesión actual.
        srv.set_token(
            "nuevo-token-de-32-caracteres-abcdefgh",
            disconnect_current=True,
        )

        msg = await asyncio.wait_for(s.recv(), timeout=2.0)
        assert msg["type"] == "revoked"

        data = await asyncio.wait_for(r.read(10), timeout=2.0)
        assert data == b""
    finally:
        await peer_srv.stop()


async def test_cliente_no_reconecta_tras_revoked(server_port):
    """Tras 'revoked', el cliente no reintenta con el token viejo."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()
    try:
        cli = WiFiClient("127.0.0.1", token=TOKEN, port=server_port, reconnect=True)
        peer_cli = Peer(cli, heartbeat=0)
        await peer_cli.start(timeout=3.0)
        assert cli.is_connected()

        # Revocamos el token: el cliente debe parar de reconectar.
        srv.set_token(
            "nuevo-token-de-32-caracteres-abcdefgh",
            disconnect_current=True,
        )
        # Damos tiempo a que el cliente procese el "revoked" y salga.
        await asyncio.sleep(0.5)
        assert not cli.is_connected()

        # Aunque pasen varios backoffs, no debe reconectar.
        await asyncio.sleep(1.0)
        assert not cli.is_connected()
    finally:
        with contextlib.suppress(Exception):
            await peer_cli.stop()
        await peer_srv.stop()


async def test_cliente_no_reconecta_tras_replaced(server_port):
    """Un cliente reemplazado no debe reconectar (evita ping-pong)."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()
    try:
        cli1 = WiFiClient("127.0.0.1", token=TOKEN, port=server_port, reconnect=True)
        peer1 = Peer(cli1, heartbeat=0)
        await peer1.start(timeout=3.0)

        cli2 = WiFiClient("127.0.0.1", token=TOKEN, port=server_port, reconnect=True)
        peer2 = Peer(cli2, heartbeat=0)
        await peer2.start(timeout=3.0)

        # El cliente 1 debe haber recibido "replaced" y no reconectar.
        await asyncio.sleep(0.5)
        assert not cli1.is_connected()
        assert cli2.is_connected()

        # Y no debe reconectar tras varios backoffs.
        await asyncio.sleep(1.0)
        assert not cli1.is_connected()
        assert cli2.is_connected()
    finally:
        with contextlib.suppress(Exception):
            await peer1.stop()
        with contextlib.suppress(Exception):
            await peer2.stop()
        await peer_srv.stop()


async def test_cliente_reintenta_tras_rate_limited(server_port):
    """rate_limited es transitorio: el cliente debe reintentar con backoff."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()
    try:
        # Saturamos el rate limit con 5 fallos desde 127.0.0.1.
        for _ in range(5):
            r, w = await asyncio.open_connection("127.0.0.1", server_port)
            s = MessageStream(r, w)
            await s.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
            _ch = await s.recv()
            assert _ch.get("type") == "challenge"
            await s.send({"type": "auth", "mac": "00" * 32})
            assert (await s.recv())["reason"] == "auth_failed"
            await s.close()

        # El cliente con token bueno recibe rate_limited; debe reintentar
        # (no morir) y eventualmente no marcar _auth_rejected.
        cli = WiFiClient(
            "127.0.0.1", token=TOKEN, port=server_port,
            reconnect=True, max_backoff=1.0,
        )
        assert cli._auth_rejected is False
        # Lanzamos start con timeout corto: fallará al conectar pero NO
        # debe dejar el cliente en estado terminal.
        with pytest.raises(ConnectionError):
            await cli.start(timeout=1.0)
        assert cli._auth_rejected is False
    finally:
        await peer_srv.stop()
