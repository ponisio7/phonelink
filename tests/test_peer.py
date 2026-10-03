import asyncio
import contextlib

import pytest

from phonelink import Peer, WiFiClient, WiFiServer

from tests.conftest import TOKEN, Collector, free_port, raw_auth
from phonelink.protocol import PROTOCOL_VERSION
from phonelink.wifi import _mac_hex


async def test_handler_async_se_ejecuta(server):
    peer_srv, srv, port = server
    recibidos = Collector()
    peer_srv.on("evt", recibidos.handler)
    await peer_srv.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    from phonelink.protocol import MessageStream
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await stream.recv()
    await stream.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    await stream.recv()
    await stream.send({"type": "evt", "payload": {"a": 1}})

    msg = await recibidos.wait_for(lambda m: m.get("type") == "evt")
    assert msg["payload"] == {"a": 1}
    await stream.close()


async def test_handler_que_lanza_no_rompe_conexion(server):
    """Bug 3: una excepción en un handler no debe cerrar la conexión."""
    peer_srv, srv, port = server

    async def handler_malo(msg):
        raise RuntimeError("boom")

    recibidos = Collector()
    peer_srv.on("malo", handler_malo)
    peer_srv.on("bueno", recibidos.handler)
    await peer_srv.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    from phonelink.protocol import MessageStream
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await stream.recv()
    await stream.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    await stream.recv()

    await stream.send({"type": "malo"})
    await asyncio.sleep(0.2)
    # La conexión debe seguir viva
    await stream.send({"type": "bueno", "payload": {"ok": True}})
    msg = await recibidos.wait_for(lambda m: m.get("type") == "bueno")
    assert msg["payload"]["ok"] is True
    await stream.close()


async def test_handler_lento_no_bloquea_pongs(server):
    """Un handler que duerme no debe impedir el pong del heartbeat."""
    peer_srv, srv, port = server
    # Peer con heartbeat activo
    srv2 = WiFiServer(token=TOKEN, host="127.0.0.1", port=port)
    peer_srv2 = Peer(srv2, heartbeat=0.2, heartbeat_timeout_factor=3.0)

    async def handler_lento(msg):
        await asyncio.sleep(2.0)

    peer_srv2.on("lento", handler_lento)
    await peer_srv2.start()

    try:
        # Cliente con heartbeat desactivado (no emite pings propios, pero
        # responde a los pings del servidor automáticamente vía Peer).
        cli = WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False)
        peer_cli = Peer(cli, heartbeat=0)
        await peer_cli.start(timeout=2.0)

        # Enviamos un evento lento. El handler duerme 2s.
        await peer_cli.send("lento", {"x": 1})

        # Mientras duerme, el servidor sigue enviando pings y el cliente
        # responde pong (lo hace Peer._dispatch automáticamente).
        # Si el heartbeat del servidor estuviera bloqueado por el handler,
        # cerraría la conexión. Esperamos 1s (más que varios ciclos).
        await asyncio.sleep(1.0)

        # La conexión debe seguir viva
        recibidos = Collector()
        peer_cli.on("eco", recibidos.handler)
        await peer_srv2.send("eco", {"ok": True})
        msg = await recibidos.wait_for(lambda m: m.get("type") == "eco")
        assert msg["payload"]["ok"] is True

        await peer_cli.stop()
    finally:
        await peer_srv2.stop()


async def test_ping_responde_pong_automaticamente(server):
    """El Peer responde pong a ping sin que el usuario registre handler."""
    peer_srv, srv, port = server
    await peer_srv.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    from phonelink.protocol import MessageStream
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await stream.recv()
    await stream.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    await stream.recv()

    await stream.send({"type": "ping"})
    reply = await asyncio.wait_for(stream.recv(), timeout=2.0)
    assert reply["type"] == "pong"
    await stream.close()


async def test_stop_cancela_handlers_pendientes(server):
    """stop() debe cancelar handlers en vuelo."""
    peer_srv, srv, port = server
    cancelado = asyncio.Event()

    async def handler_largo(msg):
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelado.set()
            raise

    peer_srv.on("largo", handler_largo)
    await peer_srv.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    from phonelink.protocol import MessageStream
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await stream.recv()
    await stream.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    await stream.recv()
    await stream.send({"type": "largo"})

    # Damos tiempo a que el handler arranque
    await asyncio.sleep(0.2)
    await peer_srv.stop()

    await asyncio.wait_for(cancelado.wait(), timeout=2.0)
    with contextlib.suppress(Exception):
        await stream.close()


async def test_limite_handlers_concurrentes(server):
    """Si se acumulan handlers, los nuevos se descartan con warning."""
    import phonelink.peer as peer_mod

    peer_srv, srv, port = server
    recibidos = Collector()

    async def handler_bloqueante(msg):
        await asyncio.sleep(5.0)

    peer_srv.on("bloqueante", handler_bloqueante)
    peer_srv.on("normal", recibidos.handler)
    await peer_srv.start()

    # Conexión cruda para saturar sin pasar por Peer del cliente.
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    from phonelink.protocol import MessageStream
    stream = MessageStream(reader, writer)
    await stream.send({"type": "hello", "protocol_version": PROTOCOL_VERSION})
    _ch = await stream.recv()
    await stream.send({"type": "auth", "mac": _mac_hex(TOKEN, bytes.fromhex(_ch["nonce"]))})
    await stream.recv()

    # Lanzamos más mensajes de los que el límite permite.
    total = peer_mod.MAX_PENDING_HANDLERS + 10
    for _ in range(total):
        await stream.send({"type": "bloqueante"})
    await asyncio.sleep(0.3)

    # El número de handlers vivos no debe superar el límite.
    assert len(peer_srv._handler_tasks) <= peer_mod.MAX_PENDING_HANDLERS
    assert len(peer_srv._handler_tasks) == peer_mod.MAX_PENDING_HANDLERS

    # La conexión sigue viva: ping/pong no pasa por el límite de handlers.
    await stream.send({"type": "ping"})
    reply = await asyncio.wait_for(stream.recv(), timeout=2.0)
    assert reply["type"] == "pong"

    # Liberamos un slot cancelando un handler y entonces un mensaje normal llega.
    task = next(iter(peer_srv._handler_tasks))
    task.cancel()
    await asyncio.sleep(0.1)
    await stream.send({"type": "normal", "payload": {"ok": True}})
    msg = await recibidos.wait_for(lambda m: m.get("type") == "normal")
    assert msg["payload"]["ok"] is True

    with contextlib.suppress(Exception):
        await stream.close()


async def test_start_kwarg_desconocido_falla(server):
    peer_srv, srv, port = server
    with pytest.raises(TypeError):
        await peer_srv.start(timout=5)  # typo a propósito
