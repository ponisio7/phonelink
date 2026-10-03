"""Regresiones de la revisión previa a publicación (puntos 1, 2 y 3)."""

import asyncio
import contextlib
import time

import pytest

from phonelink import AuthRejected, Peer, TransientAuthError, WiFiClient, WiFiServer
from phonelink import wifi
from phonelink.protocol import MessageStream

from tests.conftest import TOKEN, raw_auth, raw_handshake, raw_connect


# --------------------------------------------------------------------- #1
async def test_start_lanza_auth_rejected_con_token_incorrecto(server):
    """start() debe propagar AuthRejected (antes: ConnectionError genérico)."""
    peer_srv, srv, port = server
    await peer_srv.start()

    cli = WiFiClient("127.0.0.1", token="otro-token-12345678901234567890",
                     port=port, reconnect=True)
    peer_cli = Peer(cli, heartbeat=0)
    with pytest.raises(AuthRejected) as info:
        await peer_cli.start(timeout=3.0)
    assert info.value.reason == "auth_failed"
    # Tras un start fallido el cliente queda limpio y reutilizable.
    assert cli._running is False


async def test_start_con_rate_limit_no_es_auth_rejected(server_port):
    """rate_limited es transitorio: start() NO debe lanzar AuthRejected."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()
    try:
        # 5 fallos concurrentes desde 127.0.0.1 -> bloqueo.
        async def fallo():
            s, reply = await raw_handshake(server_port, token="x" * 20)
            assert reply.get("reason") == "auth_failed" or reply.get("type") == "error"
            await s.close()

        await asyncio.gather(*[fallo() for _ in range(5)])

        cli = WiFiClient("127.0.0.1", token=TOKEN, port=server_port,
                         reconnect=True)
        peer_cli = Peer(cli, heartbeat=0)
        with pytest.raises(ConnectionError) as info:
            await peer_cli.start(timeout=1.5)
        assert not isinstance(info.value, AuthRejected)
        assert isinstance(info.value.__cause__, TransientAuthError)
        await peer_cli.stop()
    finally:
        await peer_srv.stop()


# --------------------------------------------------------------------- #2
async def test_callback_de_conexion_que_lanza_no_deja_stream_zombi(server_port):
    """Si on_connect lanza, is_connected() debe volver a False."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)

    async def boom() -> None:
        raise RuntimeError("callback roto")

    srv.on_connect(boom)
    await srv.start()
    try:
        stream = await raw_auth(server_port)
        # auth_ok ya consumido por raw_auth; el callback boom cierra la sesión.
        with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
            await asyncio.wait_for(stream.recv(), timeout=2.0)
        await asyncio.sleep(0.1)
        assert srv.is_connected() is False
        await stream.close()
    finally:
        await srv.stop()


# --------------------------------------------------------------------- #3
async def test_limite_preauth_rechaza_en_lugar_de_encolar(server_port):
    """Con el tope lleno, la conexión extra se cierra al instante.

    v0.4: MAX_PREAUTH_CONNECTIONS ya no es constante de módulo; se pasa
    max_preauth_connections al constructor.
    """
    srv = WiFiServer(
        token=TOKEN,
        host="127.0.0.1",
        port=server_port,
        max_preauth_connections=2,
        preauth_sem_timeout=0.3,
    )
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()
    holders = []
    try:
        # Dos conexiones que no envían nada ocupan todos los slots.
        for _ in range(2):
            holders.append(await raw_connect(server_port))
        await asyncio.sleep(0.2)

        extra = await raw_connect(server_port)
        # Antes: quedaba encolada hasta que un holder expiraba (5 s).
        with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
            await asyncio.wait_for(extra.recv(), timeout=1.0)
        await extra.close()

        # Al liberar los slots, un cliente legítimo vuelve a entrar.
        for h in holders:
            await h.close()
        holders.clear()
        await asyncio.sleep(0.3)

        cli = WiFiClient("127.0.0.1", token=TOKEN, port=server_port,
                         reconnect=False)
        peer_cli = Peer(cli, heartbeat=0)
        await peer_cli.start(timeout=2.0)
        await peer_cli.stop()
    finally:
        for h in holders:
            with contextlib.suppress(Exception):
                await h.close()
        await peer_srv.stop()


async def test_retardo_de_auth_fallida_no_bloquea_slot_de_handshake(server_port):
    """Un fallo de auth no debe retener el único slot de handshake.

    v0.4: AUTH_FAIL_DELAY ya no es constante de módulo; se pasa
    auth_fail_delay al constructor. El sleep ocurre FUERA de los semáforos.
    """
    auth_fail_delay = 0.5
    srv = WiFiServer(
        token=TOKEN,
        host="127.0.0.1",
        port=server_port,
        max_handshakes=1,
        rate_limit=False,
        auth_fail_delay=auth_fail_delay,
    )
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()
    try:
        malo_stream, _ = await raw_handshake(server_port, token="x" * 20)
        malo = malo_stream
        await asyncio.sleep(0.05)  # el malo ya salió del semáforo

        t0 = time.monotonic()
        bueno, reply = await raw_handshake(server_port)
        elapsed = time.monotonic() - t0

        assert reply["type"] == "auth_ok"
        # Antes: ~0,45 s (esperaba al sleep del malo dentro del semáforo).
        assert elapsed < auth_fail_delay * 0.6, elapsed

        await malo.close()
        await bueno.close()
    finally:
        await peer_srv.stop()