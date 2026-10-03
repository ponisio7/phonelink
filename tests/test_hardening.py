"""Regresiones del parche A+B: robustez de set_token/token_provider,
zeroconf opt-in, eventos reservados y rechazo de TLS sin verificación."""

import asyncio
import contextlib
import logging
import ssl

import pytest

from phonelink import AuthRejected, Peer, TransientAuthError, WiFiClient, WiFiServer
from phonelink import wifi
from phonelink.peer import RESERVED_EVENTS
from phonelink.protocol import MessageStream

from tests.conftest import TOKEN, raw_auth, raw_handshake, raw_connect

NUEVO_TOKEN = "nuevo-token-1234567890123456789012"


# ------------------------------------------------------------------ A1
async def test_set_token_dos_veces_y_stop_espera_la_revocacion(server_port):
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    await srv.start()
    stream = None
    try:
        stream = await raw_auth(server_port)
        await asyncio.sleep(0.1)

        srv.set_token(NUEVO_TOKEN, disconnect_current=True)
        srv.set_token(NUEVO_TOKEN, disconnect_current=True)  # rápido, 2ª vez
        assert len(srv._revoke_tasks) >= 1  # referencias retenidas

        await srv.stop()  # debe esperar a que se entregue "revoked"
        assert srv._revoke_tasks == set()

        assert await asyncio.wait_for(stream.recv(), timeout=2.0) == {
            "type": "revoked"
        }
        with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
            await asyncio.wait_for(stream.recv(), timeout=2.0)
    finally:
        if stream is not None:
            await stream.close()
        await srv.stop()


async def test_set_token_fuera_del_loop_falla_sin_mutar_el_token(server_port):
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    with pytest.raises(RuntimeError, match="event loop"):
        await asyncio.to_thread(
            lambda: srv.set_token(NUEVO_TOKEN, disconnect_current=True)
        )
    # Antes: el token ya había cambiado cuando create_task() fallaba.
    assert srv.token == TOKEN


# ------------------------------------------------------------------ A2
@pytest.mark.parametrize(
    "provider",
    [
        pytest.param(lambda: (_ for _ in ()).throw(RuntimeError("keystore caído")),
                     id="lanza"),
        pytest.param(lambda: "", id="vacio"),
        pytest.param(lambda: None, id="none"),
        pytest.param(lambda: "abc", id="corto"),
    ],
)
async def test_token_provider_roto_responde_server_error_sin_castigar(
    server_port, provider, caplog
):
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port,
                     token_provider=provider)
    await srv.start()
    caplog.set_level(logging.DEBUG)
    try:
        stream, reply = await raw_handshake(server_port)
        assert reply == {"type": "error", "reason": "server_error"}
        await stream.close()

        # Fallo del servidor: no cuenta contra la IP del cliente.
        assert "127.0.0.1" not in srv._rate_limiter._failures
        # Y no se vuelca un traceback a nivel WARNING o superior.
        assert not [r for r in caplog.records
                    if r.levelno >= logging.WARNING and r.exc_info]
    finally:
        await srv.stop()


async def test_provider_vacio_no_permite_autenticar_con_token_vacio(server_port):
    """Regresión de seguridad: provider -> "" no debe aceptar token ""."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port,
                     token_provider=lambda: "")
    await srv.start()
    try:
        stream, reply = await raw_handshake(server_port, token="")
        assert reply.get("type") != "auth_ok"
        assert srv.is_connected() is False
        await stream.close()
    finally:
        await srv.stop()


async def test_cliente_reintenta_ante_server_error_y_no_se_rinde(server_port):
    """server_error es transitorio: start() no debe lanzar AuthRejected."""
    def roto() -> str:
        raise RuntimeError("keystore caído")

    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port,
                     token_provider=roto)
    await srv.start()
    try:
        cli = WiFiClient("127.0.0.1", token=TOKEN, port=server_port)
        peer = Peer(cli, heartbeat=0)
        with pytest.raises(ConnectionError) as info:
            await peer.start(timeout=1.5)
        assert not isinstance(info.value, AuthRejected)
        assert isinstance(info.value.__cause__, TransientAuthError)
        assert info.value.__cause__.reason == "server_error"
        await peer.stop()
    finally:
        await srv.stop()


# ------------------------------------------------------------------ A3
async def test_zeroconf_desactivado_por_defecto(server_port, monkeypatch):
    monkeypatch.setattr(wifi, "_HAS_ZEROCONF", True)
    llamadas = []

    async def fake_register(self):
        llamadas.append(1)

    monkeypatch.setattr(WiFiServer, "_register_zeroconf", fake_register)

    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port)
    assert srv.enable_zeroconf is False
    await srv.start()
    await srv.stop()
    assert llamadas == []  # no se anuncia nada sin pedirlo


async def test_zeroconf_se_activa_si_se_pide(server_port, monkeypatch):
    monkeypatch.setattr(wifi, "_HAS_ZEROCONF", True)
    llamadas = []

    async def fake_register(self):
        llamadas.append(1)

    monkeypatch.setattr(WiFiServer, "_register_zeroconf", fake_register)

    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port,
                     enable_zeroconf=True)
    await srv.start()
    await srv.stop()
    assert llamadas == [1]


# ------------------------------------------------------------------ B1
@pytest.mark.parametrize("nombre", sorted(RESERVED_EVENTS))
async def test_eventos_reservados_no_se_pueden_enviar_ni_registrar(
    server_port, nombre
):
    peer = Peer(WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port),
                heartbeat=0)
    with pytest.raises(ValueError, match="reservado"):
        peer.on(nombre, lambda msg: None)
    with pytest.raises(ValueError, match="reservado"):
        await peer.send(nombre, {})


async def test_nombres_normales_siguen_permitidos(server_port):
    peer = Peer(WiFiServer(token=TOKEN, host="127.0.0.1", port=server_port),
                heartbeat=0)
    for nombre in ("chat", "error", "status.update", "file-chunk_1"):
        peer.on(nombre, lambda msg: None)  # no lanza


# ------------------------------------------------------------------ B2
def _ctx_sin_verificacion() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def test_cliente_rechaza_cert_none_en_lan():
    # Mensaje real habla de CERT_REQUIRED / verify_mode (no de CERT_NONE).
    with pytest.raises(ValueError, match="CERT_REQUIRED|verify_mode"):
        WiFiClient("192.168.1.50", token=TOKEN,
                   ssl_context=_ctx_sin_verificacion())


def test_cliente_acepta_cert_none_con_opt_in_explicito():
    WiFiClient("192.168.1.50", token=TOKEN,
               ssl_context=_ctx_sin_verificacion(), allow_insecure_tls=True)


def test_cliente_acepta_contexto_que_verifica():
    WiFiClient("192.168.1.50", token=TOKEN,
               ssl_context=ssl.create_default_context())


def test_cliente_cert_none_en_loopback_permitido():
    # Misma política que "sin TLS": loopback no está expuesto a MITM de LAN.
    WiFiClient("127.0.0.1", token=TOKEN, ssl_context=_ctx_sin_verificacion())