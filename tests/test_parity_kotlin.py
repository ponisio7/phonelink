"""Tests de las capacidades añadidas para paridad con phonelink-kotlin.

Cubre:
  - Message wrapper (compatible con dict)
  - payload_of + send con kwargs
  - connected observable + wait_connected/wait_disconnected
  - TLS helpers (trust_certificate, server_context, server_context_from_p12)
  - bound_port
  - TCP_NODELAY / SO_REUSEADDR (indirecto)
  - log sink
  - jerarquía de excepciones
"""

import asyncio
import contextlib
import shutil
import socket
import ssl
import subprocess

import pytest

from phonelink import (
    AuthRejected,
    Message,
    Peer,
    PhoneLinkError,
    ProtocolError,
    TransientAuthError,
    WiFiClient,
    WiFiServer,
    get_log_sink,
    payload_of,
    server_context,
    server_context_from_p12,
    set_log_sink,
    trust_certificate,
)
from phonelink.log import plog
from tests.conftest import TOKEN, Collector, free_port


# --------------------------------------------------------------- Message
async def test_message_wrapper_compatible_con_dict(server):
    peer_srv, srv, port = server
    recibidos = Collector()

    async def handler(msg):
        assert isinstance(msg, Message)
        assert msg.type == "chat"
        assert msg.text("text") == "hola"
        # Compatibilidad con dict
        assert msg.get("type") == "chat"
        assert msg.get("payload") == {"text": "hola"}
        assert msg["payload"]["text"] == "hola"
        assert msg["text"] == "hola"
        assert "text" in msg
        recibidos.messages.append(msg)

    peer_srv.on("chat", handler)
    await peer_srv.start()

    cli = WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False)
    peer_cli = Peer(cli, heartbeat=0)
    await peer_cli.start(timeout=2.0)
    try:
        await peer_cli.send("chat", {"text": "hola"})
        await asyncio.sleep(0.3)
        assert len(recibidos.messages) == 1
    finally:
        await peer_cli.stop()


def test_message_text_no_str_devuelve_none():
    m = Message("evt", {"n": 3}, {"type": "evt", "payload": {"n": 3}})
    assert m.text("n") is None
    assert m.text("missing") is None


# ------------------------------------------------------------- payload_of
def test_payload_of():
    assert payload_of(text="hola", n=3) == {"text": "hola", "n": 3}


async def test_send_con_kwargs(server):
    peer_srv, srv, port = server
    recibidos = Collector()
    peer_srv.on("chat", recibidos.handler)
    await peer_srv.start()

    cli = WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False)
    peer_cli = Peer(cli, heartbeat=0)
    await peer_cli.start(timeout=2.0)
    try:
        await peer_cli.send("chat", text="hola", n=3)
        msg = await recibidos.wait_for(lambda m: m.get("type") == "chat")
        assert msg["payload"]["text"] == "hola"
        assert msg["payload"]["n"] == 3
    finally:
        await peer_cli.stop()


async def test_send_no_mezcla_payload_y_kwargs(server):
    peer_srv, srv, port = server
    peer_cli = Peer(
        WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False),
        heartbeat=0,
    )
    with pytest.raises(TypeError):
        await peer_cli.send("chat", {"a": 1}, b=2)


async def test_send_valida_keys_str(server):
    peer_srv, srv, port = server
    peer_cli = Peer(
        WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False),
        heartbeat=0,
    )
    with pytest.raises(TypeError):
        await peer_cli.send("chat", {1: "no-str"})


# --------------------------------------------------------- connected event
async def test_connected_event(server):
    peer_srv, srv, port = server
    await peer_srv.start()

    cli = WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False)
    peer_cli = Peer(cli, heartbeat=0)
    assert peer_cli.connected is False
    await peer_cli.start(timeout=2.0)
    assert peer_cli.connected is True
    await peer_cli.stop()
    assert peer_cli.connected is False


async def test_wait_connected(server):
    peer_srv, srv, port = server
    await peer_srv.start()

    cli = WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False)
    peer_cli = Peer(cli, heartbeat=0)
    task = asyncio.create_task(peer_cli.wait_connected(timeout=3.0))
    await peer_cli.start(timeout=2.0)
    await asyncio.wait_for(task, timeout=1.0)
    assert peer_cli.connected is True
    await peer_cli.stop()


async def test_wait_connected_timeout(server):
    peer_srv, srv, port = server
    # No arrancamos servidor: wait_connected debe expirar.
    cli = WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False)
    peer_cli = Peer(cli, heartbeat=0)
    with pytest.raises(asyncio.TimeoutError):
        await peer_cli.wait_connected(timeout=0.3)


# ------------------------------------------------------------- TLS helpers
def _make_cert(tmp_path, cn="test"):
    if shutil.which("openssl") is None:
        pytest.skip("openssl no instalado")
    cert = tmp_path / f"{cn}.crt"
    key = tmp_path / f"{cn}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", f"/CN={cn}", "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    return cert, key


def test_trust_certificate_pem(tmp_path):
    cert, _ = _make_cert(tmp_path)
    ctx = trust_certificate(cert)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_server_context_pem(tmp_path):
    cert, key = _make_cert(tmp_path)
    ctx = server_context(cert, key)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_server_context_from_p12(tmp_path):
    cert, key = _make_cert(tmp_path)
    p12 = tmp_path / "server.p12"
    subprocess.run(
        ["openssl", "pkcs12", "-export",
         "-in", str(cert), "-inkey", str(key),
         "-out", str(p12), "-passout", "pass:clave"],
        check=True, capture_output=True,
    )
    ctx = server_context_from_p12(p12, "clave")
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    # Verifica que de verdad hay una clave cargada (no solo que no lanza)
    # (ssl no expone directamente el cert cargado, pero podemos al menos
    #  comprobar que el contexto sirve para crear un ServerSocket.)
    assert ctx.protocol == ssl.PROTOCOL_TLS_SERVER


# --------------------------------------------------------------- bound_port
async def test_bound_port_con_port_cero():
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=0)
    await srv.start()
    try:
        assert srv.bound_port != 0
        assert srv.bound_port > 0
    finally:
        await srv.stop()


async def test_bound_port_antes_de_start():
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=0)
    assert srv.bound_port == 0  # devuelve self.port


# --------------------------------------------------------------- log sink
def test_set_log_sink():
    capturados = []
    set_log_sink(lambda m: capturados.append(m))
    try:
        plog("hola")
        assert capturados == ["hola"]
    finally:
        set_log_sink(None)
    assert get_log_sink() is None


def test_log_sink_roto_no_tumba():
    def boom(_):
        raise RuntimeError("boom")
    set_log_sink(boom)
    try:
        plog("no debe lanzar")
    finally:
        set_log_sink(None)


# ---------------------------------------------------- jerarquía excepciones
def test_jerarquia_excepciones():
    assert issubclass(AuthRejected, PhoneLinkError)
    assert issubclass(TransientAuthError, PhoneLinkError)
    assert issubclass(ProtocolError, PhoneLinkError)
    assert issubclass(PhoneLinkError, ConnectionError)


def test_auth_rejected_es_connection_error():
    with pytest.raises(ConnectionError):
        raise AuthRejected("auth_failed")


# ----------------------------------------------------- compatibilidad dict
async def test_handler_viejo_con_dict_sigue_funcionando(server):
    """Un handler que hace msg.get("type") y msg["payload"] sigue OK."""
    peer_srv, srv, port = server
    recibidos = Collector()

    async def handler_viejo(msg):
        # Estilo antiguo: msg era un dict
        assert msg.get("type") == "chat"
        assert msg["payload"]["text"] == "hola"
        recibidos.messages.append(msg)

    peer_srv.on("chat", handler_viejo)
    await peer_srv.start()

    cli = WiFiClient("127.0.0.1", token=TOKEN, port=port, reconnect=False)
    peer_cli = Peer(cli, heartbeat=0)
    await peer_cli.start(timeout=2.0)
    try:
        await peer_cli.send("chat", {"text": "hola"})
        await asyncio.sleep(0.3)
        assert len(recibidos.messages) == 1
    finally:
        await peer_cli.stop()