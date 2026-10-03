"""Tests de integración TLS.

Generan certificados autofirmados en tiempo de test con openssl.
Si openssl no está disponible, se saltan con skip.
"""

import asyncio
import contextlib
import shutil
import socket
import ssl
import subprocess
from pathlib import Path
from typing import Optional

import pytest

from phonelink import Peer, WiFiClient, WiFiServer

from tests.conftest import TOKEN, Collector, free_port


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #

def _openssl_available() -> bool:
    return shutil.which("openssl") is not None


pytestmark = pytest.mark.skipif(
    not _openssl_available(),
    reason="openssl no está instalado; tests TLS omitidos",
)


def _generate_cert(
    tmp_path: Path,
    cn: str = "phonelink-test",
    san_ips: Optional[list[str]] = None,
) -> tuple[Path, Path]:
    """Genera un par (cert, key) autofirmado para tests.

    Devuelve las rutas de los archivos.
    """
    if san_ips is None:
        san_ips = ["127.0.0.1"]
    san = ",".join(f"IP:{ip}" for ip in san_ips)
    cert = tmp_path / f"{cn}.crt"
    key = tmp_path / f"{cn}.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key),
            "-out", str(cert),
            "-days", "1",
            "-subj", f"/CN={cn}",
            "-addext", f"subjectAltName={san}",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def _server_ctx(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return ctx


def _client_ctx(cert: Path) -> ssl.SSLContext:
    """Contexto que confía en el certificado del servidor."""
    ctx = ssl.create_default_context(cafile=str(cert))
    # El cert es autofirmado; desactivamos check_hostname porque nos
    # conectamos por IP y el SAN ya lo cubre, pero create_default_context
    # exige hostname match con check_hostname=True.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

async def test_tls_handshake_exitoso(tmp_path):
    """Cliente y servidor con TLS se conectan correctamente."""
    cert, key = _generate_cert(tmp_path)
    port = free_port()

    srv = WiFiServer(
        token=TOKEN,
        host="127.0.0.1",
        port=port,
        ssl_context=_server_ctx(cert, key),
    )
    peer_srv = Peer(srv, heartbeat=0)
    recibidos = Collector()
    peer_srv.on("chat", recibidos.handler)
    await peer_srv.start()

    try:
        cli = WiFiClient(
            "127.0.0.1",
            token=TOKEN,
            port=port,
            reconnect=False,
            ssl_context=_client_ctx(cert),
        )
        peer_cli = Peer(cli, heartbeat=0)
        await peer_cli.start(timeout=3.0)
        try:
            await peer_cli.send("chat", {"text": "hola TLS"})
            msg = await recibidos.wait_for(lambda m: m.get("type") == "chat")
            assert msg["payload"]["text"] == "hola TLS"
        finally:
            await peer_cli.stop()
    finally:
        await peer_srv.stop()


async def test_tls_bidireccional(tmp_path):
    """Envío en ambos sentidos sobre TLS."""
    cert, key = _generate_cert(tmp_path)
    port = free_port()

    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=port,
                     ssl_context=_server_ctx(cert, key))
    peer_srv = Peer(srv, heartbeat=0)
    recibidos_srv = Collector()
    peer_srv.on("chat", recibidos_srv.handler)
    await peer_srv.start()

    try:
        cli = WiFiClient("127.0.0.1", token=TOKEN, port=port,
                         reconnect=False, ssl_context=_client_ctx(cert))
        peer_cli = Peer(cli, heartbeat=0)
        recibidos_cli = Collector()
        peer_cli.on("chat", recibidos_cli.handler)
        await peer_cli.start(timeout=3.0)
        try:
            # Cliente → servidor
            await peer_cli.send("chat", {"text": "ping"})
            m1 = await recibidos_srv.wait_for(lambda m: m["payload"]["text"] == "ping")
            assert m1["payload"]["text"] == "ping"

            # Servidor → cliente
            await peer_srv.send("chat", {"text": "pong"})
            m2 = await recibidos_cli.wait_for(lambda m: m["payload"]["text"] == "pong")
            assert m2["payload"]["text"] == "pong"
        finally:
            await peer_cli.stop()
    finally:
        await peer_srv.stop()


async def test_tls_rechaza_cliente_sin_ca(tmp_path):
    """Un cliente que no confía en el cert autofirmado no conecta."""
    cert, key = _generate_cert(tmp_path)
    port = free_port()

    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=port,
                     ssl_context=_server_ctx(cert, key))
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()

    try:
        # Contexto por defecto: NO confía en el cert autofirmado.
        cli = WiFiClient(
            "127.0.0.1", token=TOKEN, port=port,
            reconnect=False,
            ssl_context=ssl.create_default_context(),
        )
        peer_cli = Peer(cli, heartbeat=0)
        with pytest.raises(ConnectionError):
            await peer_cli.start(timeout=2.0)
        assert not cli.is_connected()
    finally:
        await peer_srv.stop()


async def test_tls_pinning_fingerprint_incorrecto(tmp_path):
    """Si el cliente tiene una CA distinta, rechaza el cert del servidor."""
    cert_srv, key_srv = _generate_cert(tmp_path, cn="server")
    cert_otro, _ = _generate_cert(tmp_path, cn="otro")

    port = free_port()
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=port,
                     ssl_context=_server_ctx(cert_srv, key_srv))
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()

    try:
        # Cliente confía en un cert distinto → handshake falla.
        cli = WiFiClient(
            "127.0.0.1", token=TOKEN, port=port,
            reconnect=False,
            ssl_context=_client_ctx(cert_otro),
        )
        peer_cli = Peer(cli, heartbeat=0)
        with pytest.raises(ConnectionError):
            await peer_cli.start(timeout=2.0)
    finally:
        await peer_srv.stop()


async def test_tls_heartbeat(tmp_path):
    """El heartbeat ping/pong funciona sobre TLS."""
    cert, key = _generate_cert(tmp_path)
    port = free_port()

    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=port,
                     ssl_context=_server_ctx(cert, key))
    # Heartbeat agresivo: cada 0.2s, timeout 0.6s.
    peer_srv = Peer(srv, heartbeat=0.2, heartbeat_timeout_factor=3.0)
    await peer_srv.start()

    try:
        cli = WiFiClient("127.0.0.1", token=TOKEN, port=port,
                         reconnect=False, ssl_context=_client_ctx(cert))
        # El cliente responde a los pings automáticamente vía Peer._dispatch.
        peer_cli = Peer(cli, heartbeat=0)
        await peer_cli.start(timeout=3.0)

        # Esperamos varios ciclos de heartbeat.
        await asyncio.sleep(1.0)
        assert cli.is_connected()

        # La conexión sigue viva: enviamos un mensaje.
        recibidos = Collector()
        peer_srv.on("test", recibidos.handler)
        await peer_cli.send("test", {"ok": True})
        msg = await recibidos.wait_for(lambda m: m.get("type") == "test")
        assert msg["payload"]["ok"] is True

        await peer_cli.stop()
    finally:
        await peer_srv.stop()


def test_server_rechaza_lan_sin_tls():
    """Sin ssl_context, el servidor no acepta escuchar en IP no-loopback."""
    with pytest.raises(ValueError, match="Sin TLS"):
        WiFiServer(token=TOKEN, host="0.0.0.0", port=8888)


def test_client_rechaza_lan_sin_tls():
    """Sin ssl_context, el cliente no acepta conectar a IP no-loopback."""
    with pytest.raises(ValueError, match="Sin TLS"):
        WiFiClient("192.168.1.1", token=TOKEN, port=8888)


def test_server_loopback_sin_tls_permitido():
    """Sin ssl_context, escuchar en loopback SÍ se permite."""
    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=8888)
    assert srv.ssl_context is None


def test_server_lan_sin_tls_con_override():
    """allow_insecure_lan=True permite escuchar en LAN sin TLS."""
    srv = WiFiServer(
        token=TOKEN, host="0.0.0.0", port=8888,
        allow_insecure_lan=True,
    )
    assert srv.ssl_context is None


async def test_tls_info_cifrado(tmp_path):
    """Verifica que los datos viajan cifrados (no se lee el token en claro)."""
    cert, key = _generate_cert(tmp_path)
    port = free_port()

    srv = WiFiServer(token=TOKEN, host="127.0.0.1", port=port,
                     ssl_context=_server_ctx(cert, key))
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()

    try:
        # Nos conectamos a bajo nivel para inspeccionar el handshake.
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=_client_ctx(cert)
        )
        # El socket subyacente debe ser un SSLSocket.
        sock = writer.get_extra_info("socket")
        # En asyncio, get_extra_info("ssl_object") da el objeto SSL.
        ssl_obj = writer.get_extra_info("ssl_object")
        assert ssl_obj is not None
        assert ssl_obj.version() in ("TLSv1.2", "TLSv1.3")
        # El cifrado debe ser AEAD (GCM o ChaCha20) o similar moderno.
        cipher = ssl_obj.cipher()
        assert cipher is not None
        assert any(tag in cipher[0] for tag in ("GCM", "CHACHA20", "CCM"))

        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
    finally:
        await peer_srv.stop()

async def test_tls_handshake_timeout(tmp_path):
    """Un cliente que abre TCP pero no completa el TLS es rechazado pronto."""
    cert, key = _generate_cert(tmp_path)
    port = free_port()

    srv = WiFiServer(
        token=TOKEN, host="127.0.0.1", port=port,
        ssl_context=_server_ctx(cert, key),
    )
    peer_srv = Peer(srv, heartbeat=0)
    await peer_srv.start()
    try:
        # Abrimos TCP crudo, sin TLS.
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # El servidor debe cerrar en ~HANDSHAKE_TIMEOUT (5 s) como máximo.
        data = await asyncio.wait_for(reader.read(10), timeout=8.0)
        assert data == b""
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
    finally:
        await peer_srv.stop()