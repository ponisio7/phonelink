"""Helpers TLS para phonelink.

Equivalen a `object Tls` de phonelink-kotlin:

    Tls.trustCertificate(pem)             -> SSLContext cliente
    Tls.serverContext(pkcs12, password)   -> SSLContext servidor

Uso típico:

    from phonelink import trust_certificate, server_context

    # Cliente que confía SOLO en tu server.crt autofirmado
    ctx = trust_certificate("certs/server.crt")
    peer = Peer(WiFiClient("192.168.1.20", token, ssl_context=ctx))

    # Servidor desde PEM (cert + key)
    ctx = server_context("certs/server.crt", "certs/server.key")
    peer = Peer(WiFiServer(token, host="0.0.0.0", ssl_context=ctx))

    # Servidor desde PKCS#12
    ctx = server_context_from_p12("certs/server.p12", "clave")
"""

from __future__ import annotations

import contextlib
import ssl
import tempfile
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]


def trust_certificate(pem: PathLike) -> ssl.SSLContext:
    """Contexto de cliente que confía SOLO en el/los certificado(s) PEM dados.

    Equivale a Tls.trustCertificate(pem) de Kotlin: pinning de cert
    autofirmado en una línea. El hostname/IP debe figurar en el SAN del
    certificado (se verifica hostname).

    Args:
        pem: ruta al fichero PEM (puede contener varios certificados).

    Returns:
        SSLContext listo para WiFiClient(..., ssl_context=ctx).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=str(pem))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def server_context(cert: PathLike, key: PathLike) -> ssl.SSLContext:
    """Contexto de servidor desde PEM (certificado + clave privada).

    Args:
        cert: ruta al certificado PEM (server.crt).
        key:  ruta a la clave privada PEM (server.key).

    Returns:
        SSLContext listo para WiFiServer(..., ssl_context=ctx).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return ctx


def server_context_from_p12(p12: PathLike, password: str) -> ssl.SSLContext:
    """Contexto de servidor desde un fichero PKCS#12 (.p12).

    Equivale exactamente a Tls.serverContext(pkcs12, password) de Kotlin.

    Crear el .p12 desde PEM:
        openssl pkcs12 -export -in server.crt -inkey server.key -out server.p12

    Requiere el paquete `cryptography` (pip install cryptography).

    Args:
        p12:      ruta al fichero .p12.
        password: contraseña del .p12.

    Returns:
        SSLContext listo para WiFiServer(..., ssl_context=ctx).

    Raises:
        ImportError: si `cryptography` no está instalada.
        FileNotFoundError: si el .p12 no existe.
        ValueError: si el .p12 no se puede descifrar con esa contraseña.
    """
    try:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )
        from cryptography.hazmat.primitives.serialization.pkcs12 import (
            load_key_and_certificates,
        )
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "server_context_from_p12 requiere el paquete 'cryptography'. "
            "Instálalo con `pip install cryptography` o usa "
            "server_context(cert_pem, key_pem) en su lugar."
        ) from exc

    p12_path = Path(p12)
    if not p12_path.is_file():
        raise FileNotFoundError(f"No existe el fichero .p12: {p12_path}")

    data = p12_path.read_bytes()
    try:
        key, cert, extra_certs = load_key_and_certificates(
            data, password.encode("utf-8") if password else None
        )
    except Exception as exc:
        raise ValueError(
            f"No se pudo descifrar el .p12 {p12_path} "
            f"(¿contraseña incorrecta?): {exc}"
        ) from exc

    if key is None or cert is None:
        raise ValueError(
            f"El .p12 {p12_path} no contiene clave privada o certificado"
        )

    # Serializamos a PEM en memoria y usamos load_cert_chain vía tempfiles.
    key_pem = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    cert_pem = cert.public_bytes(Encoding.PEM)

    with tempfile.NamedTemporaryFile(
        "wb", suffix=".key", delete=False
    ) as f_key, tempfile.NamedTemporaryFile(
        "wb", suffix=".crt", delete=False
    ) as f_cert:
        f_key.write(key_pem)
        f_cert.write(cert_pem)
        key_path = Path(f_key.name)
        cert_path = Path(f_cert.name)

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    finally:
        with contextlib.suppress(OSError):
            key_path.unlink()
        with contextlib.suppress(OSError):
            cert_path.unlink()
    return ctx


__all__ = [
    "trust_certificate",
    "server_context",
    "server_context_from_p12",
]