"""Jerarquía de excepciones de phonelink.

Se mantiene compatibilidad con las excepciones previas heredando de
ConnectionError (que es lo que la librería lanzaba antes), pero se añade
una raíz común PhoneLinkError para poder capturar todo de una vez.

Jerarquía:
    Exception
    └── ConnectionError
        └── PhoneLinkError
            ├── ProtocolError          (framing/JSON/validación)
            ├── LinkConnectionError    (fallo de red/auth genérico)
            │   ├── AuthRejected       (terminal: no reintentar)
            │   └── TransientAuthError (transitorio: reintentar)

Uso:
    from phonelink import PhoneLinkError, AuthRejected
    try:
        ...
    except AuthRejected as e:
        print("terminal:", e.reason)
    except PhoneLinkError:
        print("cualquier error de phonelink")
"""

from __future__ import annotations


class PhoneLinkError(ConnectionError):
    """Raíz común de todos los errores de phonelink."""


class ProtocolError(PhoneLinkError):
    """Error de framing, serialización o validación."""


class LinkConnectionError(PhoneLinkError):
    """Fallo de conexión o autenticación genérico."""


class AuthRejected(LinkConnectionError):
    """Auth rechazada de forma terminal (no reintentar con el mismo token)."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Auth rechazada: {reason}")
        self.reason = reason


class TransientAuthError(LinkConnectionError):
    """Auth rechazada temporalmente (rate_limited, server_error): reintentar."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Auth temporalmente rechazada: {reason}")
        self.reason = reason


__all__ = [
    "PhoneLinkError",
    "ProtocolError",
    "LinkConnectionError",
    "AuthRejected",
    "TransientAuthError",
]