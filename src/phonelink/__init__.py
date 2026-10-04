"""phonelink: comunicación PC ↔ móvil sobre TCP con TLS.

API pública:
    Núcleo:       Peer, WiFiServer, WiFiClient, Transport
    Mensajería:   Message, payload_of
    Errores:      PhoneLinkError, ProtocolError, LinkConnectionError,
                  AuthRejected, TransientAuthError
    TLS helpers:  trust_certificate, server_context, server_context_from_p12
    Log:          set_log_sink, get_log_sink
    Token:        generate_token
"""

from .exceptions import (
    AuthRejected,
    LinkConnectionError,
    PhoneLinkError,
    ProtocolError,
    TransientAuthError,
)
from .log import get_log_sink, set_log_sink
from .peer import Message, Peer, payload_of
from .tls import server_context, server_context_from_p12, trust_certificate
from .transport import Transport
from .wifi import WiFiClient, WiFiServer, generate_token

__all__ = [
    # Núcleo
    "Peer",
    "WiFiServer",
    "WiFiClient",
    "Transport",
    # Mensajería
    "Message",
    "payload_of",
    # Errores
    "PhoneLinkError",
    "ProtocolError",
    "LinkConnectionError",
    "AuthRejected",
    "TransientAuthError",
    # TLS helpers
    "trust_certificate",
    "server_context",
    "server_context_from_p12",
    # Log
    "set_log_sink",
    "get_log_sink",
    # Token
    "generate_token",
]
__version__ = "0.5.0"