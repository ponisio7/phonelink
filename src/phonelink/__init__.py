"""phonelink: comunicación PC ↔ móvil sobre TCP con TLS."""

from .peer import Peer
from .protocol import ProtocolError
from .transport import Transport
from .wifi import AuthRejected, TransientAuthError, WiFiClient, WiFiServer

__all__ = [
    "Peer",
    "WiFiServer",
    "WiFiClient",
    "ProtocolError",
    "Transport",
    "AuthRejected",
    "TransientAuthError",
]
__version__ = "0.4.0"