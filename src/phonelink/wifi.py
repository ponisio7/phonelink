"""Transporte WiFi con sockets TCP, autenticación por token y zeroconf - v0.4.0.

Fixes acumulados:
  v0.3: C1 host="" bypass, C2 nonce/MAC longitud, C3 DoS semáforos, C5 TLS mínimo,
        C6 on_disconnect perdido, C7 race revoke, C9 _connected limpio,
        C10 rate limiter evict, C12 handshake send timeout, A1 on_auth_error async,
        A2 replaced/revoked etiquetado, A3 set_token con provider,
        A7 version mismatch no rate-limit, A8 reason validado, A10 warning insecure,
        M1 código muerto, M4 start timeout, M17 service_name validación,
        B6 IPv6 zeroconf.
  v0.4: BLOCKER 1 deadlock en send() (lock no reentrante),
        BLOCKER 2 TLS endurecido (check_hostname + verify_mode fuera de loopback),
        A6/M5 MAX_PAYLOAD, timeouts y límites configurables por constructor,
        M5 last_rx=None hasta primer byte (requiere protocol.py),
        on_session_terminated para replaced/revoked,
        set_token con update_provider=True,
        _token_digest eliminado (código muerto),
        generate_token() helper exportable.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import inspect
import ipaddress
import logging
import re
import secrets
import socket
import ssl
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from zeroconf import ServiceInfo
    from zeroconf.asyncio import AsyncZeroconf

try:
    from zeroconf import ServiceInfo
    from zeroconf.asyncio import AsyncZeroconf
    _HAS_ZEROCONF = True
except ImportError:  # pragma: no cover
    ServiceInfo = None  # type: ignore[assignment]
    AsyncZeroconf = None  # type: ignore[assignment]
    _HAS_ZEROCONF = False

from .protocol import (
    DEFAULT_IDLE_TIMEOUT,
    HANDSHAKE_MAX,
    MAX_PAYLOAD,
    NONCE_SIZE,
    PROTOCOL_VERSION,
    MessageStream,
    ProtocolError,
    close_quietly,
)
from .transport import Transport

log = logging.getLogger(__name__)
SERVICE_TYPE = "_phonelink._tcp.local."
DEFAULT_PORT = 8888
MIN_TOKEN_LEN = 16

# Valores por defecto (configurables por constructor a partir de v0.4)
DEFAULT_HANDSHAKE_TIMEOUT = 5.0
DEFAULT_SEND_TIMEOUT = 15.0
DEFAULT_REVOKE_TIMEOUT = 3.0
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_MAX_PREAUTH_CONNECTIONS = 32
DEFAULT_MAX_HANDSHAKES = 8
DEFAULT_HANDSHAKE_SEM_TIMEOUT = 2.0
DEFAULT_PREAUTH_SEM_TIMEOUT = 1.0

DEFAULT_RATE_WINDOW = 60.0
DEFAULT_RATE_MAX_FAILURES = 5
DEFAULT_RATE_BLOCK_SECONDS = 300.0
DEFAULT_AUTH_FAIL_DELAY = 0.5
DEFAULT_RATE_MAX_TRACKED_IPS = 10_000

AUTH_FAILED = "auth_failed"
PROTOCOL_VERSION_MISMATCH = "protocol_version_mismatch"
RATE_LIMITED = "rate_limited"
REVOKED = "revoked"
SERVER_ERROR = "server_error"

TERMINAL_AUTH_REASONS = frozenset({AUTH_FAILED, PROTOCOL_VERSION_MISMATCH, REVOKED})
TRANSIENT_AUTH_REASONS = frozenset({RATE_LIMITED, SERVER_ERROR})

_SERVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9-]+$")
MAX_SERVICE_NAME_LEN = 63


# --------------------------------------------------------------------------- #
# Excepciones
# --------------------------------------------------------------------------- #
class AuthRejected(ConnectionError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Auth rechazada: {reason}")
        self.reason = reason


class TransientAuthError(ConnectionError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Auth temporalmente rechazada: {reason}")
        self.reason = reason


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #
def generate_token(nbytes: int = 32) -> str:
    """Genera un token seguro listo para usar como token de phonelink.

    Usa secrets.token_urlsafe, que produce una cadena URL-safe sin caracteres
    problemáticos para HMAC ni para logs. 32 bytes ≈ 43 caracteres.
    """
    if nbytes < MIN_TOKEN_LEN:
        raise ValueError(f"nbytes debe ser >= {MIN_TOKEN_LEN}")
    return secrets.token_urlsafe(nbytes)


def _local_ip() -> Optional[str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        if ip.startswith("127.") or ip.startswith("169.254."):
            return None
        return ip
    except OSError:
        return None
    finally:
        s.close()


def _is_loopback(host: str) -> bool:
    """True si `host` es loopback. host="" NO es loopback (escucha en 0.0.0.0)."""
    if not host or not host.strip():
        return False
    lower = host.lower()
    if lower == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _token_key(token: str) -> Optional[bytes]:
    if not isinstance(token, str):
        return None
    try:
        return token.encode("utf-8")
    except UnicodeEncodeError:
        return None


def _compute_mac(token: str, nonce: bytes) -> Optional[bytes]:
    key = _token_key(token)
    if key is None:
        return None
    return hmac.new(key, nonce, hashlib.sha256).digest()


def _mac_hex(token: str, nonce: bytes) -> Optional[str]:
    mac = _compute_mac(token, nonce)
    if mac is None:
        return None
    return mac.hex()


def _validate_reason(reason: Any) -> str:
    if isinstance(reason, str) and reason and len(reason) < 256:
        if re.match(r"^[a-zA-Z0-9_.-]+$", reason):
            return reason
    return "unknown"


def _validate_service_name(name: str) -> None:
    if not isinstance(name, str) or not name:
        raise ValueError("service_name debe ser str no vacío")
    if len(name) > MAX_SERVICE_NAME_LEN:
        raise ValueError(f"service_name demasiado largo (máx {MAX_SERVICE_NAME_LEN})")
    if not _SERVICE_NAME_RE.match(name):
        raise ValueError("service_name solo puede contener letras, dígitos y guión")


def _check_tls_context(
    ctx: Optional[ssl.SSLContext],
    is_server: bool,
    *,
    host: str = "",
    allow_insecure_tls: bool = False,
) -> None:
    """Valida el SSLContext.

    - Rechaza versiones *explícitamente* débiles (SSLv3, TLSv1.0, TLSv1.1).
      No rechaza MINIMUM_SUPPORTED / MAXIMUM_SUPPORTED: son marcadores de
      "deja que OpenSSL decida" y en la práctica negocian TLS 1.2+.
    - En cliente, fuera de loopback y sin allow_insecure_tls, exige
      verify_mode == CERT_REQUIRED y check_hostname == True.
    - En servidor, no se puede verificar el contexto de cliente.
    """
    if ctx is None:
        return

    # 1) TLS mínimo: solo rechazar versiones explícitamente débiles.
    #    MINIMUM_SUPPORTED (-2) < TLSv1_2 es True por accidente de enum,
    #    pero no significa que el contexto sea débil.
    if hasattr(ctx, "minimum_version"):
        weak_versions = {
            ssl.TLSVersion.SSLv3,
            ssl.TLSVersion.TLSv1,
            ssl.TLSVersion.TLSv1_1,
        }
        try:
            if ctx.minimum_version in weak_versions:
                raise ValueError(
                    "SSLContext.minimum_version debe ser TLSv1_2 o superior"
                )
        except (AttributeError, TypeError):
            pass

    # 2) Cliente: verificación completa fuera de loopback
    if not is_server and not _is_loopback(host) and not allow_insecure_tls:
        if ctx.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError(
                "ssl_context debe tener verify_mode=CERT_REQUIRED fuera de "
                "loopback. Si aceptas MITM conscientemente, pasa "
                "allow_insecure_tls=True."
            )
        if not ctx.check_hostname:
            raise ValueError(
                "ssl_context debe tener check_hostname=True fuera de loopback. "
                "Si aceptas MITM conscientemente, pasa allow_insecure_tls=True."
            )

    # 3) Servidor: aviso si no hay cipher suites
    if is_server:
        try:
            if not ctx.get_ciphers():
                log.warning("SSLContext de servidor sin cipher suites configuradas")
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Rate limiter
# --------------------------------------------------------------------------- #
class _RateLimiter:
    def __init__(
        self,
        window: float = DEFAULT_RATE_WINDOW,
        max_failures: int = DEFAULT_RATE_MAX_FAILURES,
        block_seconds: float = DEFAULT_RATE_BLOCK_SECONDS,
        max_tracked_ips: int = DEFAULT_RATE_MAX_TRACKED_IPS,
    ) -> None:
        self.window = window
        self.max_failures = max_failures
        self.block_seconds = block_seconds
        self.max_tracked_ips = max_tracked_ips
        self._failures: "OrderedDict[str, List[float]]" = OrderedDict()
        self._blocked_until: "OrderedDict[str, float]" = OrderedDict()
        self._lock = asyncio.Lock()

    def _purge_expired(self, now: float) -> None:
        expired_ips = [ip for ip, until in self._blocked_until.items() if until <= now]
        for ip in expired_ips:
            self._blocked_until.pop(ip, None)
            self._failures.pop(ip, None)
        for ip, fails in list(self._failures.items()):
            filtered = [t for t in fails if now - t < self.window]
            if not filtered:
                self._failures.pop(ip, None)
            else:
                self._failures[ip] = filtered

    def _purge_if_needed(self, now: float) -> None:
        self._purge_expired(now)
        # Evitar evictar bloqueos activos: solo purgamos fallos no bloqueados.
        while len(self._failures) > self.max_tracked_ips:
            evicted = False
            for ip in list(self._failures.keys()):
                if ip not in self._blocked_until:
                    self._failures.popitem(last=False)
                    evicted = True
                    break
            if not evicted:
                # Todos los fallos corresponden a IPs bloqueadas activas.
                # No evictamos para no desbloquear atacantes; solo avisamos.
                log.warning(
                    "RateLimiter: %d fallos con todas las IPs bloqueadas; "
                    "no se evicta para no desbloquear atacantes",
                    len(self._failures),
                )
                break
        if len(self._blocked_until) > self.max_tracked_ips:
            log.warning(
                "RateLimiter: %d IPs bloqueadas activas (>%d); "
                "no se evicta para no desbloquear atacantes",
                len(self._blocked_until), self.max_tracked_ips,
            )

    async def is_blocked(self, ip: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            until = self._blocked_until.get(ip, 0.0)
            if until > now:
                return True
            if until:
                self._blocked_until.pop(ip, None)
                self._failures.pop(ip, None)
            return False

    async def record_failure(self, ip: str) -> None:
        async with self._lock:
            now = time.monotonic()
            self._purge_if_needed(now)
            fails = [t for t in self._failures.get(ip, []) if now - t < self.window]
            fails.append(now)
            self._failures[ip] = fails
            if len(fails) >= self.max_failures:
                self._blocked_until[ip] = now + self.block_seconds
                log.warning(
                    "IP %s bloqueada por %d fallos (%.0fs)",
                    ip, len(fails), self.block_seconds,
                )

    async def record_success(self, ip: str) -> None:
        async with self._lock:
            self._failures.pop(ip, None)
            self._blocked_until.pop(ip, None)


# --------------------------------------------------------------------------- #
# Servidor
# --------------------------------------------------------------------------- #
class WiFiServer(Transport):
    def __init__(
        self,
        token: str,
        host: str = "127.0.0.1",
        port: int = DEFAULT_PORT,
        service_name: str = "phonelink-pc",
        ssl_context: Optional[ssl.SSLContext] = None,
        allow_insecure_lan: bool = False,
        max_handshakes: int = DEFAULT_MAX_HANDSHAKES,
        enable_zeroconf: bool = False,
        require_strong_token: bool = True,
        rate_limit: bool = True,
        token_provider: Optional[Callable[[], str]] = None,
        *,
        # [FIX v0.4] Límites configurables
        max_payload: int = MAX_PAYLOAD,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
        send_timeout: float = DEFAULT_SEND_TIMEOUT,
        revoke_timeout: float = DEFAULT_REVOKE_TIMEOUT,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        max_preauth_connections: int = DEFAULT_MAX_PREAUTH_CONNECTIONS,
        handshake_sem_timeout: float = DEFAULT_HANDSHAKE_SEM_TIMEOUT,
        preauth_sem_timeout: float = DEFAULT_PREAUTH_SEM_TIMEOUT,
        auth_fail_delay: float = DEFAULT_AUTH_FAIL_DELAY,
        rate_window: float = DEFAULT_RATE_WINDOW,
        rate_max_failures: int = DEFAULT_RATE_MAX_FAILURES,
        rate_block_seconds: float = DEFAULT_RATE_BLOCK_SECONDS,
        rate_max_tracked_ips: int = DEFAULT_RATE_MAX_TRACKED_IPS,
    ) -> None:
        super().__init__()
        if not token:
            raise ValueError("Se requiere un token no vacío")
        if require_strong_token and len(token) < MIN_TOKEN_LEN:
            raise ValueError(f"Token demasiado corto (mínimo {MIN_TOKEN_LEN} caracteres)")
        _validate_service_name(service_name)
        _check_tls_context(ssl_context, is_server=True)
        if ssl_context is None and not _is_loopback(host) and not allow_insecure_lan:
            raise ValueError(
                "Sin TLS solo se permite escuchar en loopback. "
                "Configura ssl_context o allow_insecure_lan=True conscientemente."
            )
        if allow_insecure_lan:
            log.warning("ALLOW_INSECURE_LAN activo - tráfico sin cifrar en LAN!")

        # Validación de límites
        if max_payload <= 0:
            raise ValueError("max_payload debe ser > 0")
        if max_preauth_connections <= 0:
            raise ValueError("max_preauth_connections debe ser > 0")
        if max_handshakes <= 0:
            raise ValueError("max_handshakes debe ser > 0")

        self.token = token
        self._token_provider = token_provider
        self._require_strong_token = require_strong_token
        self.host = host
        self.port = port
        self.service_name = service_name
        self.ssl_context = ssl_context
        self.enable_zeroconf = enable_zeroconf and _HAS_ZEROCONF

        # [FIX v0.4] Límites configurables
        self.max_payload = max_payload
        self.handshake_timeout = handshake_timeout
        self.send_timeout = send_timeout
        self.revoke_timeout = revoke_timeout
        self.idle_timeout = idle_timeout
        self.handshake_sem_timeout = handshake_sem_timeout
        self.preauth_sem_timeout = preauth_sem_timeout
        self.auth_fail_delay = auth_fail_delay

        self._max_handshakes = max(1, max_handshakes)
        self._handshake_sem = asyncio.Semaphore(self._max_handshakes)
        self._preauth_sem = asyncio.Semaphore(max_preauth_connections)
        self._server: Optional[asyncio.AbstractServer] = None
        self._stream: Optional[MessageStream] = None
        self._zeroconf: Optional["AsyncZeroconf"] = None
        self._service_info: Optional["ServiceInfo"] = None
        self._lock = asyncio.Lock()
        self._closed_by_us = False
        self._rate_limiter = (
            _RateLimiter(
                window=rate_window,
                max_failures=rate_max_failures,
                block_seconds=rate_block_seconds,
                max_tracked_ips=rate_max_tracked_ips,
            )
            if rate_limit else None
        )
        self._revoke_tasks: Set[asyncio.Task] = set()

    # ------------------------------------------------------------------ #
    # Estado
    # ------------------------------------------------------------------ #
    def is_connected(self) -> bool:
        return self._stream is not None

    def last_rx_time(self) -> Optional[float]:
        stream = self._stream
        return stream.last_rx if stream is not None else None

    # ------------------------------------------------------------------ #
    # Token
    # ------------------------------------------------------------------ #
    def set_token(
        self,
        token: str,
        *,
        disconnect_current: bool = False,
        update_provider: bool = False,
    ) -> None:
        """Actualiza el token del servidor.

        - Si hay token_provider y no se pasa disconnect_current ni
          update_provider, lanza ValueError (la auth seguiría leyendo del
          provider).
        - update_provider=True envuelve el provider en un callable que
          devuelve el nuevo token (rotación efectiva).
        - disconnect_current=True revoca la sesión activa.
        """
        if not token:
            raise ValueError("Token vacío")
        if self._require_strong_token and len(token) < MIN_TOKEN_LEN:
            raise ValueError(f"Token demasiado corto (mínimo {MIN_TOKEN_LEN} caracteres)")

        if self._token_provider is not None and not (disconnect_current or update_provider):
            raise ValueError(
                "set_token() con token_provider activo no tiene efecto en futuras "
                "autenticaciones. Usa update_provider=True para rotar el provider, "
                "o disconnect_current=True solo para revocar la sesión actual."
            )

        loop: Optional[asyncio.AbstractEventLoop] = None
        if disconnect_current:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                raise RuntimeError(
                    "set_token(disconnect_current=True) debe llamarse desde el event loop"
                ) from None

        self.token = token
        if update_provider:
            self._token_provider = lambda: token

        if disconnect_current and loop is not None:
            task = loop.create_task(self._revoke_current_session())
            self._revoke_tasks.add(task)
            task.add_done_callback(self._revoke_tasks.discard)

    async def _revoke_current_session(self) -> None:
        async with self._lock:
            stream = self._stream
            self._stream = None
            self._closed_by_us = True
        if stream is None:
            return
        with contextlib.suppress(Exception):
            await asyncio.wait_for(
                stream.send({"type": "revoked"}), timeout=self.revoke_timeout
            )
        with contextlib.suppress(Exception):
            await stream.close()
        with contextlib.suppress(Exception):
            await self._emit_disconnect()

    def _current_token_str(self) -> str:
        if self._token_provider is not None:
            tok = self._token_provider()
            if not isinstance(tok, str) or not tok:
                raise ValueError("token_provider devolvió un token vacío o no-str")
            if self._require_strong_token and len(tok) < MIN_TOKEN_LEN:
                raise ValueError(
                    f"token_provider devolvió un token demasiado corto "
                    f"(mínimo {MIN_TOKEN_LEN})"
                )
            if _token_key(tok) is None:
                raise ValueError("token_provider devolvió un token no codificable en UTF-8")
            return tok
        return self.token

    # ------------------------------------------------------------------ #
    # Ciclo de vida
    # ------------------------------------------------------------------ #
    async def start(self, timeout: Optional[float] = None) -> None:
        async def _start_server() -> None:
            self._server = await asyncio.start_server(
                self._handle_client,
                self.host,
                self.port,
                ssl=self.ssl_context,
                ssl_handshake_timeout=(
                    self.handshake_timeout if self.ssl_context is not None else None
                ),
                backlog=64,
            )
            log.info("WiFiServer escuchando en %s:%d", self.host, self.port)
            if self.enable_zeroconf:
                await self._register_zeroconf()

        if timeout is not None:
            await asyncio.wait_for(_start_server(), timeout=timeout)
        else:
            await _start_server()

    async def _register_zeroconf(self) -> None:
        if not _HAS_ZEROCONF:
            log.info("zeroconf no instalado; descubrimiento mDNS deshabilitado")
            return
        if _is_loopback(self.host):
            log.info("Servidor en loopback; zeroconf no aplica")
            return
        ip = _local_ip()
        if ip is None:
            log.info("Sin IP de LAN utilizable; zeroconf deshabilitado")
            return
        try:
            self._zeroconf = AsyncZeroconf()
            try:
                ip_bytes = socket.inet_aton(ip)
            except OSError:
                try:
                    ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
                except OSError:
                    log.warning("IP %s no es IPv4 ni IPv6 válida para zeroconf", ip)
                    return
            self._service_info = ServiceInfo(
                SERVICE_TYPE,
                f"{self.service_name}.{SERVICE_TYPE}",
                addresses=[ip_bytes],
                port=self.port,
                properties={"token_required": "1"},
            )
            await self._zeroconf.async_register_service(self._service_info)
        except Exception:
            log.exception("No se pudo registrar el servicio zeroconf")
            if self._zeroconf is not None:
                with contextlib.suppress(Exception):
                    await self._zeroconf.async_close()
            self._zeroconf = None
            self._service_info = None

    # ------------------------------------------------------------------ #
    # Manejo de cliente
    # ------------------------------------------------------------------ #
    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"
        stream = MessageStream(reader, writer)
        try:
            if self._rate_limiter is not None and await self._rate_limiter.is_blocked(ip):
                log.warning("Rate limit activo para %s", ip)
                with contextlib.suppress(Exception):
                    await stream.send({"type": "error", "reason": RATE_LIMITED})
                return

            # Pre-auth sem con timeout para no saturar
            try:
                await asyncio.wait_for(
                    self._preauth_sem.acquire(), timeout=self.preauth_sem_timeout
                )
            except asyncio.TimeoutError:
                log.warning("Demasiadas conexiones pre-auth; rechazando %s", peer)
                return
            try:
                try:
                    await asyncio.wait_for(
                        self._handshake_sem.acquire(),
                        timeout=self.handshake_sem_timeout,
                    )
                except asyncio.TimeoutError:
                    log.warning("Handshake saturado; rechazando %s", peer)
                    return
                try:
                    authed, reject_reason = await self._do_handshake(stream, peer, ip)
                finally:
                    self._handshake_sem.release()
            finally:
                self._preauth_sem.release()

            if not authed:
                if reject_reason is not None:
                    if reject_reason != RATE_LIMITED:
                        await asyncio.sleep(self.auth_fail_delay)
                    with contextlib.suppress(Exception):
                        await stream.send({"type": "error", "reason": reject_reason})
                return

            await self._serve_session(stream, peer, ip)
        except Exception:
            log.exception("Error en cliente %s", peer)
        finally:
            await close_quietly(writer)

    async def _do_handshake(
        self,
        stream: MessageStream,
        peer: Any,
        ip: str,
    ) -> Tuple[bool, Optional[str]]:
        log.info("Cliente conectado: %s", peer)

        try:
            hello = await asyncio.wait_for(
                stream.recv(max_size=HANDSHAKE_MAX),
                timeout=self.handshake_timeout,
            )
        except asyncio.TimeoutError:
            await self._record_auth_failure(ip, is_version_mismatch=False)
            log.warning("Timeout de handshake (hello) desde %s", peer)
            return False, None
        except ProtocolError as exc:
            await self._record_auth_failure(ip, is_version_mismatch=False)
            log.info("Protocolo inválido (hello) desde %s: %s", peer, exc)
            return False, None
        except (asyncio.IncompleteReadError, ConnectionError):
            log.info("Cliente desconectado durante handshake: %s", peer)
            return False, None

        if not isinstance(hello, dict) or hello.get("type") != "hello":
            await self._record_auth_failure(ip, is_version_mismatch=False)
            log.warning("Handshake inválido (esperado hello) desde %s", peer)
            return False, AUTH_FAILED

        client_version = hello.get("protocol_version")
        if client_version != PROTOCOL_VERSION:
            await self._record_auth_failure(ip, is_version_mismatch=True)
            log.warning(
                "Versión de protocolo incompatible desde %s: %r (esperada %d)",
                peer, client_version, PROTOCOL_VERSION,
            )
            return False, PROTOCOL_VERSION_MISMATCH

        nonce = secrets.token_bytes(NONCE_SIZE)
        try:
            await stream.send({
                "type": "challenge",
                "nonce": nonce.hex(),
                "protocol_version": PROTOCOL_VERSION,
            })
        except (ConnectionError, OSError):
            log.info("Cliente desconectado al enviar challenge: %s", peer)
            return False, None

        try:
            auth = await asyncio.wait_for(
                stream.recv(max_size=HANDSHAKE_MAX),
                timeout=self.handshake_timeout,
            )
        except asyncio.TimeoutError:
            await self._record_auth_failure(ip, is_version_mismatch=False)
            log.warning("Timeout de handshake (auth) desde %s", peer)
            return False, None
        except ProtocolError as exc:
            await self._record_auth_failure(ip, is_version_mismatch=False)
            log.info("Protocolo inválido (auth) desde %s: %s", peer, exc)
            return False, None
        except (asyncio.IncompleteReadError, ConnectionError):
            log.info("Cliente desconectado durante auth: %s", peer)
            return False, None

        if (
            not isinstance(auth, dict)
            or auth.get("type") != "auth"
            or not isinstance(auth.get("mac"), str)
        ):
            await self._record_auth_failure(ip, is_version_mismatch=False)
            log.warning("Handshake inválido (esperado auth+mac) desde %s", peer)
            return False, AUTH_FAILED

        provided_mac_hex = auth["mac"]
        if len(provided_mac_hex) != 64:
            await self._record_auth_failure(ip, is_version_mismatch=False)
            log.warning("MAC longitud inválida desde %s", peer)
            return False, AUTH_FAILED
        try:
            provided_mac = bytes.fromhex(provided_mac_hex)
        except (ValueError, TypeError):
            await self._record_auth_failure(ip, is_version_mismatch=False)
            log.warning("MAC no es hex válido desde %s", peer)
            return False, AUTH_FAILED
        if len(provided_mac) != 32:
            await self._record_auth_failure(ip, is_version_mismatch=False)
            return False, AUTH_FAILED

        try:
            expected_token = self._current_token_str()
        except Exception as exc:
            log.warning(
                "token_provider falló (%s: %s); rechazando a %s",
                type(exc).__name__, exc, peer,
            )
            log.debug("Detalle del fallo de token_provider", exc_info=True)
            return False, SERVER_ERROR

        expected_mac = _compute_mac(expected_token, nonce)
        if expected_mac is None or not secrets.compare_digest(provided_mac, expected_mac):
            await self._record_auth_failure(ip, is_version_mismatch=False)
            log.warning("Auth fallida (HMAC incorrecto) desde %s", peer)
            return False, AUTH_FAILED

        if self._rate_limiter is not None:
            await self._rate_limiter.record_success(ip)

        await stream.send({
            "type": "auth_ok",
            "protocol_version": PROTOCOL_VERSION,
        })
        return True, None

    async def _record_auth_failure(self, ip: str, is_version_mismatch: bool) -> None:
        if is_version_mismatch:
            return
        if self._rate_limiter is not None:
            await self._rate_limiter.record_failure(ip)

    async def _serve_session(
        self,
        stream: MessageStream,
        peer: Any,
        ip: str,
    ) -> None:
        async with self._lock:
            old = self._stream
            self._stream = stream
            self._closed_by_us = False
        if old is not None and old is not stream:
            log.info("Reemplazando cliente previo")
            with contextlib.suppress(Exception):
                await old.send({"type": "replaced"})
            with contextlib.suppress(Exception):
                await old.close()

        should_emit_disconnect = False
        try:
            await self._emit_connect()
            while True:
                msg = await stream.recv(
                    max_size=self.max_payload,
                    idle_timeout=self.idle_timeout,
                )
                await self._emit_message(msg)
        except ProtocolError as exc:
            log.info("Protocolo inválido desde %s: %s", peer, exc)
        except (asyncio.IncompleteReadError, ConnectionError):
            log.info("Cliente desconectado: %s", peer)
        finally:
            async with self._lock:
                if self._stream is stream:
                    self._stream = None
                    self._closed_by_us = True
                    should_emit_disconnect = True
            with contextlib.suppress(Exception):
                await stream.close()
            if should_emit_disconnect:
                with contextlib.suppress(Exception):
                    await self._emit_disconnect()

    # ------------------------------------------------------------------ #
    # Envío / desconexión / stop
    # ------------------------------------------------------------------ #
    async def send(self, obj: Any) -> None:
        # [FIX v0.4 BLOCKER 1] Extraer stream y cerrarlo sin re-adquirir el lock.
        async with self._lock:
            stream = self._stream
            if stream is None:
                raise ConnectionError("No hay cliente conectado")
            try:
                await asyncio.wait_for(stream.send(obj), timeout=self.send_timeout)
            except asyncio.TimeoutError as exc:
                log.warning("Timeout al enviar; cerrando conexión")
                # Mutamos bajo el mismo lock, sin llamar a disconnect()
                self._stream = None
                self._closed_by_us = True
                with contextlib.suppress(Exception):
                    await stream.close()
                raise ConnectionError("Timeout al enviar") from exc

    async def disconnect(self) -> None:
        async with self._lock:
            stream = self._stream
            self._stream = None
            self._closed_by_us = True
        if stream is not None:
            with contextlib.suppress(Exception):
                await stream.close()

    async def stop(self) -> None:
        if self._revoke_tasks:
            _, still = await asyncio.wait(
                list(self._revoke_tasks), timeout=self.revoke_timeout
            )
            for t in still:
                t.cancel()
            if still:
                await asyncio.gather(*still, return_exceptions=True)
            self._revoke_tasks.clear()
        await self.disconnect()
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        if self._zeroconf is not None:
            with contextlib.suppress(Exception):
                if self._service_info is not None:
                    await self._zeroconf.async_unregister_service(self._service_info)
                else:
                    await self._zeroconf.async_unregister_all_services()
            with contextlib.suppress(Exception):
                await self._zeroconf.async_close()
            self._zeroconf = None
            self._service_info = None


# --------------------------------------------------------------------------- #
# Cliente
# --------------------------------------------------------------------------- #
class WiFiClient(Transport):
    def __init__(
        self,
        host: str,
        token: str,
        port: int = DEFAULT_PORT,
        reconnect: bool = True,
        max_backoff: float = 30.0,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        ssl_context: Optional[ssl.SSLContext] = None,
        allow_insecure_lan: bool = False,
        min_stable_seconds: float = 3.0,
        on_auth_error: Optional[Callable[[str], Any]] = None,
        allow_insecure_tls: bool = False,
        *,
        # [FIX v0.4] Límites configurables
        max_payload: int = MAX_PAYLOAD,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
        send_timeout: float = DEFAULT_SEND_TIMEOUT,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        on_session_terminated: Optional[Callable[[str], Any]] = None,
    ) -> None:
        super().__init__()
        if not token:
            raise ValueError("Se requiere un token no vacío")
        _check_tls_context(
            ssl_context, is_server=False,
            host=host, allow_insecure_tls=allow_insecure_tls,
        )
        if ssl_context is None and not _is_loopback(host) and not allow_insecure_lan:
            raise ValueError(
                "Sin TLS solo se permite conectar a loopback. "
                "Configura ssl_context o allow_insecure_lan=True conscientemente."
            )
        if allow_insecure_lan or allow_insecure_tls:
            log.warning("Modo inseguro activo en cliente (LAN o TLS sin verificación)!")
        if (
            ssl_context is not None
            and ssl_context.verify_mode == ssl.CERT_NONE
            and not _is_loopback(host)
            and not allow_insecure_tls
        ):
            raise ValueError(
                "ssl_context con verify_mode=CERT_NONE no verifica al servidor "
                "y expondría el token a un MITM."
            )
        if max_payload <= 0:
            raise ValueError("max_payload debe ser > 0")

        self.host = host
        self.port = port
        self.token = token
        self.reconnect = reconnect
        self.max_backoff = max_backoff
        self.connect_timeout = connect_timeout
        self.ssl_context = ssl_context
        self.min_stable_seconds = min_stable_seconds
        self.on_auth_error = on_auth_error
        self.on_session_terminated = on_session_terminated

        # [FIX v0.4] Límites configurables
        self.max_payload = max_payload
        self.handshake_timeout = handshake_timeout
        self.send_timeout = send_timeout
        self.idle_timeout = idle_timeout

        self._stream: Optional[MessageStream] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._connected = asyncio.Event()
        self._lock = asyncio.Lock()
        self._auth_rejected = False
        self._last_auth_error: Optional[ConnectionError] = None
        self._replaced_or_revoked = False

    def is_connected(self) -> bool:
        return self._stream is not None

    def last_rx_time(self) -> Optional[float]:
        stream = self._stream
        return stream.last_rx if stream is not None else None

    async def start(self, timeout: Optional[float] = None) -> None:
        if self._running:
            raise RuntimeError("WiFiClient ya iniciado")
        self._running = True
        self._connected.clear()
        self._auth_rejected = False
        self._last_auth_error = None
        self._replaced_or_revoked = False
        self._task = asyncio.create_task(self._connect_with_retry())

        try:
            if timeout is not None:
                await asyncio.wait_for(self._connected.wait(), timeout=timeout)
            else:
                await self._connected.wait()
        except asyncio.TimeoutError:
            auth_err = self._last_auth_error
            task_exc = None
            if self._task.done() and not self._task.cancelled():
                task_exc = self._task.exception()
            await self._cleanup_failed_start()
            if isinstance(auth_err, AuthRejected):
                raise auth_err
            if isinstance(task_exc, AuthRejected):
                raise task_exc
            cause = task_exc or auth_err
            if cause is not None:
                raise ConnectionError("No se pudo conectar") from cause
            raise ConnectionError("No se pudo conectar (timeout)")
        if self._last_auth_error and not self._connected.is_set():
            auth_err = self._last_auth_error
            await self._cleanup_failed_start()
            raise auth_err

    async def _cleanup_failed_start(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _open_stream(self) -> MessageStream:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.host,
                self.port,
                ssl=self.ssl_context,
                ssl_handshake_timeout=(
                    self.connect_timeout if self.ssl_context is not None else None
                ),
            ),
            timeout=self.connect_timeout,
        )
        return MessageStream(reader, writer)

    async def _call_auth_error(self, reason: str) -> None:
        reason = _validate_reason(reason)
        if self.on_auth_error is None:
            return
        try:
            res = self.on_auth_error(reason)
            if inspect.isawaitable(res):
                await res
        except Exception:
            log.exception("on_auth_error falló")

    async def _call_session_terminated(self, reason: str) -> None:
        """[FIX v0.4] Notifica a la app que la sesión fue terminada por el
        servidor (replaced/revoked) sin marcarla como auth_rejected."""
        if self.on_session_terminated is None:
            return
        try:
            res = self.on_session_terminated(reason)
            if inspect.isawaitable(res):
                await res
        except Exception:
            log.exception("on_session_terminated falló")

    async def _connect_with_retry(self) -> None:
        backoff = 0.5
        while self._running:
            stream: Optional[MessageStream] = None
            connected_at = 0.0
            try:
                stream = await self._open_stream()
                try:
                    await asyncio.wait_for(
                        stream.send({
                            "type": "hello",
                            "protocol_version": PROTOCOL_VERSION,
                        }),
                        timeout=self.handshake_timeout,
                    )
                except asyncio.TimeoutError:
                    raise ConnectionError("Timeout enviando hello")

                challenge = await asyncio.wait_for(
                    stream.recv(max_size=HANDSHAKE_MAX),
                    timeout=self.handshake_timeout,
                )
                if (
                    not isinstance(challenge, dict)
                    or challenge.get("type") != "challenge"
                    or not isinstance(challenge.get("nonce"), str)
                ):
                    reason = _validate_reason(
                        challenge.get("reason", "malformed_challenge")
                        if isinstance(challenge, dict)
                        else "malformed_challenge"
                    )
                    await self._call_auth_error(reason)
                    err: ConnectionError = (
                        TransientAuthError(reason)
                        if reason in TRANSIENT_AUTH_REASONS
                        else AuthRejected(reason)
                    )
                    self._last_auth_error = err
                    raise err

                nonce_hex = challenge["nonce"]
                if len(nonce_hex) != NONCE_SIZE * 2:
                    err = AuthRejected("malformed_nonce")
                    self._last_auth_error = err
                    raise err
                try:
                    nonce = bytes.fromhex(nonce_hex)
                except (ValueError, TypeError):
                    err = AuthRejected("malformed_nonce")
                    self._last_auth_error = err
                    raise err
                if len(nonce) != NONCE_SIZE:
                    err = AuthRejected("malformed_nonce")
                    self._last_auth_error = err
                    raise err

                mac_hex = _mac_hex(self.token, nonce)
                if mac_hex is None:
                    err = AuthRejected("invalid_token")
                    self._last_auth_error = err
                    raise err

                try:
                    await asyncio.wait_for(
                        stream.send({"type": "auth", "mac": mac_hex}),
                        timeout=self.handshake_timeout,
                    )
                except asyncio.TimeoutError:
                    raise ConnectionError("Timeout enviando auth")

                reply = await asyncio.wait_for(
                    stream.recv(max_size=HANDSHAKE_MAX),
                    timeout=self.handshake_timeout,
                )
                if not isinstance(reply, dict) or reply.get("type") != "auth_ok":
                    reason = _validate_reason(
                        reply.get("reason", "unknown")
                        if isinstance(reply, dict) else "malformed_reply"
                    )
                    await self._call_auth_error(reason)
                    err = (
                        TransientAuthError(reason)
                        if reason in TRANSIENT_AUTH_REASONS
                        else AuthRejected(reason)
                    )
                    self._last_auth_error = err
                    raise err

                async with self._lock:
                    self._stream = stream
                self._connected.set()
                connected_at = asyncio.get_running_loop().time()

                await self._emit_connect()
                await self._read_loop(stream)

                duration = asyncio.get_running_loop().time() - connected_at
                if duration >= self.min_stable_seconds:
                    backoff = 0.5

                if not self.reconnect or not self._running:
                    break

            except asyncio.CancelledError:
                raise
            except AuthRejected as exc:
                log.error("Auth rechazada de forma terminal: %s", exc.reason)
                self._auth_rejected = True
                self._running = False
                break
            except TransientAuthError as exc:
                log.warning("Auth transitoria fallida (%s); reintentando", exc.reason)
            except ConnectionError as exc:
                log.warning("Conexión fallida (%s)", exc)
            except Exception as exc:
                log.warning("Conexión fallida (%s)", exc)
            finally:
                if stream is not None:
                    with contextlib.suppress(Exception):
                        await stream.close()
                async with self._lock:
                    if self._stream is stream:
                        self._stream = None
                if not self._running or not self.reconnect:
                    self._connected.clear()

            if not self.reconnect or not self._running:
                break
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, self.max_backoff)

    async def _read_loop(self, stream: MessageStream) -> None:
        try:
            while True:
                msg = await stream.recv(
                    max_size=self.max_payload,
                    idle_timeout=self.idle_timeout,
                )
                if isinstance(msg, dict):
                    t = msg.get("type")
                    if t in ("replaced", "revoked"):
                        log.warning(
                            "Sesión terminada por el servidor: %s", t
                        )
                        self._running = False
                        self._replaced_or_revoked = True
                        # [FIX v0.4] Notificar a la app sin marcarlo como auth_rejected
                        await self._call_session_terminated(t)
                        break
                await self._emit_message(msg)
        except ProtocolError:
            pass
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            async with self._lock:
                if self._stream is stream:
                    self._stream = None
            self._connected.clear()
            with contextlib.suppress(Exception):
                await stream.close()
            with contextlib.suppress(Exception):
                await self._emit_disconnect()

    # ------------------------------------------------------------------ #
    # Envío / desconexión / stop
    # ------------------------------------------------------------------ #
    async def send(self, obj: Any) -> None:
        # [FIX v0.4 BLOCKER 1] Igual que en el servidor: cerrar sin re-adquirir lock.
        async with self._lock:
            stream = self._stream
            if stream is None:
                raise ConnectionError("No conectado")
            try:
                await asyncio.wait_for(stream.send(obj), timeout=self.send_timeout)
            except asyncio.TimeoutError as exc:
                log.warning("Timeout al enviar; cerrando conexión")
                self._stream = None
                with contextlib.suppress(Exception):
                    await stream.close()
                self._connected.clear()
                raise ConnectionError("Timeout al enviar") from exc

    async def disconnect(self) -> None:
        async with self._lock:
            stream = self._stream
            self._stream = None
        self._connected.clear()
        if stream is not None:
            with contextlib.suppress(Exception):
                await stream.close()

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        await self.disconnect()
        self._connected.clear()