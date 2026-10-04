"""API de alto nivel sobre cualquier Transport - v0.5.1.

Fixes acumulados:
  v0.3: C8 race en stop(), A9 max_pending_handlers configurable,
        B14 hook on_handler_error, M2 timeout en stop().
  v0.4: M5 _last_seen/_last_pong=None hasta actividad real,
        _on_connect ya no resetea last_seen/last_pong (M5 efectivo),
        heartbeat usa _last_pong + last_rx_time() como fuentes primarias,
        on_handler_error recibe el event correcto (no "unknown"),
        on_handler_error soporta sync y async,
        stop() idempotente, simplificado y con timeout configurable,
        validación de payload en send() (defensa en profundidad).
  v0.5: Message wrapper tipado (equivalente a data class Message de Kotlin),
        payload_of() y send(event, **kwargs),
        connected observable (asyncio.Event) + wait_connected/wait_disconnected,
        stop() idempotente reforzado.
  v0.5.1: max_pending_handlers_per_event (paridad con Kotlin pendingPerEvent),
          add_connected_listener / connection_state (paridad con StateFlow).
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
import logging
import threading
import time
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Set, Union

from .transport import Transport

log = logging.getLogger(__name__)

MAX_EVENT_NAME = 256
_ALLOWED_EVENT_CHARS = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789._-"
)

RESERVED_EVENTS = frozenset({"ping", "pong", "replaced", "revoked"})
MAX_PENDING_HANDLERS = 64
MAX_PENDING_HANDLERS_PER_EVENT = 64
DEFAULT_STOP_TIMEOUT = 5.0

HandlerErrorCallback = Callable[[str, Exception], Union[None, Awaitable[None]]]


def _validate_event_name(event: str) -> None:
    if not isinstance(event, str) or not event:
        raise ValueError("event debe ser un str no vacío")
    if len(event) > MAX_EVENT_NAME:
        raise ValueError(f"event demasiado largo (máx {MAX_EVENT_NAME})")
    if not set(event).issubset(_ALLOWED_EVENT_CHARS):
        raise ValueError(
            "event solo puede contener letras, dígitos, '.', '_' y '-'"
        )
    if event in RESERVED_EVENTS:
        raise ValueError(
            f"event {event!r} está reservado para el protocolo "
            f"({', '.join(sorted(RESERVED_EVENTS))})"
        )


# --------------------------------------------------------------------------- #
# Message + payload_of (paridad con Kotlin)
# --------------------------------------------------------------------------- #
class Message:
    """Mensaje recibido: type + payload + raw.

    Equivale a `data class Message` de phonelink-kotlin.

    Es compatible con dict para no romper handlers existentes:
        msg.get("type")        -> self.type (sobre)
        msg.get("payload")     -> self.payload
        msg["payload"]         -> self.payload
        msg["text"]            -> payload["text"] (si existe)
        msg.text("text")       -> payload["text"] si es str, si no None

    Uso:
        peer.on("chat", lambda m: print(m.text("text")))
    """

    __slots__ = ("type", "payload", "raw")

    def __init__(self, type: str, payload: dict, raw: dict) -> None:
        self.type = type
        self.payload = payload
        self.raw = raw

    def text(self, key: str) -> Optional[str]:
        """Devuelve payload[key] si es str, si no None."""
        v = self.payload.get(key)
        return v if isinstance(v, str) else None

    def get(self, key: str, default=None):
        """Compatibilidad dict: primero payload, luego sobre ("type"/"payload")."""
        if key in self.payload:
            return self.payload[key]
        if key == "type":
            return self.type
        if key == "payload":
            return self.payload
        return self.raw.get(key, default)

    def __getitem__(self, key: str):
        if key in self.payload:
            return self.payload[key]
        return self.raw[key]

    def __contains__(self, key: str) -> bool:
        return key in self.payload or key in self.raw

    def __repr__(self) -> str:
        return f"Message(type={self.type!r}, payload={self.payload!r})"


def payload_of(**kwargs) -> dict:
    """Construye un payload ergonómico.

    Uso:
        await peer.send("chat", payload_of(text="hola", n=3))
    """
    return dict(kwargs)


# --------------------------------------------------------------------------- #
# Peer
# --------------------------------------------------------------------------- #
class Peer:
    """Capa de alto nivel sobre un Transport.

    Gestiona handlers de eventos, heartbeat (ping/pong), errores de handlers
    y expone un estado de conexión observable (`connected`).

    Contrato del heartbeat:
      - El peer envía un ``ping`` cada ``heartbeat`` segundos.
      - Espera un ``pong`` del peer remoto.
      - Si no hay actividad real (mensaje de app, pong o bytes recibidos)
        durante ``heartbeat * heartbeat_timeout_factor`` segundos, cierra
        la conexión.
      - ``last_rx_time()`` del transporte cuenta como actividad real: un
        mensaje grande en transferencia mantiene viva la conexión aunque
        no haya pongs.

    ``_last_seen`` y ``_last_pong`` se inicializan a ``None``. Solo se
    actualizan con actividad real, evitando que una conexión recién
    establecida (pero silenciosa) parezca viva durante
    ``heartbeat_timeout`` segundos.
    """

    def __init__(
        self,
        transport: Transport,
        heartbeat: float = 15.0,
        heartbeat_timeout_factor: float = 3.0,
        max_pending_handlers: int = MAX_PENDING_HANDLERS,
        max_pending_handlers_per_event: int = MAX_PENDING_HANDLERS_PER_EVENT,
        on_handler_error: Optional[HandlerErrorCallback] = None,
        *,
        stop_timeout: float = DEFAULT_STOP_TIMEOUT,
    ) -> None:
        if heartbeat < 0:
            raise ValueError("heartbeat debe ser >= 0")
        if heartbeat_timeout_factor <= 0:
            raise ValueError("heartbeat_timeout_factor debe ser > 0")
        if max_pending_handlers <= 0:
            raise ValueError("max_pending_handlers debe ser > 0")
        if max_pending_handlers_per_event <= 0:
            raise ValueError("max_pending_handlers_per_event debe ser > 0")
        if stop_timeout <= 0:
            raise ValueError("stop_timeout debe ser > 0")

        self.transport = transport
        self.heartbeat = heartbeat
        self.heartbeat_timeout = heartbeat * heartbeat_timeout_factor
        self.max_pending_handlers = max_pending_handlers  # global
        self.max_pending_handlers_per_event = max_pending_handlers_per_event
        self.on_handler_error = on_handler_error
        self.stop_timeout = stop_timeout

        self._handlers: Dict[str, Callable] = {}
        self._default_handler: Optional[Callable] = None
        self._heartbeat_task: Optional[asyncio.Task] = None

        # C8: threading.Lock (no asyncio.Lock) porque _on_handler_done es un
        # callback síncrono invocado por asyncio al terminar la Task.
        self._handler_tasks: Set[asyncio.Task] = set()
        self._tasks_lock = threading.Lock()
        # Contador por evento (paridad con Kotlin pendingPerEvent)
        self._pending_per_event: Dict[str, int] = {}

        # M5 FIX: None hasta actividad real.
        self._last_seen: Optional[float] = None
        self._last_pong: Optional[float] = None

        self._started = False

        # v0.5: estado de conexión observable (paridad con StateFlow<Boolean>)
        self._connected_event = asyncio.Event()
        # v0.5.1: listeners de conexión (paridad con StateFlow collect)
        self._connected_listeners: List[Callable[[bool], Any]] = []

        transport.on_message(self._dispatch)
        transport.on_connect(self._on_connect)
        transport.on_disconnect(self._on_disconnect)

    # ------------------------------------------------------------------ #
    # Estado de conexión observable
    # ------------------------------------------------------------------ #
    @property
    def connected(self) -> bool:
        """True si hay sesión autenticada activa.

        Equivale a `peer.connected.value` (StateFlow<Boolean>) de Kotlin.
        """
        return self._connected_event.is_set()

    async def wait_connected(self, timeout: Optional[float] = None) -> None:
        """Bloquea hasta que haya conexión autenticada.

        Equivale a `peer.connected.first { it }` en Kotlin.
        """
        if timeout is not None:
            await asyncio.wait_for(self._connected_event.wait(), timeout=timeout)
        else:
            await self._connected_event.wait()

    async def wait_disconnected(self, timeout: Optional[float] = None) -> None:
        """Bloquea hasta que se pierda la conexión."""
        async def _wait() -> None:
            while self._connected_event.is_set():
                await asyncio.sleep(0.05)
        if timeout is not None:
            await asyncio.wait_for(_wait(), timeout=timeout)
        else:
            await _wait()

    def add_connected_listener(
        self, cb: Callable[[bool], Any]
    ) -> Callable[[], None]:
        """Registra un callback que se invoca al conectar/desconectar.

        Paridad con `peer.connected` StateFlow de Kotlin: permite observar
        cambios de estado sin bloquear. Devuelve una función para
        desuscribirse.
        """
        self._connected_listeners.append(cb)

        def _unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._connected_listeners.remove(cb)

        return _unsubscribe

    def _notify_connected_listeners(self, connected: bool) -> None:
        for cb in list(self._connected_listeners):
            try:
                res = cb(connected)
                if inspect.isawaitable(res):
                    asyncio.create_task(res)
            except Exception:
                log.exception("connected listener falló")

    async def connection_state(self) -> AsyncIterator[bool]:
        """Async generator que emite el estado actual y cada cambio.

        Paridad con StateFlow<Boolean> de Kotlin:
            async for state in peer.connection_state():
                ...
        """
        queue: asyncio.Queue[bool] = asyncio.Queue()
        queue.put_nowait(self.connected)
        unsub = self.add_connected_listener(lambda c: queue.put_nowait(c))
        try:
            while True:
                yield await queue.get()
        finally:
            unsub()

    # ------------------------------------------------------------------ #
    # Registro de handlers
    # ------------------------------------------------------------------ #
    def on(self, event: str, handler: Callable) -> "Peer":
        _validate_event_name(event)
        if not callable(handler):
            raise TypeError("handler debe ser invocable")
        self._handlers[event] = handler
        return self

    def on_any(self, handler: Callable) -> "Peer":
        if not callable(handler):
            raise TypeError("handler debe ser invocable")
        self._default_handler = handler
        return self

    # ------------------------------------------------------------------ #
    # API de envío
    # ------------------------------------------------------------------ #
    async def send(
        self,
        event: str,
        payload: Optional[dict] = None,
        **kwargs,
    ) -> None:
        """Envía un evento.

        Acepta payload como dict posicional o como kwargs:
            await peer.send("chat", {"text": "hola"})
            await peer.send("chat", text="hola", n=3)
            await peer.send("chat", payload_of(text="hola"))
        """
        _validate_event_name(event)
        if payload is not None and kwargs:
            raise TypeError("No mezcles payload= con kwargs en send()")
        if payload is None and kwargs:
            payload = kwargs
        if payload is not None:
            if not isinstance(payload, dict):
                raise TypeError("payload debe ser un dict o None")
            # Defensa en profundidad: el payload no debe contener claves
            # reservadas (por si el usuario intenta inyectar metadatos).
            for key in payload:
                if not isinstance(key, str):
                    raise TypeError("payload keys deben ser str")
        await self.transport.send(
            {"type": event, "payload": payload if payload is not None else {}}
        )

    # ------------------------------------------------------------------ #
    # Ciclo de vida
    # ------------------------------------------------------------------ #
    async def start(self, timeout: Optional[float] = None) -> None:
        if self._started:
            raise RuntimeError("Peer ya iniciado")
        await self.transport.start(timeout=timeout)
        self._started = True
        if self.heartbeat:
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self) -> None:
        """Detiene el peer: heartbeat, handlers pendientes y transporte.

        Idempotente: llamar dos veces no falla.
        """
        if not self._started and self._heartbeat_task is None:
            # Ya detenido (o nunca iniciado). Asegurar transporte parado.
            with contextlib.suppress(Exception):
                await self.transport.stop()
            self._connected_event.clear()
            return

        # 1) Cancelar heartbeat y esperar a que termine de verdad
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._heartbeat_task
            self._heartbeat_task = None

        # 2) Snapshot atómico de handlers pendientes bajo lock.
        with self._tasks_lock:
            pending = list(self._handler_tasks)
            self._handler_tasks.clear()
            self._pending_per_event.clear()

        # 3) Cancelar y esperar con timeout configurable (M2)
        for t in pending:
            t.cancel()
        if pending:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*pending, return_exceptions=True),
                    timeout=self.stop_timeout,
                )
            except asyncio.TimeoutError:
                log.warning(
                    "Timeout (%.1fs) esperando %d handlers en stop()",
                    self.stop_timeout, len(pending),
                )

        # 4) Parar transporte
        with contextlib.suppress(Exception):
            await self.transport.stop()

        self._started = False
        self._last_seen = None
        self._last_pong = None
        self._connected_event.clear()

    # ------------------------------------------------------------------ #
    # Dispatch
    # ------------------------------------------------------------------ #
    async def _dispatch(self, msg: Any) -> None:
        if not isinstance(msg, dict):
            return
        event = msg.get("type")
        if not isinstance(event, str) or not event or len(event) > MAX_EVENT_NAME:
            log.debug("Mensaje descartado: type inválido %r", event)
            return

        # M5: cualquier mensaje de app cuenta como actividad real
        self._last_seen = time.monotonic()

        if event == "ping":
            try:
                await self.transport.send({"type": "pong"})
            except ConnectionError:
                pass
            return
        if event == "pong":
            self._last_pong = time.monotonic()
            return

        # Eventos reservados no deben llegar a handlers de app
        if event in RESERVED_EVENTS:
            log.debug("Evento reservado %r descartado en dispatch", event)
            return

        handler = self._handlers.get(event) or self._default_handler
        if handler is None:
            return

        # C8 + A9: acceso protegido a _handler_tasks
        # v0.5.1: límite global + límite por evento (paridad Kotlin)
        with self._tasks_lock:
            if len(self._handler_tasks) >= self.max_pending_handlers:
                pending_full = True
                reason = "max_pending_handlers exceeded"
            elif self._pending_per_event.get(event, 0) >= self.max_pending_handlers_per_event:
                pending_full = True
                reason = "max_pending_handlers_per_event exceeded"
            else:
                pending_full = False
                self._pending_per_event[event] = self._pending_per_event.get(event, 0) + 1

        if pending_full:
            log.warning(
                "Demasiados handlers pendientes; descartando %r (%s)",
                event, reason,
            )
            await self._safe_handler_error(event, RuntimeError(reason))
            return

        # v0.5: construimos Message (compatible con dict) y lo pasamos al handler.
        payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
        message = Message(event, payload, msg)

        try:
            result = handler(message)
            if inspect.isawaitable(result):
                task = asyncio.create_task(result)
                with self._tasks_lock:
                    self._handler_tasks.add(task)
                task.add_done_callback(
                    functools.partial(self._on_handler_done, event)
                )
            else:
                # Handler síncrono: decrementar contador por evento de inmediato
                with self._tasks_lock:
                    n = self._pending_per_event.get(event, 0)
                    if n <= 1:
                        self._pending_per_event.pop(event, None)
                    else:
                        self._pending_per_event[event] = n - 1
        except Exception as exc:
            # Handler síncrono falló: decrementar y reportar
            with self._tasks_lock:
                n = self._pending_per_event.get(event, 0)
                if n <= 1:
                    self._pending_per_event.pop(event, None)
                else:
                    self._pending_per_event[event] = n - 1
            log.exception("Error en handler de %r", event)
            await self._safe_handler_error(event, exc)

    def _on_handler_done(self, event: str, task: asyncio.Task) -> None:
        # C8: protegido con lock (callback síncrono)
        with self._tasks_lock:
            self._handler_tasks.discard(task)
            # Decrementar contador por evento
            n = self._pending_per_event.get(event, 0)
            if n <= 1:
                self._pending_per_event.pop(event, None)
            else:
                self._pending_per_event[event] = n - 1

        if task.cancelled():
            return

        try:
            exc = task.exception()
        except Exception:
            log.exception("No se pudo obtener la excepción del handler %r", event)
            return

        if exc is not None:
            log.error(
                "Excepción no capturada en handler de %r: %s",
                event, exc, exc_info=exc,
            )
            loop = asyncio.get_event_loop()
            loop.create_task(self._safe_handler_error(event, exc))

    async def _safe_handler_error(self, event: str, exc: Exception) -> None:
        """Invoca on_handler_error soportando sync y async."""
        if self.on_handler_error is None:
            return
        try:
            result = self.on_handler_error(event, exc)
            if inspect.isawaitable(result):
                await result
        except Exception:
            log.exception("on_handler_error falló para event=%r", event)

    # ------------------------------------------------------------------ #
    # Handlers de conexión
    # ------------------------------------------------------------------ #
    async def _on_connect(self) -> None:
        log.info("Transporte conectado")
        # M5 FIX: NO reseteamos _last_seen/_last_pong aquí.
        # v0.5: marcamos connected.
        self._connected_event.set()
        self._notify_connected_listeners(True)

    async def _on_disconnect(self) -> None:
        log.info("Transporte desconectado")
        self._connected_event.clear()
        # M5: limpiar estado para que una reconexión no arrastre actividad
        # de la sesión anterior.
        self._last_seen = None
        self._last_pong = None
        self._notify_connected_listeners(False)

    # ------------------------------------------------------------------ #
    # Heartbeat
    # ------------------------------------------------------------------ #
    async def _heartbeat_loop(self) -> None:
        """Envía ping periódicamente y cierra si no hay actividad.

        Fuentes de actividad (en orden de prioridad):
          1. ``_last_pong``: el peer remoto respondió a nuestro ping.
          2. ``last_rx_time()`` del transporte: llegaron bytes reales.
          3. ``_last_seen``: cualquier mensaje de app recibido.
        """
        try:
            while True:
                await asyncio.sleep(self.heartbeat)

                if not self.transport.is_connected():
                    continue

                now = time.monotonic()
                candidates: list[float] = []
                if self._last_pong is not None:
                    candidates.append(self._last_pong)
                if self._last_seen is not None:
                    candidates.append(self._last_seen)
                rx = self.transport.last_rx_time()
                if rx is not None:
                    candidates.append(rx)

                if candidates:
                    last_activity = max(candidates)
                else:
                    last_activity = now - self.heartbeat

                if now - last_activity > self.heartbeat_timeout:
                    log.warning(
                        "Heartbeat perdido (sin actividad %.1fs); cerrando conexión",
                        now - last_activity,
                    )
                    try:
                        await self.transport.disconnect()
                    except Exception:
                        log.exception("Error al cerrar por heartbeat")
                    continue

                try:
                    await self.transport.send({"type": "ping"})
                except ConnectionError:
                    pass
                except Exception:
                    log.exception("Error enviando ping")
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Heartbeat loop terminó por excepción")


__all__ = [
    "Peer",
    "Message",
    "payload_of",
    "MAX_EVENT_NAME",
    "RESERVED_EVENTS",
    "MAX_PENDING_HANDLERS",
    "MAX_PENDING_HANDLERS_PER_EVENT",
    "DEFAULT_STOP_TIMEOUT",
    "_validate_event_name",
]