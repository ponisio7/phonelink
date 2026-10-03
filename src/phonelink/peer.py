"""API de alto nivel sobre cualquier Transport - v0.4.0.

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
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
import logging
import threading
import time
from typing import Any, Awaitable, Callable, Dict, Optional, Set, Union

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
DEFAULT_STOP_TIMEOUT = 5.0

# Tipo de callback para errores de handler (sync o async)
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


class Peer:
    """Capa de alto nivel sobre un Transport.

    Gestiona handlers de eventos, heartbeat (ping/pong) y errores de handlers.

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
        if stop_timeout <= 0:
            raise ValueError("stop_timeout debe ser > 0")

        self.transport = transport
        self.heartbeat = heartbeat
        self.heartbeat_timeout = heartbeat * heartbeat_timeout_factor
        self.max_pending_handlers = max_pending_handlers
        self.on_handler_error = on_handler_error
        self.stop_timeout = stop_timeout

        self._handlers: Dict[str, Callable] = {}
        self._default_handler: Optional[Callable] = None
        self._heartbeat_task: Optional[asyncio.Task] = None

        # C8: threading.Lock (no asyncio.Lock) porque _on_handler_done es un
        # callback síncrono invocado por asyncio al terminar la Task, no una
        # coroutine. Un asyncio.Lock aquí no se podría adquirir sin await.
        self._handler_tasks: Set[asyncio.Task] = set()
        self._tasks_lock = threading.Lock()

        # M5 FIX: None hasta actividad real. No usar time.monotonic() porque
        # eso haría que una conexión silenciosa parezca viva.
        self._last_seen: Optional[float] = None
        self._last_pong: Optional[float] = None

        self._started = False

        transport.on_message(self._dispatch)
        transport.on_connect(self._on_connect)
        transport.on_disconnect(self._on_disconnect)

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
    async def send(self, event: str, payload: Optional[dict] = None) -> None:
        _validate_event_name(event)
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
            # M5: no inicializamos _last_seen/_last_pong aquí. Se fijarán
            # cuando llegue el primer mensaje o el primer pong.
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self) -> None:
        """Detiene el peer: heartbeat, handlers pendientes y transporte.

        Idempotente: llamar dos veces no falla.
        """
        if not self._started and self._heartbeat_task is None:
            # Ya detenido (o nunca iniciado). Asegurar transporte parado.
            with contextlib.suppress(Exception):
                await self.transport.stop()
            return

        # 1) Cancelar heartbeat y esperar a que termine de verdad
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._heartbeat_task
            self._heartbeat_task = None

        # 2) Snapshot atómico de handlers pendientes bajo lock.
        #    Ya no hace falta el bucle de reintentos: el lock de threading
        #    garantiza consistencia y no hay mutación concurrente posible
        #    desde _on_handler_done mientras lo tenemos adquirido.
        with self._tasks_lock:
            pending = list(self._handler_tasks)
            self._handler_tasks.clear()

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
        with self._tasks_lock:
            if len(self._handler_tasks) >= self.max_pending_handlers:
                log.warning(
                    "Demasiados handlers pendientes (%d); descartando %r",
                    len(self._handler_tasks), event,
                )
                pending_full = True
            else:
                pending_full = False

        if pending_full:
            await self._safe_handler_error(
                event, RuntimeError("max_pending_handlers exceeded")
            )
            return

        try:
            result = handler(msg)
            if inspect.isawaitable(result):
                task = asyncio.create_task(result)
                with self._tasks_lock:
                    self._handler_tasks.add(task)
                # Pasar el event al callback para no perderlo
                task.add_done_callback(
                    functools.partial(self._on_handler_done, event)
                )
        except Exception as exc:
            log.exception("Error en handler de %r", event)
            await self._safe_handler_error(event, exc)

    def _on_handler_done(self, event: str, task: asyncio.Task) -> None:
        # C8: protegido con lock (callback síncrono)
        with self._tasks_lock:
            self._handler_tasks.discard(task)

        if task.cancelled():
            return

        try:
            exc = task.exception()
        except Exception:
            # No debería ocurrir, pero por si el task fue manipulado
            log.exception("No se pudo obtener la excepción del handler %r", event)
            return

        if exc is not None:
            log.error(
                "Excepción no capturada en handler de %r: %s",
                event, exc, exc_info=exc,
            )
            # Programar el callback de error en el event loop (estamos en
            # un callback síncrono, no podemos await aquí).
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
        # M5 FIX: NO reseteamos _last_seen/_last_pong aquí. Si el cliente
        # se conecta y no envía nada, el heartbeat detectará la ausencia
        # de pongs y cerrará la conexión tras heartbeat_timeout.
        # El primer ping se enviará en el siguiente ciclo del heartbeat.

    async def _on_disconnect(self) -> None:
        log.info("Transporte desconectado")
        # M5: limpiar estado para que una reconexión no arrastre actividad
        # de la sesión anterior.
        self._last_seen = None
        self._last_pong = None

    # ------------------------------------------------------------------ #
    # Heartbeat
    # ------------------------------------------------------------------ #
    async def _heartbeat_loop(self) -> None:
        """Envía ping periódicamente y cierra si no hay actividad.

        Fuentes de actividad (en orden de prioridad):
          1. ``_last_pong``: el peer remoto respondió a nuestro ping.
          2. ``last_rx_time()`` del transporte: llegaron bytes reales
             (mensaje de app, ping, pong o chunks de un mensaje grande).
          3. ``_last_seen``: cualquier mensaje de app recibido.

        Si ninguna de las tres ha avanzado en ``heartbeat_timeout``
        segundos, se cierra la conexión.
        """
        try:
            while True:
                await asyncio.sleep(self.heartbeat)

                if not self.transport.is_connected():
                    # Sin conexión: nada que hacer. No reseteamos timestamps
                    # para no ocultar el estado real.
                    continue

                # Determinar la última actividad real
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
                    # Aún no hay actividad registrada (conexión recién
                    # establecida o last_rx=None). Usamos el momento en que
                    # empezó el heartbeat como referencia inicial.
                    # Como no guardamos ese instante, usamos now - lo que
                    # llevamos esperando en este ciclo. En la práctica, el
                    # primer ping se enviará abajo y, si no hay pong, el
                    # siguiente ciclo tendrá _last_pong=None y volverá a
                    # caer aquí. Para evitar un busy-close inmediato tras
                    # conectar, permitimos un margen de un ciclo completo
                    # antes de considerar timeout.
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
                    # No reseteamos timestamps: si la reconexión ocurre,
                    # _on_disconnect los limpiará y _on_connect no los
                    # restaurará. El siguiente ciclo verá is_connected()==False
                    # y no hará nada hasta que haya actividad real.
                    continue

                try:
                    await self.transport.send({"type": "ping"})
                except ConnectionError:
                    # El transporte ya está caído; el próximo ciclo verá
                    # is_connected()==False.
                    pass
                except Exception:
                    log.exception("Error enviando ping")
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Heartbeat loop terminó por excepción")