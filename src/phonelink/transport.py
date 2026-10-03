"""Interfaz común para cualquier transporte (WiFi, BLE, WebSocket...).

Todos los métodos deben llamarse desde el event loop de asyncio.
"""

from abc import ABC, abstractmethod
from typing import Any, Awaitable, Callable, Optional

MessageHandler = Callable[[Any], Awaitable[None]]
DisconnectHandler = Callable[[], Awaitable[None]]
ConnectHandler = Callable[[], Awaitable[None]]


class Transport(ABC):
    """Contrato mínimo que WiFi y BLE comparten."""

    def __init__(self) -> None:
        self._message_handler: Optional[MessageHandler] = None
        self._connect_handler: Optional[ConnectHandler] = None
        self._disconnect_handler: Optional[DisconnectHandler] = None

    @abstractmethod
    async def start(self, timeout: Optional[float] = None) -> None:
        """Inicia el transporte.

        timeout: si no es None, la implementación debe esperar como mucho
        ese tiempo a estar lista (servidor escuchando / cliente conectado)
        o lanzar ConnectionError.
        """

    @abstractmethod
    async def send(self, obj: Any) -> None:
        """Envía un mensaje. Solo seguro dentro del event loop."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Cierra la conexión activa sin detener el transporte."""

    @abstractmethod
    async def stop(self) -> None:
        """Cierra el transporte y libera recursos."""

    def is_connected(self) -> bool:
        """True si hay una conexión activa y autenticada.

        El default devuelve False para que transportes sin noción de
        conexión (p. ej. un transporte sin estado) puedan ignorarlo.
        """
        return False

    def last_rx_time(self) -> Optional[float]:
        """Instante (time.monotonic) del último dato recibido, o None.

        Permite al heartbeat distinguir "enlace lento pero vivo" (llegan
        bytes de un mensaje grande) de "enlace muerto". El default None
        significa que el transporte no lo soporta.
        """
        return None

    def on_message(self, handler: MessageHandler) -> None:
        self._message_handler = handler

    def on_connect(self, handler: ConnectHandler) -> None:
        self._connect_handler = handler

    def on_disconnect(self, handler: DisconnectHandler) -> None:
        self._disconnect_handler = handler

    async def _emit_message(self, msg: Any) -> None:
        if self._message_handler is not None:
            await self._message_handler(msg)

    async def _emit_connect(self) -> None:
        if self._connect_handler is not None:
            await self._connect_handler()

    async def _emit_disconnect(self) -> None:
        if self._disconnect_handler is not None:
            await self._disconnect_handler()