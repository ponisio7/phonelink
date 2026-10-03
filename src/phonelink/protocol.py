"""Framing y serialización de mensajes - v0.3 parcheado.

Formato en el cable: [4 bytes big-endian con longitud N][N bytes JSON UTF-8].

Fixes aplicados:
- C4: Pre-validación de profundidad JSON para evitar C-Stack Overflow en json.loads
- C11: Rechazo de enteros gigantes (DoS cuadrático)
- M10: Límite de claves/estructura
- B5: Preservar traza en IncompleteReadError
- A6: MAX_PAYLOAD reducido a 1MB configurable
"""

import asyncio
import json
import struct
import time
import re
from typing import Any, Callable, List, Optional

HEADER_SIZE = 4
PROTOCOL_VERSION = 2

# [SEC] Límites - reducidos para librería
MAX_PAYLOAD = 1 * 1024 * 1024  # 1MB, antes 10MB -> A6
HANDSHAKE_MAX = 4 * 1024
CONTROL_MAX = 64 * 1024
DEFAULT_IDLE_TIMEOUT = 60.0
READ_CHUNK = 16 * 1024
NONCE_SIZE = 32

# Nuevos límites para C4, C11, M10
MAX_JSON_DEPTH = 64  # profundidad máxima de anidamiento
MAX_INT_DIGITS = 100  # dígitos máximos en un entero JSON (C11)
MAX_JSON_KEYS = 10_000  # número aproximado máximo de claves

# Regex para detectar enteros largos fuera de strings - usado en pre-validación
_LONG_INT_RE = re.compile(r'(?<!\\)"-?\d{100,}|(?<!")-?\d{100,}')

class ProtocolError(Exception):
    """Error de framing, serialización o validación."""


def encode(obj: Any) -> bytes:
    try:
        data = json.dumps(
            obj, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError(f"Objeto no serializable: {exc}") from exc
    if len(data) > MAX_PAYLOAD:
        raise ProtocolError(f"Payload demasiado grande: {len(data)} bytes")
    return struct.pack(">I", len(data)) + data


def _reject_json_constant(name: str) -> None:
    raise ValueError(f"Constante JSON no permitida: {name}")


def _prevalidate_json_payload(payload: bytes) -> None:
    """Valida profundidad, enteros gigantes y tamaño de estructura antes de json.loads.
    
    C4: Evita C-Stack Overflow por anidamiento profundo.
    C11: Evita DoS por enteros de 1MB de dígitos.
    M10: Evita JSON bombs por exceso de claves.
    """
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"UTF-8 inválido: {exc}") from exc

    # C11: búsqueda rápida de enteros muy largos
    # Si encontramos \d{100,} fuera de contexto simple, rechazamos
    # Hacemos scan rápido sin regex costoso primero
    if len(text) > 100:
        # Escaneo manual para no contar dígitos dentro de strings
        in_string = False
        escape = False
        digit_run = 0
        depth = 0
        max_depth = 0
        colon_count = 0
        
        for ch in text:
            if in_string:
                if escape:
                    escape = False
                elif ch == '\\':
                    escape = True
                elif ch == '"':
                    in_string = False
                continue
            else:
                if ch == '"':
                    in_string = True
                    digit_run = 0
                elif ch == '{' or ch == '[':
                    depth += 1
                    if depth > max_depth:
                        max_depth = depth
                    if max_depth > MAX_JSON_DEPTH:
                        raise ProtocolError(f"JSON demasiado profundo: {max_depth} > {MAX_JSON_DEPTH}")
                    digit_run = 0
                elif ch == '}' or ch == ']':
                    depth -= 1
                    if depth < 0:
                        raise ProtocolError("JSON mal formado: cierre inesperado")
                    digit_run = 0
                elif ch == ':':
                    colon_count += 1
                    if colon_count > MAX_JSON_KEYS:
                        raise ProtocolError(f"Demasiadas claves: >{MAX_JSON_KEYS}")
                    digit_run = 0
                elif ch.isdigit() or (ch == '-' and digit_run == 0):
                    digit_run += 1
                    if digit_run > MAX_INT_DIGITS:
                        raise ProtocolError(f"Entero demasiado largo: >{MAX_INT_DIGITS} dígitos")
                else:
                    digit_run = 0
        # depth final debe ser 0
        if depth != 0:
            raise ProtocolError("JSON mal formado: brackets desbalanceados")


async def _read_exactly(
    reader: asyncio.StreamReader,
    n: int,
    idle_timeout: Optional[float],
    on_activity: Optional[Callable[[], None]],
) -> bytes:
    if idle_timeout is None:
        data = await reader.readexactly(n)
        if on_activity is not None:
            on_activity()
        return data

    chunks: List[bytes] = []
    got = 0
    while got < n:
        size = min(n - got, READ_CHUNK)
        try:
            chunk = await asyncio.wait_for(
                reader.readexactly(size), timeout=idle_timeout
            )
        except asyncio.IncompleteReadError as exc:
            # B5: preservar traza original, antes era from None
            raise asyncio.IncompleteReadError(
                b"".join(chunks) + exc.partial, n
            ) from exc
        except asyncio.TimeoutError as exc:
            raise ProtocolError(
                f"Timeout de inactividad ({idle_timeout}s) leyendo "
                f"{got}/{n} bytes"
            ) from exc
        chunks.append(chunk)
        got += len(chunk)
        if on_activity is not None:
            on_activity()
    return b"".join(chunks)


async def read_message(
    reader: asyncio.StreamReader,
    max_size: int = MAX_PAYLOAD,
    idle_timeout: Optional[float] = None,
    on_activity: Optional[Callable[[], None]] = None,
) -> Any:
    header = await _read_exactly(reader, HEADER_SIZE, idle_timeout, on_activity)
    (n,) = struct.unpack(">I", header)
    if n > max_size:
        raise ProtocolError(
            f"Payload anunciado demasiado grande: {n} > {max_size}"
        )
    payload = await _read_exactly(reader, n, idle_timeout, on_activity)
    
    # C4, C11, M10: pre-validación antes de json.loads
    _prevalidate_json_payload(payload)
    
    try:
        return json.loads(
            payload.decode("utf-8"),
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise ProtocolError(f"JSON inválido: {exc}") from exc


async def write_message(writer: asyncio.StreamWriter, obj: Any) -> None:
    writer.write(encode(obj))
    await writer.drain()


async def close_quietly(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass


class MessageStream:
    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.reader = reader
        self.writer = writer
        self._lock = asyncio.Lock()
        # M5 FIX: last_rx=None hasta el primer byte recibido. Evita que un
        # cliente que se conecta y no envía nada parezca "vivo" hasta
        # heartbeat_timeout. El heartbeat sigue protegiendo mediante ping/pong;
        # last_rx_time() es la métrica de actividad real del socket.
        self.last_rx: Optional[float] = None

    def _touch(self) -> None:
        self.last_rx = time.monotonic()

    async def send(self, obj: Any) -> None:
        async with self._lock:
            writer = self.writer
            writer.write(encode(obj))
        try:
            await writer.drain()
        except OSError as exc:
            raise ConnectionError(str(exc)) from exc

    async def recv(
        self,
        max_size: int = MAX_PAYLOAD,
        idle_timeout: Optional[float] = None,
    ) -> Any:
        return await read_message(
            self.reader,
            max_size=max_size,
            idle_timeout=idle_timeout,
            on_activity=self._touch,
        )

    async def close(self) -> None:
        await close_quietly(self.writer)
