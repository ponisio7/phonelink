"""Hook de log opcional para phonelink.

Por defecto, la librería usa `logging` estándar (más potente y flexible).
Este hook existe para entornos embedded (MicroPython, Kivy en Android,
etc.) donde se quiere redirigir los mensajes a un sink simple.

Uso:
    from phonelink import set_log_sink

    def mi_sink(msg: str) -> None:
        print(f"[phonelink] {msg}")

    set_log_sink(mi_sink)
    # ...
    set_log_sink(None)   # desactivar

Equivale a PhoneLinkLog.sink de phonelink-kotlin.
"""

from __future__ import annotations

from typing import Callable, Optional

_sink: Optional[Callable[[str], None]] = None


def set_log_sink(fn: Optional[Callable[[str], None]]) -> None:
    """Instala (o quita con None) un sink de log simple.

    El sink recibe strings ya formateados. Si está instalado, se invoca
    además de `logging` (no en su lugar).
    """
    global _sink
    _sink = fn


def get_log_sink() -> Optional[Callable[[str], None]]:
    """Devuelve el sink actual, o None si no hay."""
    return _sink


def plog(msg: str) -> None:
    """Emite un mensaje al sink instalado (si lo hay)."""
    if _sink is not None:
        try:
            _sink(msg)
        except Exception:
            # Un sink roto nunca debe tumbar la librería.
            pass


__all__ = ["set_log_sink", "get_log_sink", "plog"]