import asyncio
import contextlib
import socket
from typing import Any, List

TOKEN = "test-token-123"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Collector:
    def __init__(self) -> None:
        self.messages: List[Any] = []
        self._event = asyncio.Event()

    async def handler(self, msg: Any) -> None:
        self.messages.append(msg)
        self._event.set()

    async def wait_for(self, predicate, timeout: float = 2.0) -> Any:
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            for m in self.messages:
                if predicate(m):
                    return m
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise AssertionError(f"No llegó mensaje. Recibidos: {self.messages}")
            self._event.clear()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._event.wait(), timeout=remaining)