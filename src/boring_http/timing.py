import asyncio
import builtins
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from time import monotonic
from typing import Literal, Self, final

from boring_http.errors import TimeoutError

type Phase = Literal["connect", "read", "write"]


@final
@dataclass(frozen=True, slots=True)
class Timeout:
    connect: float | None = 10.0
    read: float | None = 30.0
    write: float | None = 30.0
    total: float | None = None

    @classmethod
    def of(cls, value: float | Self | None) -> Self:
        match value:
            case Timeout():
                return value
            case None:
                return cls(None, None, None, None)
            case _:
                return cls(value, value, value, value)


@final
class Deadline:
    def __init__(self, timeout: Timeout) -> None:
        self._timeout = timeout
        self._limits: dict[Phase, float | None] = {
            "connect": timeout.connect,
            "read": timeout.read,
            "write": timeout.write,
        }
        self._end = None if timeout.total is None else monotonic() + timeout.total

    @asynccontextmanager
    async def phase(self, name: Phase) -> AsyncGenerator[None]:
        limit = self._limits[name]
        # the total budget wins when it leaves less time than the phase's own limit, and the error then names the total
        shortened = False
        if self._end is not None:
            left = self._end - monotonic()
            if left <= 0:
                raise TimeoutError("total", self._timeout.total or 0.0)
            if limit is None or left < limit:
                limit, shortened = left, True
        try:
            async with asyncio.timeout(limit):
                yield
        except TimeoutError:
            raise
        except builtins.TimeoutError:
            if shortened:
                raise TimeoutError("total", self._timeout.total or 0.0) from None
            raise TimeoutError(name, limit or 0.0) from None
