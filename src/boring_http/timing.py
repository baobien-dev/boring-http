import asyncio
import builtins
from dataclasses import dataclass
from time import monotonic
from types import TracebackType
from typing import Literal, Self

from boring_http.errors import TimeoutError

type Phase = Literal["connect", "read", "write"]


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


class Deadline:
    def __init__(self, timeout: Timeout) -> None:
        self._timeout = timeout
        self._limits: dict[Phase, float | None] = {
            "connect": timeout.connect,
            "read": timeout.read,
            "write": timeout.write,
        }
        self._end = None if timeout.total is None else monotonic() + timeout.total

    @property
    def total(self) -> float | None:
        return self._timeout.total

    def phase(self, name: Phase) -> PhaseTimer:
        return PhaseTimer(self, name)

    def limit(self, name: Phase) -> tuple[float | None, bool]:
        # the total budget wins when it leaves less time than the phase's own limit, and the error then names the total
        limit = self._limits[name]
        if self._end is None:
            return limit, False
        left = self._end - monotonic()
        if left <= 0:
            raise TimeoutError("total", self._timeout.total or 0.0)
        if limit is None or left < limit:
            return left, True
        return limit, False


class PhaseTimer:
    # a request enters a phase several times per response, so this is a small object rather than a generator
    __slots__ = ("_deadline", "_limit", "_name", "_shortened", "_timeout")

    def __init__(self, deadline: Deadline, name: Phase) -> None:
        self._deadline = deadline
        self._name: Phase = name
        self._limit: float | None = None
        self._shortened = False
        self._timeout: asyncio.Timeout | None = None

    async def __aenter__(self) -> None:
        self._limit, self._shortened = self._deadline.limit(self._name)
        if self._limit is not None:
            self._timeout = asyncio.timeout(self._limit)
            await self._timeout.__aenter__()

    async def __aexit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._timeout is not None:
            try:
                await self._timeout.__aexit__(kind, error, traceback)
            except builtins.TimeoutError:
                raise self._expired() from None
        if (
            kind is not None
            and issubclass(kind, builtins.TimeoutError)
            and not issubclass(kind, TimeoutError)
        ):
            raise self._expired() from None

    def _expired(self) -> TimeoutError:
        if self._shortened:
            return TimeoutError("total", self._deadline.total or 0.0)
        return TimeoutError(self._name, self._limit or 0.0)
