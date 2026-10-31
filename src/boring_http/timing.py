import asyncio
import builtins
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from time import monotonic
from types import TracebackType
from typing import Self

from ssl2.value import Value

from boring_http.errors import RequestTimeoutError


class Phase(StrEnum):
    CONNECT = "connect"
    READ = "read"
    WRITE = "write"
    TOTAL = "total"


class Seconds(IntEnum):
    CONNECT = 10
    READ = 30
    WRITE = 30


@dataclass(frozen=True, slots=True)
class Timeout(Value):
    # connect covers opening a connection, read the longest wait for bytes, write the longest wait to send a chunk,
    # total the whole exchange with its redirects; None is no limit
    connect: float | None = Seconds.CONNECT
    read: float | None = Seconds.READ
    write: float | None = Seconds.WRITE
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
    # hands out one phase at a time; the total wins when it leaves less time than the phase's own limit
    def __init__(self, timeout: Timeout) -> None:
        self._timeout = timeout
        self._end = None if timeout.total is None else monotonic() + timeout.total

    @property
    def timeout(self) -> Timeout:
        return self._timeout

    def phase(self, name: Phase) -> PhaseTimer:
        return PhaseTimer(self, name)

    def drop_total(self) -> None:
        self._end = None

    def limit(self, name: Phase) -> tuple[float | None, bool]:
        # the seconds this phase may take, and whether it was the total that shortened it
        match name:
            case Phase.CONNECT:
                own = self._timeout.connect
            case Phase.READ:
                own = self._timeout.read
            case Phase.WRITE:
                own = self._timeout.write
            case Phase.TOTAL:
                own = self._timeout.total
        if self._end is None:
            return own, False
        left = self._end - monotonic()
        if left <= 0:
            raise RequestTimeoutError(Phase.TOTAL, self._timeout.total or 0.0)
        if own is None or left < own:
            return left, True
        return own, False


class PhaseTimer:
    # a request enters a phase several times per response, so this is a small object rather than a generator
    __slots__ = ("_deadline", "_limit", "_name", "_shortened", "_timeout")

    def __init__(self, deadline: Deadline, name: Phase) -> None:
        self._deadline = deadline
        self._name = name
        self._limit: float | None = None
        self._shortened = False
        self._timeout: asyncio.Timeout | None = None

    async def __aenter__(self) -> None:
        self._limit, self._shortened = self._deadline.limit(self._name)
        if self._limit is not None:
            self._timeout = asyncio.timeout(self._limit)
            await self._timeout.__aenter__()

    async def __aexit__(
        self, kind: type[BaseException] | None, error: BaseException | None, traceback: TracebackType | None
    ) -> None:
        if self._timeout is not None:
            try:
                await self._timeout.__aexit__(kind, error, traceback)
            except builtins.TimeoutError:
                raise self._expired() from None
        if kind is not None and issubclass(kind, builtins.TimeoutError) and not issubclass(kind, RequestTimeoutError):
            raise self._expired() from None

    def _expired(self) -> RequestTimeoutError:
        if self._shortened:
            return RequestTimeoutError(Phase.TOTAL, self._deadline.timeout.total or 0.0)
        return RequestTimeoutError(self._name, self._limit or 0.0)
