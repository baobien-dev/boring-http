import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from time import monotonic
from typing import Protocol

from ssl2.proxy import Proxy
from ssl2.tracing import Trace
from ssl2.value import Value

from boring_http.request import Request
from boring_http.response import ConnectionInfo, Response
from boring_http.timing import Deadline, Phase
from boring_http.tracing import Event
from boring_http.url import Scheme, Url


class Connection(Protocol):
    closed: bool
    reused: bool
    connect_time: float
    released: Callable[[], None]

    @property
    def available(self) -> bool: ...

    @property
    def shared(self) -> bool: ...

    @property
    def info(self) -> ConnectionInfo: ...

    def take(self) -> None: ...

    async def send(self, request: Request, deadline: Deadline, *, decode: bool, trace: Trace | None) -> Response: ...

    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class PoolKey(Value):
    # one pool per origin and the way it is reached
    scheme: Scheme
    host: str
    port: int
    proxy: Proxy | None
    quic: bool

    @classmethod
    def of(cls, url: Url, proxy: Proxy | None, *, quic: bool) -> PoolKey:
        return cls(url.scheme, url.host, url.port, proxy, quic)


class Pool:
    logger = logging.getLogger("boring_http")

    def __init__(
        self,
        connector: Callable[[Url, Proxy | None, bool, Trace | None], Awaitable[Connection]],
        max_connections: int,
        max_connections_per_host: int,
        max_idle_time: float | None,
    ) -> None:
        self._connector = connector
        self._per_host = max_connections_per_host
        self._total = asyncio.Semaphore(max_connections)
        self._max_idle_time = max_idle_time
        self._limits: dict[PoolKey, asyncio.Semaphore] = {}
        self._locks: dict[PoolKey, asyncio.Lock] = {}
        self._changes: dict[PoolKey, asyncio.Event] = {}
        self._connections: dict[PoolKey, list[Connection]] = {}
        # the requests each connection is serving, and when it last became idle
        self._in_use: dict[Connection, int] = {}
        self._idle_since: dict[Connection, float] = {}

    async def acquire(
        self, url: Url, proxy: Proxy | None, deadline: Deadline, *, quic: bool = False, trace: Trace | None = None
    ) -> Connection:
        key = PoolKey.of(url, proxy, quic=quic)
        limit = self._limits.setdefault(key, asyncio.Semaphore(self._per_host))
        changed = self._changes.setdefault(key, asyncio.Event())
        async with self._locks.setdefault(key, asyncio.Lock()):
            while True:
                for connection in list(self._connections.get(key, [])):
                    if self._expired(connection):
                        await connection.close()
                    elif connection.available:
                        connection.take()
                        connection.reused = True
                        self._in_use[connection] += 1
                        self.logger.debug("%s host=%s port=%d", Event.CONNECTION_REUSED, url.host, url.port)
                        return connection
                if not limit.locked() and not self._total.locked():
                    break
                # every connection is busy and no new one may open: wait for a stream to finish or a connection to close
                changed.clear()
                async with deadline.phase(Phase.CONNECT):
                    await changed.wait()
            async with deadline.phase(Phase.CONNECT):
                await limit.acquire()
                await self._total.acquire()
            try:
                started = monotonic()
                async with deadline.phase(Phase.CONNECT):
                    connection = await self._connector(url, proxy, quic, trace)
                connection.connect_time = monotonic() - started
            except BaseException:
                limit.release()
                self._total.release()
                raise
            connection.take()
            connection.released = lambda: self._changed(key, connection, limit)
            self._connections.setdefault(key, []).append(connection)
            self._in_use[connection] = 1
            self.logger.info(
                "%s host=%s port=%d quic=%s seconds=%.3f",
                Event.CONNECTION_OPENED,
                url.host,
                url.port,
                quic,
                connection.connect_time,
            )
            return connection

    async def close(self) -> None:
        for connections in list(self._connections.values()):
            for connection in list(connections):
                await connection.close()
        self._connections.clear()

    def _changed(self, key: PoolKey, connection: Connection, limit: asyncio.Semaphore) -> None:
        connections = self._connections.get(key, [])
        if connection.closed and connection in connections:
            connections.remove(connection)
            del self._in_use[connection]
            self._idle_since.pop(connection, None)
            limit.release()
            self._total.release()
            self.logger.debug("%s host=%s port=%d", Event.CONNECTION_CLOSED, key.host, key.port)
        elif connection in self._in_use:
            self._in_use[connection] = max(self._in_use[connection] - 1, 0)
            if not self._in_use[connection]:
                self._idle_since[connection] = monotonic()
        self._changes[key].set()

    def _expired(self, connection: Connection) -> bool:
        idle_since = self._idle_since.get(connection)
        return (
            self._max_idle_time is not None
            and idle_since is not None
            and not self._in_use[connection]
            and monotonic() - idle_since > self._max_idle_time
        )
