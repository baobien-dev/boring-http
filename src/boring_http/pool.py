import asyncio
from collections.abc import Awaitable, Callable
from time import monotonic
from typing import Protocol

from ssl2 import Proxy

from boring_http.message import URL, ConnectionInfo, Request, Response
from boring_http.timing import Deadline

type Key = tuple[str, str, int, Proxy | None, bool]


class Connection(Protocol):
    closed: bool
    reused: bool
    released: Callable[[], None]

    @property
    def available(self) -> bool: ...

    @property
    def shared(self) -> bool: ...

    @property
    def info(self) -> ConnectionInfo: ...

    def take(self) -> None: ...

    async def send(
        self, request: Request, deadline: Deadline, *, decode: bool
    ) -> Response: ...

    async def close(self) -> None: ...


type Connector = Callable[[URL, Proxy | None, bool], Awaitable[Connection]]


class Pool:
    def __init__(
        self,
        connector: Connector,
        max_connections: int,
        max_connections_per_host: int,
        max_idle_time: float | None,
    ) -> None:
        self._connector = connector
        self._per_host = max_connections_per_host
        self._total = asyncio.Semaphore(max_connections)
        self._max_idle_time = max_idle_time
        self._limits: dict[Key, asyncio.Semaphore] = {}
        self._locks: dict[Key, asyncio.Lock] = {}
        self._changes: dict[Key, asyncio.Event] = {}
        self._connections: dict[Key, list[Connection]] = {}
        # the requests each connection is serving, and when it last became idle
        self._in_use: dict[Connection, int] = {}
        self._idle_since: dict[Connection, float] = {}

    async def acquire(
        self, url: URL, proxy: Proxy | None, deadline: Deadline, *, quic: bool = False
    ) -> Connection:
        key: Key = (url.scheme, url.host, url.port or url.default_port, proxy, quic)
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
                        return connection
                if not limit.locked() and not self._total.locked():
                    break
                # every connection is busy and no new one may open: wait for a stream to finish or a connection to close
                changed.clear()
                async with deadline.phase("connect"):
                    await changed.wait()
            async with deadline.phase("connect"):
                await limit.acquire()
                await self._total.acquire()
            try:
                async with deadline.phase("connect"):
                    connection = await self._connector(url, proxy, quic)
            except BaseException:
                limit.release()
                self._total.release()
                raise
            connection.take()
            connection.released = lambda: self._changed(key, connection, limit)
            self._connections.setdefault(key, []).append(connection)
            self._in_use[connection] = 1
            return connection

    async def close(self) -> None:
        for connections in list(self._connections.values()):
            for connection in list(connections):
                await connection.close()
        self._connections.clear()

    def _changed(
        self, key: Key, connection: Connection, limit: asyncio.Semaphore
    ) -> None:
        connections = self._connections.get(key, [])
        if connection.closed and connection in connections:
            connections.remove(connection)
            del self._in_use[connection]
            self._idle_since.pop(connection, None)
            limit.release()
            self._total.release()
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
