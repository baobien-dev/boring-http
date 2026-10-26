import asyncio
from collections.abc import Awaitable, Callable
from typing import Protocol, final

from ssl2 import Proxy

from boring_http.message import URL, Request, Response
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

    def take(self) -> None: ...

    async def send(
        self, request: Request, deadline: Deadline, *, decode: bool
    ) -> Response: ...

    async def close(self) -> None: ...


type Connector = Callable[[URL, Proxy | None, bool], Awaitable[Connection]]


@final
class Pool:
    def __init__(
        self, connector: Connector, max_connections: int, max_connections_per_host: int
    ) -> None:
        self._connector = connector
        self._per_host = max_connections_per_host
        self._total = asyncio.Semaphore(max_connections)
        self._limits: dict[Key, asyncio.Semaphore] = {}
        self._locks: dict[Key, asyncio.Lock] = {}
        self._changes: dict[Key, asyncio.Event] = {}
        self._connections: dict[Key, list[Connection]] = {}

    async def acquire(
        self, url: URL, proxy: Proxy | None, deadline: Deadline, *, quic: bool = False
    ) -> Connection:
        key: Key = (url.scheme, url.host, url.port or url.default_port, proxy, quic)
        limit = self._limits.setdefault(key, asyncio.Semaphore(self._per_host))
        changed = self._changes.setdefault(key, asyncio.Event())
        async with self._locks.setdefault(key, asyncio.Lock()):
            while True:
                for connection in self._connections.get(key, []):
                    if connection.available:
                        connection.take()
                        connection.reused = True
                        return connection
                if not limit.locked() and not self._total.locked():
                    break
                # every connection is busy and no new one may open: wait for a stream to finish or a connection to close
                changed.clear()
                async with deadline.phase("connect"):
                    _ = await changed.wait()
            async with deadline.phase("connect"):
                _ = await limit.acquire()
                _ = await self._total.acquire()
            try:
                connection = await self._connector(url, proxy, quic)
            except BaseException:
                limit.release()
                self._total.release()
                raise
            connection.take()
            connection.released = lambda: self._changed(key, connection, limit)
            self._connections.setdefault(key, []).append(connection)
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
            limit.release()
            self._total.release()
        self._changes[key].set()
