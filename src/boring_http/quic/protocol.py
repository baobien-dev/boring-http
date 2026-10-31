import asyncio
import errno
import logging
import socket
import sys
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Protocol, Self, override

from boring_ssl2 import ClientContext, QuicVersion
from ssl2.asynchronous import Readiness, SocketTransport, TLSStream
from ssl2.errors import ProxyError
from ssl2.proxy import Proxy, Socks5Datagram
from ssl2.tracing import Phase, Trace

from boring_http.errors import ConnectError, ProtocolError, RemoteDisconnectedError, StreamResetError
from boring_http.quic.connection import (
    ConnectionTerminated,
    DatagramReceived,
    EarlyDataAvailable,
    EarlyDataRejected,
    HandshakeCompleted,
    Limit,
    QuicConnection,
    StopSendingReceived,
    StreamDataReceived,
    StreamReset,
    VersionNegotiated,
)
from boring_http.quic.packet import TransportError
from boring_http.quic.parameters import TransportParameters
from boring_http.tracing import Event


class SocketOption(IntEnum):
    # Linux values the socket module does not name: UDP segmentation and receive offload, and the don't-fragment flag
    # RFC 9000 section 14 asks of every QUIC datagram
    UDP_SEGMENT = 103
    UDP_GRO = 104
    IP_MTU_DISCOVER = 10
    IP_PMTUDISC_DO = 2
    IPV6_MTU_DISCOVER = 23
    IPV6_PMTUDISC_DO = 2


class Size(IntEnum):
    RECEIVE_BUFFER = 4 << 20
    LANDING = 65536
    READ_BURST = 32
    SEGMENT_FIELD = 2


@dataclass(slots=True)
class OriginMemory:
    # what a later 0-RTT connection to the same origin runs under until its own handshake replaces it
    transport_parameters: bytes = b""
    settings: dict[int, int] = field(default_factory=dict[int, int])
    round_trip_time: int = 0


class SocksRelay:
    # RFC 1928 section 7: datagrams travel through the proxy's relay address, each with a header naming the destination
    def __init__(self, destination: tuple[str, int], control: SocketTransport, address: tuple[str, int]) -> None:
        self._destination = destination
        # the TCP connection that holds the UDP association open
        self._control = control
        self.address = address

    @classmethod
    async def open(cls, proxy: Proxy, destination: tuple[str, int]) -> Self:
        host, port = destination
        if (family := proxy.scheme.local_address_family) is not None:
            candidates = await asyncio.get_running_loop().getaddrinfo(host, port, family=family, type=socket.SOCK_DGRAM)
            host = str(candidates[0][4][0])
        control = await SocketTransport.connect(proxy.address)
        try:
            address = await TLSStream.associate(proxy, control)
        except BaseException:
            await control.close()
            raise
        return cls((host, port), control, address)

    def wrap(self, datagram: bytes) -> bytes:
        return Socks5Datagram.wrap(self._destination, datagram)

    @staticmethod
    def unwrap(datagram: bytes) -> bytes:
        return Socks5Datagram.unwrap(datagram)

    async def close(self) -> None:
        await self._control.close()


class Inbox:
    # what one stream received and the reader waiting for more
    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self.ended = False
        self.error: BaseException | None = None
        self.waiter: asyncio.Future[None] | None = None

    def wake(self) -> None:
        if self.waiter is not None and not self.waiter.done():
            self.waiter.set_result(None)


class DatagramSink(Protocol):
    # what a UDP socket reports to the connection driving it
    def datagrams_received(self, datagrams: list[bytes]) -> None: ...

    def datagram_too_long(self) -> None: ...

    def drained(self) -> None: ...

    def failed(self, error: OSError) -> None: ...


class ReadinessSocket:
    # a UDP socket on an event loop that signals readiness; on Linux the kernel moves many datagrams per call
    def __init__(self, sock: socket.socket, sink: DatagramSink, loop: asyncio.AbstractEventLoop) -> None:
        self._socket = sock
        self._sink = sink
        self._loop = loop
        self._offload = self._enable_offload(sock)
        self._landing = memoryview(bytearray(Size.LANDING))
        self._backlog: deque[bytes] = deque()
        self._writing = False
        loop.add_reader(sock.fileno(), self._readable)

    @staticmethod
    def _enable_offload(sock: socket.socket) -> bool:
        if sys.platform != "linux":
            return False
        try:
            sock.setsockopt(socket.IPPROTO_UDP, SocketOption.UDP_GRO, 1)
            sock.setsockopt(socket.IPPROTO_UDP, SocketOption.UDP_SEGMENT, 0)
        except OSError:
            # a kernel older than 5.0 has no UDP offload; the socket then moves one datagram per call
            return False
        return True

    @property
    def backlogged(self) -> bool:
        return bool(self._backlog)

    def send(self, datagrams: list[bytes]) -> None:
        self._backlog.extend(datagrams)
        self._drain()

    def close(self) -> None:
        self._loop.remove_reader(self._socket.fileno())
        if self._writing:
            self._loop.remove_writer(self._socket.fileno())
        self._socket.close()

    def _readable(self) -> None:
        datagrams: list[bytes] = []
        landing = self._landing
        for _ in range(Size.READ_BURST):
            try:
                if self._offload:
                    size, ancillary, _, _ = self._socket.recvmsg_into([landing], socket.CMSG_SPACE(Size.SEGMENT_FIELD))
                    segment = self._segment(ancillary, size)
                else:
                    size = self._socket.recv_into(landing)
                    segment = size
            except BlockingIOError:
                break
            except OSError as error:
                if error.errno != errno.EMSGSIZE:
                    self._sink.failed(error)
                    return
                # a router answered a datagram with "fragmentation needed"; the kernel hands that over here
                self._sink.datagram_too_long()
                continue
            # with receive offload one read may carry several datagrams of one size, the last possibly shorter
            datagrams.extend(
                bytes(landing[offset : min(offset + segment, size)]) for offset in range(0, size, max(segment, 1))
            )
        if datagrams:
            self._sink.datagrams_received(datagrams)

    @staticmethod
    def _segment(ancillary: list[tuple[int, int, bytes]], size: int) -> int:
        for level, kind, data in ancillary:
            if level == socket.IPPROTO_UDP and kind == SocketOption.UDP_GRO:
                return int.from_bytes(data[: Size.SEGMENT_FIELD], sys.byteorder)
        return size

    def _drain(self) -> None:
        backlog = self._backlog
        while backlog:
            # segmentation offload takes a run of equal-sized datagrams in one call; the kernel splits them
            count = 1
            if self._offload:
                while count < len(backlog) and len(backlog[count]) == len(backlog[0]):
                    count += 1
            try:
                if count > 1:
                    segment = len(backlog[0]).to_bytes(Size.SEGMENT_FIELD, sys.byteorder)
                    self._socket.sendmsg(
                        [b"".join(backlog[index] for index in range(count))],
                        [(socket.IPPROTO_UDP, SocketOption.UDP_SEGMENT, segment)],
                    )
                else:
                    self._socket.send(backlog[0])
            except BlockingIOError:
                # the kernel buffer is full: the rest waits, in order, until the socket drains
                if not self._writing:
                    self._writing = True
                    self._loop.add_writer(self._socket.fileno(), self._writable)
                return
            except OSError as error:
                if error.errno != errno.EMSGSIZE:
                    self._sink.failed(error)
                    return
                # the path cannot carry a datagram this large, or a router said so about an earlier one
                self._sink.datagram_too_long()
            for _ in range(count):
                backlog.popleft()
        if self._writing:
            self._writing = False
            self._loop.remove_writer(self._socket.fileno())

    def _writable(self) -> None:
        self._drain()
        if not self._backlog:
            self._sink.drained()


class EndpointSocket(asyncio.DatagramProtocol):
    # a UDP socket on an event loop without readiness callbacks, such as Windows' default one
    def __init__(self, sink: DatagramSink) -> None:
        self._sink = sink
        self._transport: asyncio.DatagramTransport | None = None

    @classmethod
    async def open(cls, sock: socket.socket, sink: DatagramSink) -> Self:
        loop = asyncio.get_running_loop()
        _, protocol = await loop.create_datagram_endpoint(lambda: cls(sink), sock=sock)
        return protocol

    @override
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        if isinstance(transport, asyncio.DatagramTransport):
            self._transport = transport

    @property
    def backlogged(self) -> bool:
        # the transport queues what the socket cannot take and sends it as the socket drains
        return False

    def send(self, datagrams: list[bytes]) -> None:
        if self._transport is not None:
            for datagram in datagrams:
                self._transport.sendto(datagram)

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | None, int]) -> None:
        self._sink.datagrams_received([data])

    @override
    def error_received(self, exc: Exception) -> None:
        if isinstance(exc, OSError) and exc.errno == errno.EMSGSIZE:
            self._sink.datagram_too_long()
        elif isinstance(exc, OSError):
            self._sink.failed(exc)


class QuicClient:
    # one QUIC connection on the event loop: the socket, the timers and the streams behind asyncio waits
    logger = logging.getLogger("boring_http")

    def __init__(self, connection: QuicConnection, relay: SocksRelay | None, memory: OriginMemory | None) -> None:
        self._connection = connection
        self._relay = relay
        self._memory = memory
        self._loop = asyncio.get_running_loop()
        self._udp: ReadinessSocket | EndpointSocket | None = None
        self._socket: socket.socket | None = None
        self._timer: asyncio.TimerHandle | None = None
        self._pacer: asyncio.TimerHandle | None = None
        self._flusher: asyncio.Handle | None = None
        self._handshake: asyncio.Future[None] = self._loop.create_future()
        # done as soon as requests may go out, with 0-RTT keys before the handshake; a version means the server
        # wants the connection made again in that version
        self._ready: asyncio.Future[QuicVersion | None] = self._loop.create_future()
        self._terminated: asyncio.Future[ConnectionTerminated] = self._loop.create_future()
        self._inboxes: dict[int, Inbox] = {}
        # set after every flush, so a writer waiting for its stream to drain looks again
        self._progress = asyncio.Event()
        self._closed = False
        self._closing_locally = False
        self.incoming: asyncio.Queue[int] = asyncio.Queue()
        self.datagrams: asyncio.Queue[bytes] = asyncio.Queue()

    @classmethod
    async def connect(
        cls,
        context: ClientContext,
        server_name: str,
        address: tuple[str, int],
        parameters: TransportParameters,
        *,
        version: QuicVersion = QuicVersion.V1,
        token: bytes = b"",
        proxy: Proxy | None = None,
        memory: OriginMemory | None = None,
        trace: Trace | None = None,
    ) -> Self:
        loop = asyncio.get_running_loop()
        while True:
            relay = None
            if proxy is not None:
                with Trace.timing(trace, Phase.PROXY):
                    relay = await SocksRelay.open(proxy, address)
            target = address if relay is None else relay.address
            with Trace.timing(trace, Phase.RESOLVE):
                family, kind, protocol, _, resolved = (
                    await loop.getaddrinfo(target[0], target[1], type=socket.SOCK_DGRAM)
                )[0]
            sock = cls._open_socket(family, kind, protocol)
            sock.connect(resolved)
            connection = QuicConnection(
                context,
                server_name,
                parameters,
                loop.time(),
                version=version,
                token=token,
                remembered=b"" if memory is None else memory.transport_parameters,
                round_trip_time=memory.round_trip_time or None if memory is not None else None,
            )
            client = cls(connection, relay, memory)
            try:
                await client._attach(sock)
                client._dispatch()
                # with 0-RTT keys the first datagram waits for the request, so Initial and 0-RTT packets travel together
                if not client._ready.done():
                    client._flush()
                with Trace.timing(trace, Phase.HANDSHAKE):
                    negotiated = await client._ready
            except BaseException:
                await client.close()
                raise
            if negotiated is None:
                return client
            await client.close()
            version = negotiated

    @staticmethod
    def _open_socket(family: int, kind: int, protocol: int) -> socket.socket:
        sock = socket.socket(family, kind, protocol)
        sock.settimeout(0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, Size.RECEIVE_BUFFER)
        if sys.platform == "linux":
            # a datagram the path cannot carry whole is refused by the kernel rather than fragmented
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, SocketOption.IPV6_MTU_DISCOVER, SocketOption.IPV6_PMTUDISC_DO)
            else:
                sock.setsockopt(socket.IPPROTO_IP, SocketOption.IP_MTU_DISCOVER, SocketOption.IP_PMTUDISC_DO)
        return sock

    async def _attach(self, sock: socket.socket) -> None:
        self._socket = sock
        if Readiness.available(self._loop):
            self._udp = ReadinessSocket(sock, self, self._loop)
        else:
            self._udp = await EndpointSocket.open(sock, self)

    @property
    def connection(self) -> QuicConnection:
        return self._connection

    @property
    def closed(self) -> bool:
        return self._terminated.done()

    @property
    def terminated(self) -> asyncio.Future[ConnectionTerminated]:
        return self._terminated

    def getsockname(self) -> tuple[str | None, int]:
        return self._socket.getsockname() if self._socket is not None else (None, 0)

    def getpeername(self) -> tuple[str | None, int]:
        return self._socket.getpeername() if self._socket is not None else (None, 0)

    async def established(self) -> None:
        await self._handshake

    def open_stream(self, *, bidirectional: bool = True) -> int:
        stream_id = self._connection.open_stream(bidirectional=bidirectional)
        self._inboxes[stream_id] = Inbox()
        return stream_id

    def send(self, stream_id: int, data: bytes, *, end: bool = False) -> None:
        self._connection.send_stream_data(stream_id, data, end=end)
        self._flush_soon()

    def reset(self, stream_id: int, error: int) -> None:
        self._connection.reset_stream(stream_id, error)
        self._flush_soon()

    def stop_sending(self, stream_id: int, error: int) -> None:
        self._connection.stop_sending(stream_id, error)
        self._flush_soon()

    def send_datagram(self, data: bytes) -> None:
        self._connection.send_datagram(data)
        self._flush_soon()

    def fail_stream(self, stream_id: int, error: BaseException) -> None:
        inbox = self._inboxes.setdefault(stream_id, Inbox())
        inbox.error = error
        inbox.wake()

    async def receive(self, stream_id: int) -> bytes:
        # the next piece of the stream, or nothing once it has ended
        inbox = self._inboxes.setdefault(stream_id, Inbox())
        while True:
            if inbox.chunks:
                chunks, inbox.chunks = inbox.chunks, []
                data = chunks[0] if len(chunks) == 1 else b"".join(chunks)
                if self._connection.stream_read(stream_id, len(data)):
                    self._flush_soon()
                return data
            if inbox.error is not None:
                raise inbox.error
            if inbox.ended:
                return b""
            inbox.waiter = self._loop.create_future()
            try:
                await inbox.waiter
            finally:
                inbox.waiter = None

    async def drain(self, stream_id: int, limit: int) -> None:
        # a writer waits while more than limit bytes of its stream are unsent, so a large body is never queued whole
        while self._connection.unsent(stream_id) > limit:
            inbox = self._inboxes.get(stream_id)
            if inbox is not None and inbox.error is not None:
                raise inbox.error
            if self._terminated.done():
                raise RemoteDisconnectedError("the QUIC connection closed with data unsent")
            self._progress.clear()
            await self._progress.wait()

    async def close(self, error: int = 0, reason: str = "") -> None:
        if not self._terminated.done():
            self._closing_locally = True
            self._connection.close(error, reason)
            self._flush()
            self._dispatch()
        if self._closed:
            return
        self._closed = True
        for handle in (self._timer, self._pacer, self._flusher):
            if handle is not None:
                handle.cancel()
        if self._udp is not None:
            self._udp.close()
        if self._relay is not None:
            await self._relay.close()

    def datagrams_received(self, datagrams: list[bytes]) -> None:
        now = self._loop.time()
        for datagram in datagrams:
            try:
                self._connection.datagram_received(
                    datagram if self._relay is None else self._relay.unwrap(datagram), now
                )
            except ProtocolError as error:
                self._connection.close(TransportError.PROTOCOL_VIOLATION, str(error), application=False)
                break
            except ProxyError as error:
                self._fail(error)
                self._close_soon()
                return
        self._dispatch()
        self._flush()

    def datagram_too_long(self) -> None:
        self._connection.datagram_too_long()

    def drained(self) -> None:
        self._flush()

    def failed(self, error: OSError) -> None:
        self._fail(ConnectError(f"QUIC socket error: {error}"))
        self._close_soon()

    def _close_soon(self) -> None:
        self._loop.create_task(self.close())

    def _flush_soon(self) -> None:
        # one burst per loop step, so the frames of consecutive calls share packets and datagrams
        if self._flusher is None and not self._closed:
            self._flusher = self._loop.call_soon(self._flush)

    def _flush(self) -> None:
        if self._flusher is not None:
            self._flusher.cancel()
            self._flusher = None
        udp = self._udp
        if self._closed or udp is None or udp.backlogged:
            return
        datagrams = self._connection.datagrams_to_send(self._loop.time())
        if datagrams:
            udp.send(datagrams if self._relay is None else [self._relay.wrap(datagram) for datagram in datagrams])
        self._progress.set()
        self._dispatch()
        self._arm_timer()
        if len(datagrams) >= Limit.BURST and not udp.backlogged and self._pacer is None:
            # a full burst means more may be waiting; the next one goes out when the pacing rate allows
            delay = self._connection.pacing_delay(sum(len(datagram) for datagram in datagrams))
            self._pacer = self._loop.call_later(delay, self._paced_flush)

    def _paced_flush(self) -> None:
        self._pacer = None
        self._flush()

    def _arm_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
        when = self._connection.next_timer()
        if when is None or self._connection.terminated or self._closed:
            self._timer = None
        else:
            self._timer = self._loop.call_at(when, self._on_timer)

    def _on_timer(self) -> None:
        self._connection.handle_timer(self._loop.time())
        self._dispatch()
        self._flush()

    def _dispatch(self) -> None:
        while (event := self._connection.next_event()) is not None:
            match event:
                case StreamDataReceived(stream_id, data, end):
                    inbox = self._inboxes.get(stream_id)
                    if inbox is None:
                        inbox = self._inboxes[stream_id] = Inbox()
                        self.incoming.put_nowait(stream_id)
                    if data:
                        inbox.chunks.append(data)
                    if end:
                        inbox.ended = True
                    inbox.wake()
                case StreamReset(stream_id, error):
                    self.fail_stream(stream_id, StreamResetError(stream_id, error))
                case HandshakeCompleted():
                    if self._memory is not None:
                        self._memory.transport_parameters = self._connection.peer_transport_parameters
                        self._memory.round_trip_time = self._connection.round_trip_time
                    for future in (self._ready, self._handshake):
                        if not future.done():
                            future.set_result(None)
                case EarlyDataAvailable():
                    if not self._ready.done():
                        self._ready.set_result(None)
                case ConnectionTerminated(error, reason, _):
                    if not self._terminated.done():
                        self._terminated.set_result(event)
                    self._fail(RemoteDisconnectedError(f"QUIC connection terminated: {reason or hex(error)}"))
                    self._close_soon()
                case DatagramReceived(data):
                    self.datagrams.put_nowait(data)
                case VersionNegotiated(version):
                    if not self._ready.done():
                        self._ready.set_result(version)
                    self._fail(RemoteDisconnectedError(f"the server asked for QUIC version {version.name}"))
                    self._close_soon()
                case StopSendingReceived() | EarlyDataRejected():
                    pass

    def _fail(self, error: BaseException) -> None:
        # a close this side asked for ends the streams the same way, but is nothing to warn about
        if not self._closing_locally:
            self.logger.warning("%s version=h3 error=%s", Event.CONNECTION_FAILED, error)
        for future in (self._ready, self._handshake):
            if not future.done():
                future.set_exception(error)
                # a 0-RTT connection may never await the handshake; reading the exception keeps asyncio from logging it
                future.exception()
        for inbox in self._inboxes.values():
            inbox.error = error
            inbox.wake()
        if not self._terminated.done():
            self._terminated.set_result(ConnectionTerminated(TransportError.NO_ERROR, str(error), application=False))
        self._progress.set()
