import asyncio
import errno
import socket
import sys
from collections import deque
from dataclasses import dataclass, field
from typing import Self

from boring_ssl2 import ClientContext, QuicVersion
from ssl2 import Proxy, ProxyError, SocketTransport, TLSStream

from boring_http.errors import (
    ConnectError,
    ProtocolError,
    RemoteDisconnected,
    StreamResetError,
)
from boring_http.quic.connection import (
    MAX_BURST,
    ConnectionTerminated,
    DatagramReceived,
    EarlyDataAvailable,
    EarlyDataRejected,
    HandshakeCompleted,
    QuicConnection,
    StopSendingReceived,
    StreamDataReceived,
    StreamReset,
    TransportParameters,
    VersionNegotiated,
)

RECEIVE_BUFFER = 4 << 20
READ_BURST = 32
# Linux UDP socket options for generic segmentation and receive offload; the socket module does not name them
UDP_SEGMENT = 103
UDP_GRO = 104
SEGMENT_SPACE = socket.CMSG_SPACE(2)
# Linux IP socket options for the don't-fragment flag, which RFC 9000 section 14 asks of every QUIC datagram
IP_MTU_DISCOVER, IP_PMTUDISC_DO = 10, 2
IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DO = 23, 2
# one 64 KiB landing area for every connection on the loop; a read callback is never interrupted by another
RECEIVED = memoryview(bytearray(65536))


@dataclass(slots=True)
class OriginMemory:
    # what a later 0-RTT connection to the same origin runs under until the new handshake replaces it
    transport_parameters: bytes = b""
    settings: dict[int, int] = field(default_factory=dict[int, int])
    round_trip_time: int = 0


class VersionChange(Exception):
    def __init__(self, version: QuicVersion) -> None:
        super().__init__(f"the server offered QUIC version {version:#010x}")
        self.version = version


class SocksRelay:
    def __init__(
        self,
        proxy: Proxy,
        destination: tuple[str, int],
        control: SocketTransport,
        address: tuple[str, int],
    ) -> None:
        self._header = proxy.udp_header(destination)
        # the TCP connection that holds the UDP association open
        self._control = control
        self.address = address

    @classmethod
    async def open(cls, proxy: Proxy, destination: tuple[str, int]) -> Self:
        host, port = destination
        if (family := proxy.scheme.local_address_family) is not None:
            candidates = await asyncio.get_running_loop().getaddrinfo(
                host, port, family=family, type=socket.SOCK_DGRAM
            )
            host = str(candidates[0][4][0])
        control = await SocketTransport.connect((proxy.host, proxy.port))
        try:
            address = await TLSStream.associate(proxy, control)
        except BaseException:
            control.socket.close()
            raise
        return cls(proxy, (host, port), control, address)

    def wrap(self, datagram: bytes) -> bytes:
        return self._header + datagram

    @staticmethod
    def unwrap(datagram: bytes) -> bytes:
        return Proxy.udp_payload(datagram)

    def close(self) -> None:
        self._control.socket.close()


class Inbox:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self.ended = False
        self.error: BaseException | None = None
        self.waiter: asyncio.Future[None] | None = None

    def wake(self) -> None:
        if self.waiter is not None and not self.waiter.done():
            self.waiter.set_result(None)


class QuicClient:
    def __init__(
        self,
        connection: QuicConnection,
        sock: socket.socket,
        relay: SocksRelay | None,
        offload: bool,
        memory: OriginMemory | None,
    ) -> None:
        self._connection = connection
        self._socket = sock
        self._relay = relay
        self._offload = offload
        self._memory = memory
        self._loop = asyncio.get_running_loop()
        self._timer: asyncio.TimerHandle | None = None
        self._pacer: asyncio.TimerHandle | None = None
        self._flusher: asyncio.Handle | None = None
        self._handshake: asyncio.Future[None] = self._loop.create_future()
        # done as soon as requests may go out: with 0-RTT keys that is before the handshake
        self._ready: asyncio.Future[None] = self._loop.create_future()
        self._terminated: asyncio.Future[ConnectionTerminated] = (
            self._loop.create_future()
        )
        self._inboxes: dict[int, Inbox] = {}
        self._unsent: deque[bytes] = deque()
        self._closed = False
        self.incoming: asyncio.Queue[int] = asyncio.Queue()
        self.datagrams: asyncio.Queue[bytes] = asyncio.Queue()
        self._loop.add_reader(sock.fileno(), self._readable)

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
    ) -> Self:
        loop = asyncio.get_running_loop()
        while True:
            relay = None if proxy is None else await SocksRelay.open(proxy, address)
            target = address if relay is None else relay.address
            family, kind, protocol, _, resolved = (
                await loop.getaddrinfo(target[0], target[1], type=socket.SOCK_DGRAM)
            )[0]
            sock = socket.socket(family, kind, protocol)
            sock.setblocking(False)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECEIVE_BUFFER)
            if sys.platform == "linux":
                # a datagram the path cannot carry whole is refused by the kernel rather than fragmented
                if family == socket.AF_INET6:
                    sock.setsockopt(
                        socket.IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DO
                    )
                else:
                    sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
            sock.connect(resolved)
            connection = QuicConnection(
                context,
                server_name,
                parameters,
                loop.time(),
                version=version,
                token=token,
                remembered=b"" if memory is None else memory.transport_parameters,
                round_trip_time=memory.round_trip_time or None if memory else None,
            )
            client = cls(connection, sock, relay, cls._offload_available(sock), memory)
            # with 0-RTT keys the first datagram waits for the request, so Initial and 0-RTT packets travel together
            client._dispatch()
            if not client._ready.done():
                client._flush()
            try:
                await client._ready
            except VersionChange as change:
                client.close()
                version = change.version
                continue
            except BaseException:
                client.close()
                raise
            return client

    @staticmethod
    def _offload_available(sock: socket.socket) -> bool:
        if sys.platform != "linux":
            return False
        try:
            sock.setsockopt(socket.IPPROTO_UDP, UDP_GRO, 1)
            sock.setsockopt(socket.IPPROTO_UDP, UDP_SEGMENT, 0)
        except OSError:
            # a kernel older than 5.0 has no UDP offload; the socket then moves one datagram per call
            return False
        return True

    @property
    def connection(self) -> QuicConnection:
        return self._connection

    @property
    def closed(self) -> bool:
        return self._terminated.done()

    @property
    def terminated(self) -> asyncio.Future[ConnectionTerminated]:
        return self._terminated

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

    def _flush_soon(self) -> None:
        # one burst per loop step, so the frames of consecutive calls share packets and datagrams
        if self._flusher is None and not self._closed:
            self._flusher = self._loop.call_soon(self._flush)

    def fail_stream(self, stream_id: int, error: BaseException) -> None:
        inbox = self._inboxes.setdefault(stream_id, Inbox())
        inbox.error = error
        inbox.wake()

    async def receive(self, stream_id: int) -> bytes:
        inbox = self._inboxes.setdefault(stream_id, Inbox())
        while True:
            if inbox.chunks:
                chunks, inbox.chunks = inbox.chunks, []
                return chunks[0] if len(chunks) == 1 else b"".join(chunks)
            if inbox.error is not None:
                raise inbox.error
            if inbox.ended:
                return b""
            inbox.waiter = self._loop.create_future()
            await inbox.waiter
            inbox.waiter = None

    def close(self, error: int = 0, reason: str = "") -> None:
        if not self._terminated.done():
            self._connection.close(error, reason)
            self._flush()
            self._dispatch()
        if self._closed:
            return
        self._closed = True
        self._loop.remove_reader(self._socket.fileno())
        self._loop.remove_writer(self._socket.fileno())
        self._socket.close()
        for handle in (self._timer, self._pacer, self._flusher):
            if handle is not None:
                handle.cancel()
        if self._relay is not None:
            self._relay.close()

    def _readable(self) -> None:
        now = self._loop.time()
        for _ in range(READ_BURST):
            try:
                if self._offload:
                    received = self._socket.recvmsg_into([RECEIVED], SEGMENT_SPACE)
                    size, ancillary = received[0], received[1]
                    segment = next(
                        (
                            int.from_bytes(data[:2], sys.byteorder)
                            for level, kind, data in ancillary
                            if level == socket.IPPROTO_UDP and kind == UDP_GRO
                        ),
                        size,
                    )
                else:
                    size = self._socket.recv_into(RECEIVED)
                    segment = size
            except BlockingIOError:
                break
            except OSError as error:
                if error.errno != errno.EMSGSIZE:
                    self._fail(ConnectError(f"QUIC socket error: {error}"))
                    self.close()
                    return
                # a router answered a datagram with "fragmentation needed"; the kernel hands that over here
                self._connection.datagram_too_long()
                continue
            # with receive offload one read may carry several datagrams of one size, the last possibly shorter
            for offset in range(0, size, max(segment, 1)):
                datagram = bytes(RECEIVED[offset : min(offset + segment, size)])
                try:
                    self._connection.datagram_received(
                        datagram
                        if self._relay is None
                        else self._relay.unwrap(datagram),
                        now,
                    )
                except ProtocolError as error:
                    self._connection.close(0x0A, str(error), application=False)
                    break
                except ProxyError as error:
                    self._fail(error)
                    self.close()
                    return
        self._dispatch()
        self._flush()

    def _flush(self) -> None:
        if self._flusher is not None:
            self._flusher.cancel()
            self._flusher = None
        if self._closed or (self._unsent and not self._send_queued()):
            return
        datagrams = self._connection.datagrams_to_send(self._loop.time())
        wires = (
            datagrams
            if self._relay is None
            else [self._relay.wrap(datagram) for datagram in datagrams]
        )
        index = 0
        while index < len(wires):
            # segmentation offload takes a run of equal-sized datagrams in one call; the kernel splits them
            end = index + 1
            while (
                self._offload
                and end < len(wires)
                and len(wires[end]) == len(wires[index])
            ):
                end += 1
            try:
                if end - index > 1:
                    self._socket.sendmsg(
                        [b"".join(wires[index:end])],
                        [
                            (
                                socket.IPPROTO_UDP,
                                UDP_SEGMENT,
                                len(wires[index]).to_bytes(2, sys.byteorder),
                            )
                        ],
                    )
                else:
                    self._socket.send(wires[index])
            except BlockingIOError:
                # the kernel send buffer is full: the rest waits, in order, until the socket drains
                self._unsent.extend(wires[index:])
                self._loop.add_writer(self._socket.fileno(), self._writable)
                break
            except OSError as error:
                if error.errno != errno.EMSGSIZE:
                    self._fail(ConnectError(f"QUIC socket error: {error}"))
                    self.close()
                    return
                # the path cannot carry a datagram this large, or a router said so about an earlier one:
                # these count as lost, and the connection goes back to the size every path carries
                self._connection.datagram_too_long()
            index = end
        self._dispatch()
        self._arm_timer()
        if len(datagrams) >= MAX_BURST and not self._unsent and self._pacer is None:
            # a full burst means more may be waiting; the next one goes out when the pacing rate allows
            self._pacer = self._loop.call_later(
                self._connection.pacing_delay(
                    sum(len(datagram) for datagram in datagrams)
                ),
                self._paced_flush,
            )

    def _paced_flush(self) -> None:
        self._pacer = None
        self._flush()

    def _send_queued(self) -> bool:
        while self._unsent:
            try:
                self._socket.send(self._unsent[0])
            except BlockingIOError:
                return False
            except OSError as error:
                if error.errno != errno.EMSGSIZE:
                    self._fail(ConnectError(f"QUIC socket error: {error}"))
                    self.close()
                    return False
                self._connection.datagram_too_long()
            self._unsent.popleft()
        self._loop.remove_writer(self._socket.fileno())
        return True

    def _writable(self) -> None:
        if self._send_queued():
            self._flush()

    def _arm_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
        when = self._connection.next_timer()
        self._timer = (
            None
            if when is None or self._connection.terminated or self._closed
            else self._loop.call_at(when, self._on_timer)
        )

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
                case StopSendingReceived():
                    pass
                case HandshakeCompleted():
                    if self._memory is not None:
                        self._memory.transport_parameters = (
                            self._connection.peer_transport_parameters
                        )
                        self._memory.round_trip_time = self._connection.round_trip_time
                    for future in (self._ready, self._handshake):
                        if not future.done():
                            future.set_result(None)
                case EarlyDataAvailable():
                    if not self._ready.done():
                        self._ready.set_result(None)
                case EarlyDataRejected():
                    pass
                case ConnectionTerminated():
                    if not self._terminated.done():
                        self._terminated.set_result(event)
                    self._fail(
                        RemoteDisconnected(
                            f"QUIC connection terminated: {event.reason or hex(event.error)}"
                        )
                    )
                    self.close()
                case DatagramReceived(data):
                    self.datagrams.put_nowait(data)
                case VersionNegotiated(version):
                    self._fail(VersionChange(version))
                    self.close()

    def _fail(self, error: BaseException) -> None:
        for future in (self._ready, self._handshake):
            if not future.done():
                future.set_exception(error)
                # a 0-RTT connection may never await the handshake; reading the exception keeps asyncio from logging it
                future.exception()
        for inbox in self._inboxes.values():
            inbox.error = error
            inbox.wake()
        if not self._terminated.done():
            self._terminated.set_result(ConnectionTerminated(0, str(error), False))
