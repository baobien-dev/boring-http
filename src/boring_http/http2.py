import asyncio
import logging
import struct
from collections.abc import AsyncGenerator, Callable
from enum import IntEnum
from http import HTTPStatus
from time import monotonic

from boring_ssl2 import Library
from ssl2.asynchronous import AsyncTransport, TLSStream
from ssl2.errors import ConfigurationError
from ssl2.fingerprint import Http2Priority, PseudoHeader
from ssl2.registry import Http2SettingIdentifier
from ssl2.tracing import Trace

from boring_http.errors import ProtocolError, RemoteDisconnectedError, StreamRefusedError, StreamResetError
from boring_http.headers import Headers
from boring_http.hpack import Decoder, Encoder
from boring_http.profiles import Http2Profile, HTTPVersion
from boring_http.request import Request
from boring_http.response import ConnectionInfo, Response
from boring_http.timing import Deadline, Phase
from boring_http.tracing import Event, Step


class FrameType(IntEnum):
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION = 0x9


class Flag(IntEnum):
    # an IntEnum rather than an IntFlag: the frame reader tests these on every frame and int's & is the fast one
    END_STREAM = 0x1
    ACK = 0x1
    END_HEADERS = 0x4
    PADDED = 0x8
    PRIORITY = 0x20


class Http2ErrorCode(IntEnum):
    NO_ERROR = 0x0
    PROTOCOL_ERROR = 0x1
    INTERNAL_ERROR = 0x2
    FLOW_CONTROL_ERROR = 0x3
    SETTINGS_TIMEOUT = 0x4
    STREAM_CLOSED = 0x5
    FRAME_SIZE_ERROR = 0x6
    REFUSED_STREAM = 0x7
    CANCEL = 0x8
    COMPRESSION_ERROR = 0x9
    CONNECT_ERROR = 0xA
    ENHANCE_YOUR_CALM = 0xB
    INADEQUATE_SECURITY = 0xC
    HTTP_1_1_REQUIRED = 0xD


class Default(IntEnum):
    # RFC 9113 section 6.5.2
    WINDOW = 65535
    FRAME_SIZE = 16384
    TABLE_SIZE = 4096
    HEADER_LIST_SIZE = 262144
    MAX_STREAMS = 1 << 31


class Size(IntEnum):
    FRAME_HEADER = 9
    LENGTH = 3
    READ = 65536
    # every DATA frame the windows allow goes out in one write, up to this much
    DATA_BATCH = 1 << 20
    SETTING = 6
    SETTING_IDENTIFIER = 2
    ERROR_CODE = 4
    PRIORITY = 5
    STREAM_ID_MASK = 0x7FFFFFFF
    EXCLUSIVE_SHIFT = 31
    WEIGHT_OFFSET = 1
    STREAM_STEP = 2


class Preface:
    BYTES = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


class Http2Stream:
    def __init__(self, identifier: int, send_window: int) -> None:
        self.identifier = identifier
        self.send_window = send_window
        self.window_changed = asyncio.Event()
        self.headers: asyncio.Future[tuple[int, Headers]] = asyncio.get_running_loop().create_future()
        self.chunks: list[bytes] = []
        self.error: BaseException | None = None
        self.waiter: asyncio.Future[None] | None = None
        self.trailers = Headers()
        self.block = bytearray()
        # what the application took since the last WINDOW_UPDATE for this stream
        self.consumed = 0
        self.finished = False

    def fail(self, error: BaseException) -> None:
        if not self.headers.done():
            self.headers.set_exception(error)
        self.error = error
        self.finished = True
        self.wake()

    def wake(self) -> None:
        if self.waiter is not None and not self.waiter.done():
            self.waiter.set_result(None)

    async def wait(self) -> None:
        self.waiter = asyncio.get_running_loop().create_future()
        try:
            await self.waiter
        finally:
            self.waiter = None

    def take(self) -> bytes:
        chunks, self.chunks = self.chunks, []
        return chunks[0] if len(chunks) == 1 else b"".join(chunks)


class Http2Connection:
    logger = logging.getLogger("boring_http")

    def __init__(self, transport: AsyncTransport, profile: Http2Profile, library: Library) -> None:
        self._transport = transport
        self._profile = profile
        self._library = library
        self._encoder = Encoder()
        self._decoder = Decoder(
            profile.setting(Http2SettingIdentifier.HEADER_TABLE_SIZE, Default.TABLE_SIZE),
            profile.setting(Http2SettingIdentifier.MAX_HEADER_LIST_SIZE, Default.HEADER_LIST_SIZE),
        )
        self._streams: dict[int, Http2Stream] = {}
        self._next_stream = 1
        self._write_lock = asyncio.Lock()
        self._buffer = bytearray()
        self._send_window: int = Default.WINDOW
        self._window_changed = asyncio.Event()
        self._peer_frame_size: int = Default.FRAME_SIZE
        self._peer_window: int = Default.WINDOW
        self._peer_max_streams: int = Default.MAX_STREAMS
        self._local_window = profile.setting(Http2SettingIdentifier.INITIAL_WINDOW_SIZE, Default.WINDOW)
        self._connection_window = Default.WINDOW + profile.fingerprint.window_update
        self._connection_received = 0
        self._goaway: int | None = None
        self._reader: asyncio.Task[None] | None = None
        self._settings_received: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self.connect_protocol = False
        self.closed = False
        self.reused = False
        self.connect_time = 0.0
        self.released: Callable[[], None] = self._nothing

    @property
    def available(self) -> bool:
        return not self.closed and self._goaway is None and len(self._streams) < self._peer_max_streams

    @property
    def shared(self) -> bool:
        return True

    @property
    def info(self) -> ConnectionInfo:
        transport = self._transport
        return ConnectionInfo.of(
            transport.getsockname(),
            transport.getpeername(),
            transport.buffer if isinstance(transport, TLSStream) else None,
        )

    def take(self) -> None:
        pass

    async def start(self) -> None:
        # the preface, then SETTINGS, WINDOW_UPDATE and PRIORITY frames as the fingerprint lists them
        fingerprint = self._profile.fingerprint
        settings = b"".join(
            struct.pack("!HI", int(setting.identifier), setting.value) for setting in fingerprint.settings
        )
        frames = self._frame(FrameType.SETTINGS, 0, 0, settings)
        if fingerprint.window_update:
            frames += self._frame(FrameType.WINDOW_UPDATE, 0, 0, struct.pack("!I", fingerprint.window_update))
        for priority in fingerprint.priorities:
            frames += self._frame(FrameType.PRIORITY, 0, priority.stream_id, self._priority_bytes(priority))
        await self._transport.write(Preface.BYTES + frames)
        self._reader = asyncio.create_task(self._read_loop())
        await self._settings_received

    async def send(self, request: Request, deadline: Deadline, *, decode: bool, trace: Trace | None) -> Response:
        stream = self._open()
        block = self._encoder.encode(self._fields(request))
        flags = Flag.END_HEADERS | (Flag.END_STREAM if request.body is None else 0)
        payload = block
        if self._profile.headers_priority is not None:
            flags |= Flag.PRIORITY
            payload = self._priority_bytes(self._profile.headers_priority) + block
        started = monotonic()
        try:
            with Trace.timing(trace, Step.SEND):
                async with deadline.phase(Phase.WRITE):
                    await self._write_headers(stream.identifier, payload, flags)
                if request.body is not None:
                    await self._write_body(stream, request, deadline)
            self.logger.debug(
                "%s method=%s url=%s version=%s stream=%d",
                Event.REQUEST_SENT,
                request.method,
                request.url,
                HTTPVersion.HTTP_2,
                stream.identifier,
            )
            with Trace.timing(trace, Step.HEADERS):
                async with deadline.phase(Phase.READ):
                    status, headers = await stream.headers
        except BaseException:
            await self._reset(stream, Http2ErrorCode.CANCEL)
            raise
        self.logger.info(
            "%s status=%d version=%s stream=%d seconds=%.3f",
            Event.RESPONSE_HEADERS,
            status,
            HTTPVersion.HTTP_2,
            stream.identifier,
            monotonic() - started,
        )
        return Response(
            status=status,
            reason="",
            version=HTTPVersion.HTTP_2,
            headers=headers,
            request=request,
            raw=self._body(stream, deadline, trace),
            trailers=stream.trailers,
            library=self._library,
            decode=decode,
            trace=trace,
        )

    async def tunnel(self, request: Request, deadline: Deadline) -> tuple[int, Headers, AsyncTransport]:
        # RFC 8441: an Extended CONNECT stream, which carries a WebSocket
        stream = self._open()
        fields = self._fields(request, protocol=b"websocket")
        try:
            async with deadline.phase(Phase.WRITE):
                await self._write_headers(stream.identifier, self._encoder.encode(fields), Flag.END_HEADERS)
            async with deadline.phase(Phase.READ):
                status, headers = await stream.headers
        except BaseException:
            await self._reset(stream, Http2ErrorCode.CANCEL)
            raise
        return status, headers, Http2StreamTransport(self, stream, deadline)

    async def write_data(self, stream: Http2Stream, data: bytes, *, end: bool) -> None:
        view = memoryview(data)
        while True:
            allowance = min(len(view), stream.send_window, self._send_window)
            if view and allowance == 0:
                stream.window_changed.clear()
                self._window_changed.clear()
                await asyncio.wait(
                    {
                        asyncio.ensure_future(stream.window_changed.wait()),
                        asyncio.ensure_future(self._window_changed.wait()),
                    },
                    return_when=asyncio.FIRST_COMPLETED,
                )
                continue
            batch = bytearray()
            sent = 0
            while sent < allowance and len(batch) < Size.DATA_BATCH:
                size = min(self._peer_frame_size, allowance - sent)
                last = end and sent + size == len(view)
                batch += self._frame_head(FrameType.DATA, Flag.END_STREAM if last else 0, stream.identifier, size)
                batch += view[sent : sent + size]
                sent += size
            if not view and end:
                batch += self._frame_head(FrameType.DATA, Flag.END_STREAM, stream.identifier, 0)
            if batch:
                await self._write(bytes(batch))
            stream.send_window -= sent
            self._send_window -= sent
            view = view[sent:]
            if not view:
                return

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self._reader is not None and self._reader is not asyncio.current_task():
            self._reader.cancel()
            await asyncio.wait({self._reader})
        for stream in list(self._streams.values()):
            stream.fail(RemoteDisconnectedError("the HTTP/2 connection was closed"))
        self._streams.clear()
        await self._transport.close()
        self.released()

    async def credit(self, stream: Http2Stream, size: int) -> None:
        # the stream window opens again as the application takes data, so a reader that stops holds the server at one window
        stream.consumed += size
        if stream.consumed > self._local_window // 2 and not stream.finished and not self.closed:
            increment, stream.consumed = stream.consumed, 0
            await self._write(self._frame(FrameType.WINDOW_UPDATE, 0, stream.identifier, struct.pack("!I", increment)))

    async def receive(self, stream: Http2Stream, deadline: Deadline) -> bytes:
        # the next piece of the stream's data, or nothing once the stream has ended
        while True:
            if stream.chunks:
                data = stream.take()
                await self.credit(stream, len(data))
                return data
            if stream.error is not None:
                raise stream.error
            if stream.finished:
                return b""
            async with deadline.phase(Phase.READ):
                await stream.wait()

    def _open(self) -> Http2Stream:
        if not self.available:
            raise RemoteDisconnectedError("the HTTP/2 connection accepts no new streams")
        stream = Http2Stream(self._next_stream, self._peer_window)
        self._next_stream += Size.STREAM_STEP
        self._streams[stream.identifier] = stream
        return stream

    def _fields(self, request: Request, *, protocol: bytes | None = None) -> list[tuple[bytes, bytes]]:
        wire = request.wire_headers(HTTPVersion.HTTP_2)
        authority = request.headers.get("host") or request.url.authority
        pseudo = {
            PseudoHeader.METHOD: (b":method", request.method.encode()),
            PseudoHeader.AUTHORITY: (b":authority", authority.encode()),
            PseudoHeader.SCHEME: (b":scheme", request.url.scheme.http.encode()),
            PseudoHeader.PATH: (b":path", request.url.target.encode()),
        }
        fields = [pseudo[header] for header in self._profile.fingerprint.pseudo_header_order]
        if protocol is not None:
            fields.insert(1, (b":protocol", protocol))
        fields += [(header.name.encode(), header.value.encode()) for header in wire]
        return fields

    async def _write_headers(self, identifier: int, payload: bytes, flags: int) -> None:
        first, rest = payload[: self._peer_frame_size], payload[self._peer_frame_size :]
        frames = self._frame(FrameType.HEADERS, flags & ~Flag.END_HEADERS if rest else flags, identifier, first)
        while rest:
            piece, rest = rest[: self._peer_frame_size], rest[self._peer_frame_size :]
            frames += self._frame(FrameType.CONTINUATION, 0 if rest else Flag.END_HEADERS, identifier, piece)
        await self._write(frames)

    async def _write_body(self, stream: Http2Stream, request: Request, deadline: Deadline) -> None:
        if request.body is None:
            return
        remaining = request.body.length
        # the write limit covers each wait for window and socket to take a chunk, not the whole body
        async for chunk in request.body.chunks():
            if remaining is not None:
                remaining -= len(chunk)
            async with deadline.phase(Phase.WRITE):
                await self.write_data(stream, chunk, end=remaining == 0)
        if remaining != 0:
            async with deadline.phase(Phase.WRITE):
                await self.write_data(stream, b"", end=True)

    async def _body(self, stream: Http2Stream, deadline: Deadline, trace: Trace | None) -> AsyncGenerator[bytes]:
        received = 0
        try:
            with Trace.timing(trace, Step.BODY):
                while data := await self.receive(stream, deadline):
                    received += len(data)
                    yield data
        except BaseException:
            await self._reset(stream, Http2ErrorCode.CANCEL)
            raise
        finally:
            self._streams.pop(stream.identifier, None)
            self.released()
        self.logger.info(
            "%s bytes=%d version=%s stream=%d", Event.RESPONSE_DONE, received, HTTPVersion.HTTP_2, stream.identifier
        )

    async def _reset(self, stream: Http2Stream, code: Http2ErrorCode) -> None:
        if self._streams.pop(stream.identifier, None) is not None and not self.closed and not stream.finished:
            await self._write(self._frame(FrameType.RST_STREAM, 0, stream.identifier, struct.pack("!I", code)))

    async def _write(self, data: bytes) -> None:
        async with self._write_lock:
            await self._transport.write(data)

    async def _read_loop(self) -> None:
        try:
            await self._read_frames()
        except (RemoteDisconnectedError, ProtocolError, OSError) as error:
            # the reader task is where a dead connection shows; every stream on it learns here
            self.closed = True
            failure = (
                error
                if isinstance(error, (RemoteDisconnectedError, ProtocolError))
                else RemoteDisconnectedError(str(error))
            )
            if self._streams or not self._settings_received.done():
                self.logger.warning("%s version=%s error=%s", Event.CONNECTION_FAILED, HTTPVersion.HTTP_2, failure)
            else:
                # a server closing an idle connection is the usual end of one, not a failure
                self.logger.info("%s version=%s reason=%s", Event.CONNECTION_CLOSED, HTTPVersion.HTTP_2, failure)
            if not self._settings_received.done():
                self._settings_received.set_exception(failure)
            for stream in list(self._streams.values()):
                stream.fail(failure)
            self._streams.clear()
            await self._transport.close()
            self.released()

    async def _read_frames(self) -> None:
        buffer = self._buffer
        while True:
            piece = await self._transport.read(Size.READ)
            if not piece:
                raise RemoteDisconnectedError("the server closed the HTTP/2 connection")
            buffer += piece
            # every whole frame in the buffer is handled before the next read; the replies they call for go out as one write
            offset = 0
            replies: list[bytes] = []
            with memoryview(buffer) as view:
                size = len(view)
                while size - offset >= Size.FRAME_HEADER:
                    length = int.from_bytes(view[offset : offset + Size.LENGTH])
                    end = offset + Size.FRAME_HEADER + length
                    if end > size:
                        break
                    kind = view[offset + Size.LENGTH]
                    flags = view[offset + Size.LENGTH + 1]
                    identifier = (
                        int.from_bytes(view[offset + Size.LENGTH + 2 : offset + Size.FRAME_HEADER])
                        & Size.STREAM_ID_MASK
                    )
                    reply = self._handle(kind, flags, identifier, bytes(view[offset + Size.FRAME_HEADER : end]))
                    if reply:
                        replies.append(reply)
                    offset = end
            del buffer[:offset]
            if replies:
                await self._write(b"".join(replies))

    def _handle(self, kind: int, flags: int, identifier: int, payload: bytes) -> bytes:
        # returns the frames the peer's frame calls for, or nothing
        match kind:
            case FrameType.DATA:
                return self._data(flags, identifier, payload)
            case FrameType.HEADERS | FrameType.CONTINUATION:
                self._headers(FrameType(kind), flags, identifier, payload)
            case FrameType.SETTINGS:
                return self._settings(flags, payload)
            case FrameType.WINDOW_UPDATE:
                self._window_update(identifier, payload)
            case FrameType.RST_STREAM:
                self._reset_received(identifier, payload)
            case FrameType.PING:
                if not flags & Flag.ACK:
                    return self._frame(FrameType.PING, Flag.ACK, 0, payload)
            case FrameType.GOAWAY:
                self._goaway_received(payload)
            case FrameType.PUSH_PROMISE:
                raise ProtocolError("the server pushed a stream although push is disabled")
            case _:
                pass
        return b""

    def _data(self, flags: int, identifier: int, payload: bytes) -> bytes:
        if flags & Flag.PADDED:
            payload = payload[1 : len(payload) - payload[0]]
        stream = self._streams.get(identifier)
        if stream is not None:
            if payload:
                stream.chunks.append(payload)
            if flags & Flag.END_STREAM:
                stream.finished = True
            stream.wake()
        # the connection window opens on arrival, so one stream that is not read leaves the others their share
        self._connection_received += len(payload)
        if self._connection_received > self._connection_window // 2:
            update = self._frame(FrameType.WINDOW_UPDATE, 0, 0, struct.pack("!I", self._connection_received))
            self._connection_received = 0
            return update
        return b""

    def _headers(self, kind: FrameType, flags: int, identifier: int, payload: bytes) -> None:
        stream = self._streams.get(identifier)
        if stream is None:
            return
        if kind is FrameType.HEADERS:
            if flags & Flag.PADDED:
                payload = payload[1 : len(payload) - payload[0]]
            if flags & Flag.PRIORITY:
                payload = payload[Size.PRIORITY :]
            stream.block = bytearray()
        stream.block += payload
        if not flags & Flag.END_HEADERS:
            return
        decoded = [
            (name.decode("latin-1"), value.decode("latin-1"))
            for name, value in self._decoder.decode(bytes(stream.block))
        ]
        stream.block = bytearray()
        pseudo = {name: value for name, value in decoded if name.startswith(":")}
        try:
            regular = Headers([(name, value) for name, value in decoded if not name.startswith(":")])
        except ConfigurationError as error:
            stream.fail(ProtocolError(f"malformed header from the server: {error}"))
            return
        if not stream.headers.done():
            status = pseudo.get(":status", "")
            if not (status.isascii() and status.isdigit()):
                stream.fail(ProtocolError("HTTP/2 response without a numeric :status"))
                return
            if HTTPStatus.CONTINUE <= int(status) < HTTPStatus.OK:
                return
            stream.headers.set_result((int(status), regular))
        else:
            for header in regular:
                stream.trailers.append(header)
        if flags & Flag.END_STREAM:
            stream.finished = True
            stream.wake()

    def _settings(self, flags: int, payload: bytes) -> bytes:
        if flags & Flag.ACK:
            return b""
        for offset in range(0, len(payload) - Size.SETTING + 1, Size.SETTING):
            identifier = int.from_bytes(payload[offset : offset + Size.SETTING_IDENTIFIER], "big")
            value = int.from_bytes(payload[offset + Size.SETTING_IDENTIFIER : offset + Size.SETTING], "big")
            match identifier:
                case Http2SettingIdentifier.HEADER_TABLE_SIZE:
                    self._encoder.set_capacity(value)
                case Http2SettingIdentifier.INITIAL_WINDOW_SIZE:
                    for stream in self._streams.values():
                        stream.send_window += value - self._peer_window
                        stream.window_changed.set()
                    self._peer_window = value
                case Http2SettingIdentifier.MAX_FRAME_SIZE:
                    self._peer_frame_size = value
                case Http2SettingIdentifier.MAX_CONCURRENT_STREAMS:
                    self._peer_max_streams = value
                case Http2SettingIdentifier.ENABLE_CONNECT_PROTOCOL:
                    self.connect_protocol = value == 1
                case _:
                    pass
        if not self._settings_received.done():
            self._settings_received.set_result(None)
        return self._frame(FrameType.SETTINGS, Flag.ACK, 0, b"")

    def _window_update(self, identifier: int, payload: bytes) -> None:
        increment = int.from_bytes(payload[: Size.ERROR_CODE], "big") & Size.STREAM_ID_MASK
        if identifier == 0:
            self._send_window += increment
            self._window_changed.set()
        elif (stream := self._streams.get(identifier)) is not None:
            stream.send_window += increment
            stream.window_changed.set()

    def _reset_received(self, identifier: int, payload: bytes) -> None:
        stream = self._streams.pop(identifier, None)
        if stream is None:
            return
        code = int.from_bytes(payload[: Size.ERROR_CODE], "big")
        if code == Http2ErrorCode.REFUSED_STREAM:
            stream.fail(StreamRefusedError(f"stream {identifier} refused by the server"))
        else:
            stream.fail(StreamResetError(identifier, Http2ErrorCode(code) if code in Http2ErrorCode else code))

    def _goaway_received(self, payload: bytes) -> None:
        last = int.from_bytes(payload[: Size.ERROR_CODE], "big") & Size.STREAM_ID_MASK
        code = int.from_bytes(payload[Size.ERROR_CODE : 2 * Size.ERROR_CODE], "big")
        reason = Http2ErrorCode(code).name if code in Http2ErrorCode else f"{code:#x}"
        self._goaway = last
        for stream_id, stream in list(self._streams.items()):
            if stream_id > last:
                stream.fail(StreamRefusedError(f"stream {stream_id} refused by GOAWAY ({reason})"))
                del self._streams[stream_id]

    @classmethod
    def _frame(cls, kind: FrameType, flags: int, identifier: int, payload: bytes) -> bytes:
        return cls._frame_head(kind, flags, identifier, len(payload)) + payload

    @staticmethod
    def _frame_head(kind: FrameType, flags: int, identifier: int, length: int) -> bytes:
        return length.to_bytes(Size.LENGTH, "big") + bytes((kind, flags)) + struct.pack("!I", identifier)

    @staticmethod
    def _priority_bytes(priority: Http2Priority) -> bytes:
        return struct.pack("!I", priority.dependency | (priority.exclusive << Size.EXCLUSIVE_SHIFT)) + bytes(
            (priority.weight - Size.WEIGHT_OFFSET,)
        )

    @staticmethod
    def _nothing() -> None:
        pass


class Http2StreamTransport:
    # one HTTP/2 stream as a transport, for a WebSocket over Extended CONNECT
    def __init__(self, connection: Http2Connection, stream: Http2Stream, deadline: Deadline) -> None:
        self._connection = connection
        self._stream = stream
        self._deadline = deadline
        self._pending = b""
        self._closed = False

    async def read(self, limit: int) -> bytes:
        if not self._pending:
            self._pending = await self._connection.receive(self._stream, self._deadline)
        piece, self._pending = self._pending[:limit], self._pending[limit:]
        return piece

    async def write(self, data: bytes) -> None:
        await self._connection.write_data(self._stream, data, end=False)

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            # the connection was opened for this tunnel alone, so it ends with it
            try:
                await self._connection.write_data(self._stream, b"", end=True)
            finally:
                await self._connection.close()

    def getsockname(self) -> tuple[str | None, int]:
        return self._connection.info.local_address

    def getpeername(self) -> tuple[str | None, int]:
        return self._connection.info.remote_address
