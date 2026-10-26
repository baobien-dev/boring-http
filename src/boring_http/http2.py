import asyncio
import struct
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import Final, final

from ssl2 import (
    AkamaiFingerprint,
    AsyncTransport,
    Http2Priority,
    Http2Setting,
    Http2SettingIdentifier,
    PseudoHeader,
)

from boring_http.errors import (
    ProtocolError,
    RemoteDisconnected,
    StreamRefused,
    StreamResetError,
)
from boring_http.hpack import Decoder, Encoder
from boring_http.message import Headers, HTTPVersion, Request, Response
from boring_http.timing import Deadline

PREFACE: Final = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DEFAULT_WINDOW: Final = 65535
DEFAULT_FRAME_SIZE: Final = 16384
DEFAULT_TABLE_SIZE: Final = 4096
DEFAULT_HEADER_LIST_SIZE: Final = 262144


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


class Flag(IntFlag):
    END_STREAM = 0x1
    ACK = 0x1
    END_HEADERS = 0x4
    PADDED = 0x8
    PRIORITY = 0x20


# plain integers for the frame reader: an IntFlag operand routes every `&` through Python-level enum code
END_STREAM: Final = Flag.END_STREAM.value
ACK: Final = Flag.ACK.value
END_HEADERS: Final = Flag.END_HEADERS.value
PADDED: Final = Flag.PADDED.value
PRIORITY: Final = Flag.PRIORITY.value


class ErrorCode(IntEnum):
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


@final
@dataclass(frozen=True, slots=True)
class Http2Profile:
    fingerprint: AkamaiFingerprint
    headers_priority: Http2Priority | None = None

    def setting(self, identifier: Http2SettingIdentifier, default: int) -> int:
        return next(
            (
                setting.value
                for setting in self.fingerprint.settings
                if setting.identifier is identifier
            ),
            default,
        )


CHROME: Final = Http2Profile(
    AkamaiFingerprint(
        settings=(
            Http2Setting(Http2SettingIdentifier.HEADER_TABLE_SIZE, 65536),
            Http2Setting(Http2SettingIdentifier.ENABLE_PUSH, 0),
            Http2Setting(Http2SettingIdentifier.INITIAL_WINDOW_SIZE, 6291456),
            Http2Setting(Http2SettingIdentifier.MAX_HEADER_LIST_SIZE, 262144),
        ),
        window_update=15663105,
        priorities=(),
        pseudo_header_order=(
            PseudoHeader.METHOD,
            PseudoHeader.AUTHORITY,
            PseudoHeader.SCHEME,
            PseudoHeader.PATH,
        ),
    ),
    headers_priority=Http2Priority(
        stream_id=0, exclusive=True, dependency=0, weight=256
    ),
)


@final
class Http2Stream:
    def __init__(self, identifier: int, send_window: int) -> None:
        self.identifier = identifier
        self.send_window = send_window
        self.window_changed = asyncio.Event()
        self.headers: asyncio.Future[tuple[int, Headers]] = (
            asyncio.get_running_loop().create_future()
        )
        self.data = bytearray()
        self.error: BaseException | None = None
        self.waiter: asyncio.Future[None] | None = None
        self.trailers = Headers()
        self.block = bytearray()
        self.received = 0
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
        data = bytes(self.data)
        self.data = bytearray()
        return data


@final
class Http2Connection:
    def __init__(self, transport: AsyncTransport, profile: Http2Profile) -> None:
        self._transport = transport
        self._profile = profile
        self._encoder = Encoder()
        self._decoder = Decoder(
            profile.setting(
                Http2SettingIdentifier.HEADER_TABLE_SIZE, DEFAULT_TABLE_SIZE
            ),
            profile.setting(
                Http2SettingIdentifier.MAX_HEADER_LIST_SIZE, DEFAULT_HEADER_LIST_SIZE
            ),
        )
        self._streams: dict[int, Http2Stream] = {}
        self._next_stream = 1
        self._write_lock = asyncio.Lock()
        self._buffer = bytearray()
        self._offset = 0
        self._send_window: int = DEFAULT_WINDOW
        self._window_changed = asyncio.Event()
        self._peer_frame_size = DEFAULT_FRAME_SIZE
        self._peer_window = DEFAULT_WINDOW
        self._peer_max_streams = 2**31
        self._local_window = profile.setting(
            Http2SettingIdentifier.INITIAL_WINDOW_SIZE, DEFAULT_WINDOW
        )
        self._connection_window = DEFAULT_WINDOW + profile.fingerprint.window_update
        self._connection_received = 0
        self._goaway: int | None = None
        self._reader: asyncio.Task[None] | None = None
        self.connect_protocol = False
        self._settings_received: asyncio.Future[None] = (
            asyncio.get_running_loop().create_future()
        )
        self.closed = False
        self.reused = False
        self.released: Callable[[], None] = self._nothing

    @property
    def available(self) -> bool:
        return (
            not self.closed
            and self._goaway is None
            and len(self._streams) < self._peer_max_streams
        )

    @property
    def shared(self) -> bool:
        return True

    def take(self) -> None:
        pass

    async def start(self) -> None:
        fingerprint = self._profile.fingerprint
        settings = b"".join(
            struct.pack("!HI", int(setting.identifier), setting.value)
            for setting in fingerprint.settings
        )
        frames = self._frame(FrameType.SETTINGS, 0, 0, settings)
        if fingerprint.window_update:
            frames += self._frame(
                FrameType.WINDOW_UPDATE,
                0,
                0,
                struct.pack("!I", fingerprint.window_update),
            )
        for priority in fingerprint.priorities:
            frames += self._frame(
                FrameType.PRIORITY,
                0,
                priority.stream_id,
                self._priority_bytes(priority),
            )
        await self._transport.write(PREFACE + frames)
        self._reader = asyncio.create_task(self._read_loop())
        await self._settings_received

    async def send(
        self, request: Request, deadline: Deadline, *, decode: bool
    ) -> Response:
        stream = self._open()
        block = self._encoder.encode(self._fields(request))
        flags = Flag.END_HEADERS | (
            Flag.END_STREAM if request.body is None else Flag(0)
        )
        payload = block
        if self._profile.headers_priority is not None:
            flags |= Flag.PRIORITY
            payload = self._priority_bytes(self._profile.headers_priority) + block
        try:
            async with deadline.phase("write"):
                await self._write_headers(stream.identifier, payload, flags)
                if request.body is not None:
                    await self._write_body(stream, request)
            async with deadline.phase("read"):
                status, headers = await stream.headers
        except BaseException:
            await self._reset(stream, ErrorCode.CANCEL)
            raise
        return Response(
            status=status,
            reason="",
            version=HTTPVersion.HTTP_2,
            headers=headers,
            request=request,
            raw=self._body(stream, deadline),
            trailers=stream.trailers,
            decode=decode,
        )

    async def tunnel(
        self, request: Request, deadline: Deadline
    ) -> tuple[int, Headers, AsyncTransport]:
        stream = self._open()
        fields = self._fields(request, protocol=b"websocket")
        try:
            async with deadline.phase("write"):
                await self._write_headers(
                    stream.identifier, self._encoder.encode(fields), Flag.END_HEADERS
                )
            async with deadline.phase("read"):
                status, headers = await stream.headers
        except BaseException:
            await self._reset(stream, ErrorCode.CANCEL)
            raise
        return status, headers, Http2StreamTransport(self, stream, deadline)

    async def write_data(self, stream: Http2Stream, data: bytes, *, end: bool) -> None:
        view = memoryview(data)
        while view or end:
            size = min(
                len(view), self._peer_frame_size, stream.send_window, self._send_window
            )
            if size == 0 and view:
                stream.window_changed.clear()
                self._window_changed.clear()
                _ = await asyncio.wait(
                    {
                        asyncio.ensure_future(stream.window_changed.wait()),
                        asyncio.ensure_future(self._window_changed.wait()),
                    },
                    return_when=asyncio.FIRST_COMPLETED,
                )
                continue
            last = end and size == len(view)
            await self._write(
                self._frame(
                    FrameType.DATA,
                    Flag.END_STREAM if last else 0,
                    stream.identifier,
                    bytes(view[:size]),
                )
            )
            stream.send_window -= size
            self._send_window -= size
            view = view[size:]
            if last:
                return

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self._reader is not None and self._reader is not asyncio.current_task():
            _ = self._reader.cancel()
            _ = await asyncio.wait({self._reader})
        for stream in list(self._streams.values()):
            stream.fail(RemoteDisconnected("the HTTP/2 connection was closed"))
        self._streams.clear()
        await self._transport.close()
        self.released()

    def _open(self) -> Http2Stream:
        if not self.available:
            raise RemoteDisconnected("the HTTP/2 connection accepts no new streams")
        stream = Http2Stream(self._next_stream, self._peer_window)
        self._next_stream += 2
        self._streams[stream.identifier] = stream
        return stream

    def _fields(
        self, request: Request, *, protocol: bytes | None = None
    ) -> list[tuple[bytes, bytes]]:
        wire = request.wire_headers(HTTPVersion.HTTP_2)
        authority = request.headers.get("host") or request.url.authority
        scheme = {"ws": "http", "wss": "https"}.get(
            request.url.scheme, request.url.scheme
        )
        pseudo = {
            PseudoHeader.METHOD: (b":method", request.method.encode()),
            PseudoHeader.AUTHORITY: (b":authority", authority.encode()),
            PseudoHeader.SCHEME: (b":scheme", scheme.encode()),
            PseudoHeader.PATH: (b":path", request.url.target.encode()),
        }
        fields = [
            pseudo[header] for header in self._profile.fingerprint.pseudo_header_order
        ]
        if protocol is not None:
            fields.insert(1, (b":protocol", protocol))
        fields += [(name.encode(), value.encode()) for name, value in wire]
        return fields

    async def _write_headers(
        self, identifier: int, payload: bytes, flags: Flag
    ) -> None:
        first, rest = payload[: self._peer_frame_size], payload[self._peer_frame_size :]
        frames = self._frame(
            FrameType.HEADERS,
            flags & ~Flag.END_HEADERS if rest else flags,
            identifier,
            first,
        )
        while rest:
            piece, rest = rest[: self._peer_frame_size], rest[self._peer_frame_size :]
            frames += self._frame(
                FrameType.CONTINUATION,
                Flag(0) if rest else Flag.END_HEADERS,
                identifier,
                piece,
            )
        await self._write(frames)

    async def _write_body(self, stream: Http2Stream, request: Request) -> None:
        if request.body is None:
            return
        remaining = request.body.length
        async for chunk in request.body.chunks():
            if remaining is not None:
                remaining -= len(chunk)
            await self.write_data(stream, chunk, end=remaining == 0)
        if remaining != 0:
            await self.write_data(stream, b"", end=True)

    async def _body(
        self, stream: Http2Stream, deadline: Deadline
    ) -> AsyncGenerator[bytes]:
        try:
            while True:
                if stream.data:
                    yield stream.take()
                elif stream.error is not None:
                    raise stream.error
                elif stream.finished:
                    break
                else:
                    async with deadline.phase("read"):
                        await stream.wait()
        except BaseException:
            await self._reset(stream, ErrorCode.CANCEL)
            raise
        finally:
            _ = self._streams.pop(stream.identifier, None)
            self.released()

    async def _reset(self, stream: Http2Stream, code: ErrorCode) -> None:
        if (
            self._streams.pop(stream.identifier, None) is not None
            and not self.closed
            and not stream.finished
        ):
            await self._write(
                self._frame(
                    FrameType.RST_STREAM, 0, stream.identifier, struct.pack("!I", code)
                )
            )

    async def _write(self, data: bytes) -> None:
        async with self._write_lock:
            await self._transport.write(data)

    async def _read_loop(self) -> None:
        try:
            while True:
                head = await self._read_exactly(9)
                length = int.from_bytes(head[:3], "big")
                kind, flags = head[3], head[4]
                identifier = int.from_bytes(head[5:9], "big") & 0x7FFFFFFF
                await self._handle(
                    kind, flags, identifier, await self._read_exactly(length)
                )
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001  the reader task is where any failure becomes a closed connection
            self.closed = True
            failure = (
                error
                if isinstance(error, (RemoteDisconnected, ProtocolError))
                else RemoteDisconnected(f"the HTTP/2 connection failed: {error}")
            )
            if not self._settings_received.done():
                self._settings_received.set_exception(failure)
            for stream in list(self._streams.values()):
                stream.fail(failure)
            self._streams.clear()
            await self._transport.close()
            self.released()

    async def _read_exactly(self, length: int) -> bytes:
        buffer = self._buffer
        while len(buffer) - self._offset < length:
            if self._offset:
                del buffer[: self._offset]
                self._offset = 0
            piece = await self._transport.read(65536)
            if not piece:
                raise RemoteDisconnected("the server closed the HTTP/2 connection")
            buffer += piece
        start = self._offset
        self._offset = start + length
        return bytes(memoryview(buffer)[start : self._offset])

    async def _handle(
        self, kind: int, flags: int, identifier: int, payload: bytes
    ) -> None:
        match kind:
            case FrameType.DATA:
                await self._data(flags, identifier, payload)
            case FrameType.HEADERS | FrameType.CONTINUATION:
                self._headers(FrameType(kind), flags, identifier, payload)
            case FrameType.SETTINGS:
                await self._settings(flags, payload)
            case FrameType.WINDOW_UPDATE:
                self._window_update(identifier, payload)
            case FrameType.RST_STREAM:
                stream = self._streams.pop(identifier, None)
                if stream is not None:
                    code = int.from_bytes(payload[:4], "big")
                    stream.fail(
                        StreamRefused(f"stream {identifier} refused by the server")
                        if code == ErrorCode.REFUSED_STREAM
                        else StreamResetError(identifier, code)
                    )
            case FrameType.PING:
                if not flags & ACK:
                    await self._write(self._frame(FrameType.PING, Flag.ACK, 0, payload))
            case FrameType.GOAWAY:
                last = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
                self._goaway = last
                for stream_id, stream in list(self._streams.items()):
                    if stream_id > last:
                        stream.fail(
                            StreamRefused(
                                f"stream {stream_id} refused by GOAWAY ({self._error_name(payload[4:8])})"
                            )
                        )
                        del self._streams[stream_id]
            case FrameType.PUSH_PROMISE:
                raise ProtocolError(
                    "the server pushed a stream although push is disabled"
                )
            case _:
                pass

    async def _data(self, flags: int, identifier: int, payload: bytes) -> None:
        if flags & PADDED:
            payload = payload[1 : len(payload) - payload[0]]
        stream = self._streams.get(identifier)
        if stream is not None:
            stream.data += payload
            if flags & END_STREAM:
                stream.finished = True
            stream.wake()
            stream.received += len(payload)
            if stream.received > self._local_window // 2 and not stream.finished:
                await self._write(
                    self._frame(
                        FrameType.WINDOW_UPDATE,
                        0,
                        identifier,
                        struct.pack("!I", stream.received),
                    )
                )
                stream.received = 0
        self._connection_received += len(payload)
        if self._connection_received > self._connection_window // 2:
            await self._write(
                self._frame(
                    FrameType.WINDOW_UPDATE,
                    0,
                    0,
                    struct.pack("!I", self._connection_received),
                )
            )
            self._connection_received = 0

    def _headers(
        self, kind: FrameType, flags: int, identifier: int, payload: bytes
    ) -> None:
        stream = self._streams.get(identifier)
        if stream is None:
            return
        if kind is FrameType.HEADERS:
            if flags & PADDED:
                payload = payload[1 : len(payload) - payload[0]]
            if flags & PRIORITY:
                payload = payload[5:]
            stream.block = bytearray()
        stream.block += payload
        if not flags & END_HEADERS:
            return
        decoded = [
            (name.decode("latin-1"), value.decode("latin-1"))
            for name, value in self._decoder.decode(bytes(stream.block))
        ]
        stream.block = bytearray()
        pseudo = {name: value for name, value in decoded if name.startswith(":")}
        try:
            regular = Headers(
                [(name, value) for name, value in decoded if not name.startswith(":")]
            )
        except ValueError as error:
            stream.fail(ProtocolError(f"malformed header from the server: {error}"))
            return
        if not stream.headers.done():
            status = pseudo.get(":status", "")
            if not (status.isascii() and status.isdigit()):
                stream.fail(ProtocolError("HTTP/2 response without a numeric :status"))
                return
            if 100 <= int(status) < 200:
                return
            stream.headers.set_result((int(status), regular))
        else:
            for name, value in regular:
                stream.trailers.add(name, value)
        if flags & END_STREAM:
            stream.finished = True
            stream.wake()

    async def _settings(self, flags: int, payload: bytes) -> None:
        if flags & ACK:
            return
        for offset in range(0, len(payload) - 5, 6):
            identifier, value = (
                int.from_bytes(payload[offset : offset + 2], "big"),
                int.from_bytes(payload[offset + 2 : offset + 6], "big"),
            )
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
        await self._write(self._frame(FrameType.SETTINGS, Flag.ACK, 0, b""))

    def _window_update(self, identifier: int, payload: bytes) -> None:
        increment = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
        if identifier == 0:
            self._send_window += increment
            self._window_changed.set()
        elif (stream := self._streams.get(identifier)) is not None:
            stream.send_window += increment
            stream.window_changed.set()

    @staticmethod
    def _frame(kind: FrameType, flags: int, identifier: int, payload: bytes) -> bytes:
        return (
            len(payload).to_bytes(3, "big")
            + bytes((kind, flags))
            + struct.pack("!I", identifier)
            + payload
        )

    @staticmethod
    def _priority_bytes(priority: Http2Priority) -> bytes:
        return struct.pack(
            "!I", priority.dependency | (priority.exclusive << 31)
        ) + bytes((priority.weight - 1,))

    @staticmethod
    def _error_name(payload: bytes) -> str:
        code = int.from_bytes(payload[:4], "big")
        return ErrorCode(code).name if code in ErrorCode else f"{code:#x}"

    @staticmethod
    def _nothing() -> None:
        pass


@final
class Http2StreamTransport:
    def __init__(
        self, connection: Http2Connection, stream: Http2Stream, deadline: Deadline
    ) -> None:
        self._connection = connection
        self._stream = stream
        self._deadline = deadline
        self._pending = b""
        self._closed = False

    async def read(self, limit: int) -> bytes:
        stream = self._stream
        while not self._pending:
            if stream.data:
                self._pending = stream.take()
            elif stream.error is not None:
                raise stream.error
            elif stream.finished:
                return b""
            else:
                async with self._deadline.phase("read"):
                    await stream.wait()
        piece, self._pending = self._pending[:limit], self._pending[limit:]
        return piece

    async def write(self, data: bytes) -> None:
        await self._connection.write_data(self._stream, data, end=False)

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            await self._connection.write_data(self._stream, b"", end=True)
