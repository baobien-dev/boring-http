import asyncio
import secrets
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass
from enum import IntEnum

from boring_ssl2 import QuicVersion
from ssl2 import AsyncTransport, ClientHello, PseudoHeader

from boring_http.errors import (
    ProtocolError,
    RemoteDisconnected,
    StreamRefused,
    StreamResetError,
)
from boring_http.message import Headers, HTTPVersion, Request, Response
from boring_http.qpack import Qpack
from boring_http.quic.connection import TransportParameters
from boring_http.quic.packet import Reader, Writer
from boring_http.quic.protocol import OriginMemory, QuicClient
from boring_http.timing import Deadline, Timeout


class FrameType(IntEnum):
    DATA = 0x00
    HEADERS = 0x01
    CANCEL_PUSH = 0x03
    SETTINGS = 0x04
    PUSH_PROMISE = 0x05
    GOAWAY = 0x07
    MAX_PUSH_ID = 0x0D
    PRIORITY_UPDATE_REQUEST = 0xF0700


class StreamType(IntEnum):
    CONTROL = 0x00
    PUSH = 0x01
    QPACK_ENCODER = 0x02
    QPACK_DECODER = 0x03


class Setting(IntEnum):
    QPACK_MAX_TABLE_CAPACITY = 0x01
    MAX_FIELD_SECTION_SIZE = 0x06
    QPACK_BLOCKED_STREAMS = 0x07
    ENABLE_CONNECT_PROTOCOL = 0x08
    H3_DATAGRAM = 0x33


class ErrorCode(IntEnum):
    NO_ERROR = 0x100
    GENERAL_PROTOCOL_ERROR = 0x101
    INTERNAL_ERROR = 0x102
    STREAM_CREATION_ERROR = 0x103
    CLOSED_CRITICAL_STREAM = 0x104
    FRAME_UNEXPECTED = 0x105
    FRAME_ERROR = 0x106
    EXCESSIVE_LOAD = 0x107
    ID_ERROR = 0x108
    SETTINGS_ERROR = 0x109
    MISSING_SETTINGS = 0x10A
    REQUEST_REJECTED = 0x10B
    REQUEST_CANCELLED = 0x10C
    REQUEST_INCOMPLETE = 0x10D
    MESSAGE_ERROR = 0x10E
    CONNECT_ERROR = 0x10F
    VERSION_FALLBACK = 0x110


@dataclass(frozen=True, slots=True)
class Http3Settings:
    settings: tuple[tuple[int, int], ...]
    pseudo_header_order: tuple[PseudoHeader, ...]
    transport: TransportParameters
    quic_version: QuicVersion = QuicVersion.V1
    tls: ClientHello | None = None
    grease: bool = False

    def setting(self, identifier: Setting, default: int) -> int:
        return next(
            (value for key, value in self.settings if key == identifier), default
        )


# RFC 8470 section 5.2: the requests a client may send before the handshake, since a server may see them twice
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class StreamFrames:
    def __init__(self, client: QuicClient, stream_id: int, deadline: Deadline) -> None:
        self._client = client
        self._stream_id = stream_id
        self._deadline = deadline
        self._buffer = bytearray()
        self.ended = False

    async def next(self) -> tuple[int, bytes] | None:
        kind = await self.varint()
        if kind is None:
            return None
        length = await self.varint()
        if length is None:
            raise ProtocolError("HTTP/3 frame ended inside its length")
        return kind, await self._exactly(length)

    async def varint(self) -> int | None:
        if not await self._fill(1):
            return None
        length = 1 << (self._buffer[0] >> 6)
        if not await self._fill(length):
            raise ProtocolError("HTTP/3 stream ended inside a varint")
        return Reader(await self._exactly(length)).varint()

    def drain(self) -> bytes:
        data = bytes(self._buffer)
        self._buffer.clear()
        return data

    async def _exactly(self, length: int) -> bytes:
        if not await self._fill(length):
            raise ProtocolError("HTTP/3 stream ended inside a frame")
        data = bytes(self._buffer[:length])
        del self._buffer[:length]
        return data

    async def _fill(self, length: int) -> bool:
        while len(self._buffer) < length:
            if self.ended:
                return False
            async with self._deadline.phase("read"):
                piece = await self._client.receive(self._stream_id)
            if not piece:
                self.ended = True
                return len(self._buffer) >= length
            self._buffer += piece
        return True


class Http3Connection:
    def __init__(
        self,
        quic: QuicClient,
        settings: Http3Settings,
        memory: OriginMemory | None = None,
    ) -> None:
        self._quic = quic
        self._local_settings = settings
        self._qpack = Qpack(settings.setting(Setting.QPACK_MAX_TABLE_CAPACITY, 0))
        self._control_stream = -1
        self._decoder_stream = -1
        self._peer_settings: dict[int, int] = {}
        self._memory = memory
        self._goaway = False
        self._pending: set[int] = set()
        self._readers: set[asyncio.Task[None]] = set()
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
            and not self._goaway
            and not self._quic.closed
            and self._quic.connection.can_open_stream()
        )

    @property
    def shared(self) -> bool:
        return True

    @property
    def connect_protocol(self) -> bool:
        return self._peer_settings.get(Setting.ENABLE_CONNECT_PROTOCOL) == 1

    def take(self) -> None:
        pass

    async def start(self) -> None:
        self._control_stream = self._quic.open_stream(bidirectional=False)
        writer = Writer()
        writer.varint(StreamType.CONTROL)
        settings = Writer()
        entries = list(self._local_settings.settings)
        if self._local_settings.grease:
            # RFC 9114 section 7.2.4.1: a reserved identifier the peer must ignore, placed at random
            entries.insert(
                secrets.randbelow(len(entries) + 1),
                (0x1F * secrets.randbelow(1 << 16) + 0x21, secrets.randbelow(1 << 20)),
            )
        for identifier, value in entries:
            settings.varint(identifier)
            settings.varint(value)
        writer.varint(FrameType.SETTINGS)
        writer.varint(len(settings))
        writer.put(settings.finish())
        if self._local_settings.grease:
            # RFC 9114 section 7.2.8: an empty frame of a reserved type right after SETTINGS
            writer.varint(0x1F * secrets.randbelow(1 << 32) + 0x21)
            writer.varint(0)
        self._quic.send(self._control_stream, writer.finish())
        self._quic.send(
            self._quic.open_stream(bidirectional=False),
            Writer.encode_varint(StreamType.QPACK_ENCODER),
        )
        self._decoder_stream = self._quic.open_stream(bidirectional=False)
        self._quic.send(
            self._decoder_stream, Writer.encode_varint(StreamType.QPACK_DECODER)
        )
        self._readers.add(asyncio.create_task(self._read_peer_streams()))
        if (
            self._quic.connection.early_data_pending
            and self._memory is not None
            and self._memory.settings
        ):
            # RFC 9114 section 7.2.4.2: 0-RTT requests run under the settings the server sent last time
            self._peer_settings = dict(self._memory.settings)
            return
        await asyncio.wait(
            {self._settings_received, self._quic.terminated},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if not self._settings_received.done():
            terminated = self._quic.terminated.result()
            raise RemoteDisconnected(
                f"QUIC connection terminated before the HTTP/3 SETTINGS frame: {terminated.reason or hex(terminated.error)}"
            )
        await self._settings_received

    async def send(
        self, request: Request, deadline: Deadline, *, decode: bool
    ) -> Response:
        if request.method not in SAFE_METHODS:
            await self._established(deadline)
        early = self._quic.connection.early_data_pending
        stream_id = self._quic.open_stream()
        priority = request.headers.get("priority")
        if priority is not None:
            # RFC 9218 section 7.2: a request's priority goes on the control stream before its HEADERS
            self._quic.send(
                self._control_stream,
                self._frame(
                    FrameType.PRIORITY_UPDATE_REQUEST,
                    Writer.encode_varint(stream_id) + priority.encode(),
                ),
            )
        block = self._qpack.encode(self._fields(request))
        self._quic.send(
            stream_id, self._frame(FrameType.HEADERS, block), end=request.body is None
        )
        if request.body is not None:
            async with deadline.phase("write"):
                async for chunk in request.body.chunks():
                    self._quic.send(stream_id, self._frame(FrameType.DATA, chunk))
                self._quic.send(stream_id, b"", end=True)
        frames = StreamFrames(self._quic, stream_id, deadline)
        status, headers = await self._response_head(frames, stream_id)
        trailers = Headers()
        if (
            status == 425
            and early
            and (request.body is None or request.body.replayable)
        ):
            # RFC 8470 section 5.2: the server wants this request again once the handshake has finished
            await self._established(deadline)
            async for _ in self._body(frames, stream_id, trailers):
                pass
            return await self.send(request, deadline, decode=decode)
        return Response(
            status=status,
            reason="",
            version=HTTPVersion.HTTP_3,
            headers=headers,
            request=request,
            raw=self._body(frames, stream_id, trailers),
            trailers=trailers,
            decode=decode,
        )

    async def tunnel(
        self, request: Request, deadline: Deadline
    ) -> tuple[int, Headers, AsyncTransport]:
        await self._established(deadline)
        stream_id = self._quic.open_stream()
        self._quic.send(
            stream_id,
            self._frame(
                FrameType.HEADERS,
                self._qpack.encode(self._fields(request, protocol=b"websocket")),
            ),
        )
        frames = StreamFrames(self._quic, stream_id, deadline)
        status, headers = await self._response_head(frames, stream_id)
        return (
            status,
            headers,
            Http3StreamTransport(self._quic, stream_id, deadline, frames),
        )

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for reader in self._readers:
            reader.cancel()
        self._quic.close(ErrorCode.NO_ERROR)
        self.released()

    async def _established(self, deadline: Deadline) -> None:
        if self._quic.connection.early_data_pending:
            async with deadline.phase("connect"):
                await self._quic.established()

    def _fields(
        self, request: Request, *, protocol: bytes | None = None
    ) -> list[tuple[bytes, bytes]]:
        wire = request.wire_headers(HTTPVersion.HTTP_3)
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
        fields = [pseudo[header] for header in self._local_settings.pseudo_header_order]
        if protocol is not None:
            fields.insert(1, (b":protocol", protocol))
        return fields + [(name.encode(), value.encode()) for name, value in wire]

    async def _response_head(
        self, frames: StreamFrames, stream_id: int
    ) -> tuple[int, Headers]:
        self._pending.add(stream_id)
        try:
            return await self._head_frames(frames, stream_id)
        except BaseException as error:
            self._qpack.cancel(stream_id)
            self._flush_decoder()
            if (
                isinstance(error, StreamResetError)
                and error.code == ErrorCode.REQUEST_REJECTED
            ):
                raise StreamRefused(
                    f"HTTP/3 stream {stream_id} was rejected before processing"
                ) from error
            raise
        finally:
            self._pending.discard(stream_id)

    async def _head_frames(
        self, frames: StreamFrames, stream_id: int
    ) -> tuple[int, Headers]:
        while True:
            frame = await frames.next()
            if frame is None:
                raise RemoteDisconnected(
                    f"HTTP/3 stream {stream_id} ended before the response head"
                )
            kind, payload = frame
            if kind == FrameType.HEADERS:
                decoded = await self._decode(payload, stream_id)
                status = next(
                    (value for name, value in decoded if name == ":status"), ""
                )
                if not (status.isascii() and status.isdigit()):
                    raise ProtocolError("HTTP/3 response without a numeric :status")
                if 100 <= int(status) < 200:
                    continue
                return int(status), Headers(
                    [
                        (name, value)
                        for name, value in decoded
                        if not name.startswith(":")
                    ]
                )
            if kind in (
                FrameType.PUSH_PROMISE,
                FrameType.SETTINGS,
                FrameType.GOAWAY,
                FrameType.MAX_PUSH_ID,
                FrameType.CANCEL_PUSH,
            ):
                raise ProtocolError(
                    f"unexpected HTTP/3 frame {FrameType(kind).name} on a request stream"
                )

    async def _body(
        self, frames: StreamFrames, stream_id: int, trailers: Headers
    ) -> AsyncGenerator[bytes]:
        try:
            while (frame := await frames.next()) is not None:
                kind, payload = frame
                if kind == FrameType.DATA:
                    if payload:
                        yield payload
                elif kind == FrameType.HEADERS:
                    for name, value in await self._decode(payload, stream_id):
                        trailers.add(name, value)
                elif kind in (
                    FrameType.PUSH_PROMISE,
                    FrameType.SETTINGS,
                    FrameType.GOAWAY,
                    FrameType.MAX_PUSH_ID,
                    FrameType.CANCEL_PUSH,
                ):
                    raise ProtocolError(
                        f"unexpected HTTP/3 frame {FrameType(kind).name} on a request stream"
                    )
        except BaseException:
            self._quic.reset(stream_id, ErrorCode.REQUEST_CANCELLED)
            self._quic.stop_sending(stream_id, ErrorCode.REQUEST_CANCELLED)
            self._qpack.cancel(stream_id)
            self._flush_decoder()
            raise
        finally:
            self.released()

    async def _decode(self, block: bytes, stream_id: int) -> list[tuple[str, str]]:
        # a block that refers to dynamic table entries still on the encoder stream waits for them
        while (fields := self._qpack.decode(block, stream_id)) is None:
            await self._qpack.wait()
        self._flush_decoder()
        decoded = [
            (name.decode("latin-1"), value.decode("latin-1")) for name, value in fields
        ]
        try:
            Headers(
                [(name, value) for name, value in decoded if not name.startswith(":")]
            )
        except ValueError as error:
            raise ProtocolError(f"malformed header from the server: {error}") from None
        return decoded

    def _flush_decoder(self) -> None:
        instructions = self._qpack.take_instructions()
        if instructions and not self._quic.closed:
            self._quic.send(self._decoder_stream, instructions)

    async def _read_peer_streams(self) -> None:
        while True:
            stream_id = await self._quic.incoming.get()
            reader = asyncio.create_task(self._read_peer_stream(stream_id))
            self._readers.add(reader)
            reader.add_done_callback(self._readers.discard)

    async def _read_peer_stream(self, stream_id: int) -> None:
        if stream_id % 4 != 3:
            self._quic.stop_sending(stream_id, ErrorCode.STREAM_CREATION_ERROR)
            return
        try:
            await self._read_unidirectional(stream_id)
        except ProtocolError as error:
            self._quic.close(ErrorCode.GENERAL_PROTOCOL_ERROR, str(error))
            if not self._settings_received.done():
                self._settings_received.set_exception(error)
        except RemoteDisconnected as error:
            if not self._settings_received.done():
                self._settings_received.set_exception(error)

    async def _read_unidirectional(self, stream_id: int) -> None:
        frames = StreamFrames(self._quic, stream_id, Deadline(Timeout.of(None)))
        kind = await frames.varint()
        match kind:
            case StreamType.CONTROL:
                while (frame := await frames.next()) is not None:
                    frame_type, payload = frame
                    if frame_type == FrameType.SETTINGS:
                        reader = Reader(payload)
                        settings: dict[int, int] = {}
                        while reader.remaining:
                            identifier = reader.varint()
                            settings[identifier] = reader.varint()
                        self._peer_settings = settings
                        if self._memory is not None:
                            self._memory.settings = settings
                        if not self._settings_received.done():
                            self._settings_received.set_result(None)
                    elif frame_type == FrameType.GOAWAY:
                        self._goaway = True
                        first_unprocessed = Reader(payload).varint()
                        for pending in list(self._pending):
                            if pending >= first_unprocessed:
                                self._quic.fail_stream(
                                    pending,
                                    StreamRefused(
                                        f"HTTP/3 stream {pending} was refused by GOAWAY"
                                    ),
                                )
            case StreamType.QPACK_ENCODER:
                # the stream type was read through the frame buffer, which may already hold the first instructions
                self._qpack.feed_encoder(frames.drain())
                self._flush_decoder()
                while piece := await self._quic.receive(stream_id):
                    self._qpack.feed_encoder(piece)
                    self._flush_decoder()
            case StreamType.QPACK_DECODER:
                # our encoder never touches the dynamic table, so the peer's acknowledgements carry nothing to act on
                while await self._quic.receive(stream_id):
                    pass
            case _:
                self._quic.stop_sending(stream_id, ErrorCode.STREAM_CREATION_ERROR)

    @staticmethod
    def _frame(kind: FrameType, payload: bytes) -> bytes:
        return Writer.encode_varint(kind) + Writer.encode_varint(len(payload)) + payload

    @staticmethod
    def _nothing() -> None:
        pass


class Http3StreamTransport:
    def __init__(
        self, quic: QuicClient, stream_id: int, deadline: Deadline, frames: StreamFrames
    ) -> None:
        self._quic = quic
        self._stream_id = stream_id
        self._frames = frames
        self._deadline = deadline
        self._pending = b""
        self._closed = False

    async def read(self, limit: int) -> bytes:
        while not self._pending:
            frame = await self._frames.next()
            if frame is None:
                return b""
            if frame[0] == FrameType.DATA:
                self._pending = frame[1]
        piece, self._pending = self._pending[:limit], self._pending[limit:]
        return piece

    async def write(self, data: bytes) -> None:
        self._quic.send(
            self._stream_id,
            Writer.encode_varint(FrameType.DATA)
            + Writer.encode_varint(len(data))
            + data,
        )

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._quic.send(self._stream_id, b"", end=True)
