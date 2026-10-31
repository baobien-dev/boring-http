import asyncio
import logging
import secrets
from collections.abc import AsyncGenerator, Awaitable, Callable
from enum import IntEnum
from http import HTTPStatus
from time import monotonic

from boring_ssl2 import Library
from ssl2.asynchronous import AsyncTransport
from ssl2.errors import ConfigurationError
from ssl2.fingerprint import PseudoHeader
from ssl2.tracing import Trace

from boring_http.errors import ProtocolError, RemoteDisconnectedError, StreamRefusedError, StreamResetError
from boring_http.headers import Headers
from boring_http.profiles import Http3Profile, Http3Setting, HTTPVersion
from boring_http.qpack import Qpack
from boring_http.quic.protocol import OriginMemory, QuicClient
from boring_http.quic.wire import Reader, Varint, Writer
from boring_http.request import Method, Request
from boring_http.response import ConnectionInfo, Response
from boring_http.timing import Deadline, Phase, Timeout
from boring_http.tracing import Event, Step


class Http3FrameType(IntEnum):
    # RFC 9114 section 7.2 and RFC 9218 section 7.2
    DATA = 0x00
    HEADERS = 0x01
    CANCEL_PUSH = 0x03
    SETTINGS = 0x04
    PUSH_PROMISE = 0x05
    GOAWAY = 0x07
    MAX_PUSH_ID = 0x0D
    PRIORITY_UPDATE_REQUEST = 0xF0700


class StreamType(IntEnum):
    # RFC 9114 section 6.2 and RFC 9204 section 4.2
    CONTROL = 0x00
    PUSH = 0x01
    QPACK_ENCODER = 0x02
    QPACK_DECODER = 0x03


class Http3ErrorCode(IntEnum):
    # RFC 9114 section 8.1 and RFC 9204 section 6
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
    QPACK_DECOMPRESSION_FAILED = 0x200
    QPACK_ENCODER_STREAM_ERROR = 0x201
    QPACK_DECODER_STREAM_ERROR = 0x202


class Grease(IntEnum):
    # RFC 9114 section 7.2.8: identifiers of the form 0x1f * N + 0x21 are reserved for the peer to ignore
    STEP = 0x1F
    OFFSET = 0x21
    SETTING_RANGE = 1 << 16
    VALUE_RANGE = 1 << 20
    FRAME_RANGE = 1 << 32


class Size(IntEnum):
    # how much of a body may wait unsent in its QUIC stream before the next chunk is taken from the caller
    SEND_BUFFER = 1 << 20


class StreamIdBits(IntEnum):
    # RFC 9000 section 2.1: the low two bits of a stream id; a server's unidirectional stream has both set
    MASK = 0x03
    SERVER_UNIDIRECTIONAL = 0x03


class StreamFrames:
    # RFC 9114 section 7.1: the frames of one stream, read as the stream delivers them
    def __init__(self, quic: QuicClient, stream_id: int, deadline: Deadline) -> None:
        self._quic = quic
        self._stream_id = stream_id
        self._deadline = deadline
        self._buffer = bytearray()
        self.ended = False

    async def next(self) -> tuple[int, bytes] | None:
        # the next frame's type and payload, or None once the stream has ended
        kind = await self.varint()
        if kind is None:
            return None
        length = await self.varint()
        if length is None:
            raise ProtocolError("an HTTP/3 frame ended inside its length")
        return kind, await self._exactly(length)

    async def varint(self) -> int | None:
        if not await self._fill(1):
            return None
        length = 1 << (self._buffer[0] >> Varint.LENGTH_SHIFT)
        if not await self._fill(length):
            raise ProtocolError("an HTTP/3 stream ended inside a varint")
        return Reader(await self._exactly(length)).varint()

    def drain(self) -> bytes:
        data = bytes(self._buffer)
        self._buffer.clear()
        return data

    async def _exactly(self, length: int) -> bytes:
        if not await self._fill(length):
            raise ProtocolError("an HTTP/3 stream ended inside a frame")
        data = bytes(self._buffer[:length])
        del self._buffer[:length]
        return data

    async def _fill(self, length: int) -> bool:
        while len(self._buffer) < length:
            if self.ended:
                return False
            async with self._deadline.phase(Phase.READ):
                piece = await self._quic.receive(self._stream_id)
            if not piece:
                self.ended = True
                return len(self._buffer) >= length
            self._buffer += piece
        return True


class Http3Connection:
    logger = logging.getLogger("boring_http")
    # the frames a server never sends on a request stream, RFC 9114 section 7.2
    NOT_ON_REQUEST_STREAMS = frozenset(
        {
            Http3FrameType.PUSH_PROMISE,
            Http3FrameType.SETTINGS,
            Http3FrameType.GOAWAY,
            Http3FrameType.MAX_PUSH_ID,
            Http3FrameType.CANCEL_PUSH,
        }
    )

    def __init__(
        self, quic: QuicClient, profile: Http3Profile, library: Library, memory: OriginMemory | None = None
    ) -> None:
        self._quic = quic
        self._profile = profile
        self._library = library
        self._memory = memory
        self._qpack = Qpack(profile.setting(Http3Setting.QPACK_MAX_TABLE_CAPACITY, 0))
        self._control_stream = -1
        self._decoder_stream = -1
        self._peer_settings: dict[int, int] = {}
        self._goaway = False
        # the request streams still waiting for their response head, which a GOAWAY may refuse
        self._pending: set[int] = set()
        self._readers: set[asyncio.Task[None]] = set()
        self._settings_received: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._info: ConnectionInfo | None = None
        self.closed = False
        self.reused = False
        self.connect_time = 0.0
        self.released: Callable[[], None] = self._nothing

    @property
    def available(self) -> bool:
        return (
            not self.closed and not self._goaway and not self._quic.closed and self._quic.connection.can_open_stream()
        )

    @property
    def shared(self) -> bool:
        return True

    @property
    def info(self) -> ConnectionInfo:
        # the addresses and the handshake do not change for the life of a connection, so this is read once
        if self._info is None:
            self._info = ConnectionInfo.of(
                self._quic.getsockname(), self._quic.getpeername(), self._quic.connection.buffer
            )
        return self._info

    @property
    def connect_protocol(self) -> bool:
        # RFC 9220: the server takes Extended CONNECT, which carries a WebSocket
        return self._peer_settings.get(Http3Setting.ENABLE_CONNECT_PROTOCOL) == 1

    def take(self) -> None:
        pass

    async def start(self) -> None:
        self._control_stream = self._quic.open_stream(bidirectional=False)
        self._quic.send(self._control_stream, Writer.encode_varint(StreamType.CONTROL) + self._settings_frame())
        self._quic.send(self._quic.open_stream(bidirectional=False), Writer.encode_varint(StreamType.QPACK_ENCODER))
        self._decoder_stream = self._quic.open_stream(bidirectional=False)
        self._quic.send(self._decoder_stream, Writer.encode_varint(StreamType.QPACK_DECODER))
        self._readers.add(asyncio.create_task(self._read_peer_streams()))
        if self._quic.connection.early_data_pending and self._memory is not None and self._memory.settings:
            # RFC 9114 section 7.2.4.2: 0-RTT requests run under the settings the server sent last time
            self._peer_settings = dict(self._memory.settings)
            return
        await asyncio.wait({self._settings_received, self._quic.terminated}, return_when=asyncio.FIRST_COMPLETED)
        if not self._settings_received.done():
            terminated = self._quic.terminated.result()
            raise RemoteDisconnectedError(
                f"the QUIC connection ended before the HTTP/3 SETTINGS frame: {terminated.reason or hex(terminated.error)}"
            )
        await self._settings_received

    def _settings_frame(self) -> bytes:
        settings = list(self._profile.settings)
        if self._profile.grease:
            # RFC 9114 section 7.2.4.1: a reserved identifier the peer must ignore, placed at random
            identifier = Grease.STEP * secrets.randbelow(Grease.SETTING_RANGE) + Grease.OFFSET
            settings.insert(secrets.randbelow(len(settings) + 1), (identifier, secrets.randbelow(Grease.VALUE_RANGE)))
        payload = Writer()
        for identifier, value in settings:
            payload.varint(identifier)
            payload.varint(value)
        frame = self.frame(Http3FrameType.SETTINGS, payload.finish())
        if self._profile.grease:
            # RFC 9114 section 7.2.8: an empty frame of a reserved type right after SETTINGS
            frame += self.frame(Grease.STEP * secrets.randbelow(Grease.FRAME_RANGE) + Grease.OFFSET, b"")
        return frame

    async def send(self, request: Request, deadline: Deadline, *, decode: bool, trace: Trace | None) -> Response:
        # RFC 8470 section 5.2: only a safe method goes out before the handshake, since a server may see it twice
        if request.method not in Method or not Method(request.method).safe:
            await self._established(deadline)
        early = self._quic.connection.early_data_pending
        stream_id = self._quic.open_stream()
        started = monotonic()
        with Trace.timing(trace, Step.SEND):
            self._send_head(request, stream_id)
            if request.body is not None:
                await self._send_body(request, stream_id, deadline)
        self.logger.debug(
            "%s method=%s url=%s version=%s stream=%d early=%s",
            Event.REQUEST_SENT,
            request.method,
            request.url,
            HTTPVersion.HTTP_3,
            stream_id,
            early,
        )
        frames = StreamFrames(self._quic, stream_id, deadline)
        with Trace.timing(trace, Step.HEADERS):
            status, headers = await self._response_head(frames, stream_id)
        trailers = Headers()
        if status == HTTPStatus.TOO_EARLY and early and (request.body is None or request.body.replayable):
            # RFC 8470 section 5.2: the server wants this request again once the handshake has finished
            await self._established(deadline)
            async for _ in self._body(frames, stream_id, trailers, trace):
                pass
            return await self.send(request, deadline, decode=decode, trace=trace)
        self.logger.info(
            "%s status=%d version=%s stream=%d seconds=%.3f",
            Event.RESPONSE_HEADERS,
            status,
            HTTPVersion.HTTP_3,
            stream_id,
            monotonic() - started,
        )
        raw = self._body(frames, stream_id, trailers, trace)
        await anext(raw)
        return Response(
            status=status,
            reason="",
            version=HTTPVersion.HTTP_3,
            headers=headers,
            request=request,
            raw=raw,
            trailers=trailers,
            library=self._library,
            decode=decode,
            trace=trace,
        )

    def _send_head(self, request: Request, stream_id: int) -> None:
        priority = request.headers.get("priority")
        if priority is not None:
            # RFC 9218 section 7.2: a request's priority goes on the control stream before its HEADERS
            update = Writer.encode_varint(stream_id) + priority.encode()
            self._quic.send(self._control_stream, self.frame(Http3FrameType.PRIORITY_UPDATE_REQUEST, update))
        block = self._qpack.encode(self._fields(request))
        self._quic.send(stream_id, self.frame(Http3FrameType.HEADERS, block), end=request.body is None)

    async def _send_body(self, request: Request, stream_id: int, deadline: Deadline) -> None:
        if request.body is None:
            return
        # the write limit covers each wait for the stream to drain, not the whole body
        async for chunk in request.body.chunks():
            self._quic.send(stream_id, self.frame(Http3FrameType.DATA, chunk))
            async with deadline.phase(Phase.WRITE):
                await self._quic.drain(stream_id, Size.SEND_BUFFER)
        self._quic.send(stream_id, b"", end=True)

    async def tunnel(self, request: Request, deadline: Deadline) -> tuple[int, Headers, AsyncTransport]:
        # RFC 9220: an Extended CONNECT stream, which carries a WebSocket
        await self._established(deadline)
        stream_id = self._quic.open_stream()
        block = self._qpack.encode(self._fields(request, protocol=b"websocket"))
        self._quic.send(stream_id, self.frame(Http3FrameType.HEADERS, block))
        frames = StreamFrames(self._quic, stream_id, deadline)
        status, headers = await self._response_head(frames, stream_id)
        return status, headers, Http3StreamTransport(self._quic, stream_id, deadline, frames, self.close)

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for reader in self._readers:
            reader.cancel()
        await self._quic.close(Http3ErrorCode.NO_ERROR)
        self.released()

    async def _established(self, deadline: Deadline) -> None:
        if self._quic.connection.early_data_pending:
            async with deadline.phase(Phase.CONNECT):
                await self._quic.established()

    def _fields(self, request: Request, *, protocol: bytes | None = None) -> list[tuple[bytes, bytes]]:
        wire = request.wire_headers(HTTPVersion.HTTP_3)
        authority = request.headers.get("host") or request.url.authority
        pseudo = {
            PseudoHeader.METHOD: (b":method", request.method.encode()),
            PseudoHeader.AUTHORITY: (b":authority", authority.encode()),
            PseudoHeader.SCHEME: (b":scheme", request.url.scheme.http.encode()),
            PseudoHeader.PATH: (b":path", request.url.target.encode()),
        }
        fields = [pseudo[header] for header in self._profile.pseudo_header_order]
        if protocol is not None:
            fields.insert(1, (b":protocol", protocol))
        fields += [(header.name.encode(), header.value.encode()) for header in wire]
        return fields

    async def _response_head(self, frames: StreamFrames, stream_id: int) -> tuple[int, Headers]:
        self._pending.add(stream_id)
        try:
            return await self._head_frames(frames, stream_id)
        except StreamResetError as error:
            self._cancel(stream_id)
            if error.code == Http3ErrorCode.REQUEST_REJECTED:
                raise StreamRefusedError(f"HTTP/3 stream {stream_id} was rejected before processing") from error
            raise
        except BaseException:
            self._cancel(stream_id)
            raise
        finally:
            self._pending.discard(stream_id)

    def _cancel(self, stream_id: int) -> None:
        self._qpack.cancel(stream_id)
        self._flush_decoder()

    async def _head_frames(self, frames: StreamFrames, stream_id: int) -> tuple[int, Headers]:
        # informational answers are skipped; the first final status is the response
        while True:
            frame = await frames.next()
            if frame is None:
                raise RemoteDisconnectedError(f"HTTP/3 stream {stream_id} ended before the response head")
            kind, payload = frame
            if kind in self.NOT_ON_REQUEST_STREAMS:
                raise ProtocolError(f"unexpected HTTP/3 frame {Http3FrameType(kind).name} on a request stream")
            if kind != Http3FrameType.HEADERS:
                continue
            decoded = await self._decode(payload, stream_id)
            status = next((value for name, value in decoded if name == ":status"), "")
            if not (status.isascii() and status.isdigit()):
                raise ProtocolError("an HTTP/3 response without a numeric :status")
            if HTTPStatus.CONTINUE <= int(status) < HTTPStatus.OK:
                continue
            return int(status), Headers([(name, value) for name, value in decoded if not name.startswith(":")])

    async def _body(
        self, frames: StreamFrames, stream_id: int, trailers: Headers, trace: Trace | None
    ) -> AsyncGenerator[bytes]:
        received = 0
        try:
            with Trace.timing(trace, Step.BODY):
                # the connection runs the body to here before handing it out, so a response closed before it is
                # read still reaches the cleanup below
                yield b""
                async for payload in self._data_frames(frames, stream_id, trailers):
                    received += len(payload)
                    yield payload
        except BaseException:
            self._quic.reset(stream_id, Http3ErrorCode.REQUEST_CANCELLED)
            self._quic.stop_sending(stream_id, Http3ErrorCode.REQUEST_CANCELLED)
            self._cancel(stream_id)
            raise
        finally:
            self.released()
        self.logger.info(
            "%s bytes=%d version=%s stream=%d", Event.RESPONSE_DONE, received, HTTPVersion.HTTP_3, stream_id
        )

    async def _data_frames(self, frames: StreamFrames, stream_id: int, trailers: Headers) -> AsyncGenerator[bytes]:
        while (frame := await frames.next()) is not None:
            kind, payload = frame
            if kind in self.NOT_ON_REQUEST_STREAMS:
                raise ProtocolError(f"unexpected HTTP/3 frame {Http3FrameType(kind).name} on a request stream")
            match kind:
                case Http3FrameType.DATA:
                    if payload:
                        yield payload
                case Http3FrameType.HEADERS:
                    for name, value in await self._decode(payload, stream_id):
                        trailers.add(name, value)
                case _:
                    pass

    async def _decode(self, block: bytes, stream_id: int) -> list[tuple[str, str]]:
        # a block that refers to dynamic table entries still on the encoder stream waits for them
        while (fields := self._qpack.decode(block, stream_id)) is None:
            await self._qpack.wait()
        self._flush_decoder()
        decoded = [(name.decode("latin-1"), value.decode("latin-1")) for name, value in fields]
        try:
            Headers([(name, value) for name, value in decoded if not name.startswith(":")])
        except ConfigurationError as error:
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
        if stream_id & StreamIdBits.MASK != StreamIdBits.SERVER_UNIDIRECTIONAL:
            # RFC 9114 section 6.1: a server opens no bidirectional streams
            self._quic.stop_sending(stream_id, Http3ErrorCode.STREAM_CREATION_ERROR)
            return
        try:
            await self._read_unidirectional(stream_id)
        except ProtocolError as error:
            await self._quic.close(Http3ErrorCode.GENERAL_PROTOCOL_ERROR, str(error))
            if not self._settings_received.done():
                self._settings_received.set_exception(error)
        except RemoteDisconnectedError as error:
            if not self._settings_received.done():
                self._settings_received.set_exception(error)

    async def _read_unidirectional(self, stream_id: int) -> None:
        frames = StreamFrames(self._quic, stream_id, Deadline(Timeout.of(None)))
        match await frames.varint():
            case StreamType.CONTROL:
                await self._read_control(frames)
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
                self._quic.stop_sending(stream_id, Http3ErrorCode.STREAM_CREATION_ERROR)

    async def _read_control(self, frames: StreamFrames) -> None:
        while (frame := await frames.next()) is not None:
            kind, payload = frame
            match kind:
                case Http3FrameType.SETTINGS:
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
                case Http3FrameType.GOAWAY:
                    # RFC 9114 section 5.2: requests on streams from this id on were not processed and may be retried
                    self._goaway = True
                    first_unprocessed = Reader(payload).varint()
                    for pending in list(self._pending):
                        if pending >= first_unprocessed:
                            refused = StreamRefusedError(f"HTTP/3 stream {pending} was refused by GOAWAY")
                            self._quic.fail_stream(pending, refused)
                case _:
                    pass

    @staticmethod
    def frame(kind: int, payload: bytes) -> bytes:
        return Writer.encode_varint(kind) + Writer.encode_varint(len(payload)) + payload

    @staticmethod
    def _nothing() -> None:
        pass


class Http3StreamTransport:
    # one HTTP/3 request stream as a transport, for a WebSocket over Extended CONNECT
    def __init__(
        self,
        quic: QuicClient,
        stream_id: int,
        deadline: Deadline,
        frames: StreamFrames,
        close_connection: Callable[[], Awaitable[None]],
    ) -> None:
        self._quic = quic
        self._stream_id = stream_id
        self._deadline = deadline
        self._frames = frames
        self._close_connection = close_connection
        self._pending = b""
        self._closed = False

    async def read(self, limit: int) -> bytes:
        while not self._pending:
            frame = await self._frames.next()
            if frame is None:
                return b""
            kind, payload = frame
            if kind == Http3FrameType.DATA:
                self._pending = payload
        piece, self._pending = self._pending[:limit], self._pending[limit:]
        return piece

    async def write(self, data: bytes) -> None:
        self._quic.send(self._stream_id, Http3Connection.frame(Http3FrameType.DATA, data))
        async with self._deadline.phase(Phase.WRITE):
            await self._quic.drain(self._stream_id, Size.SEND_BUFFER)

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._quic.send(self._stream_id, b"", end=True)
            # the connection was opened for this tunnel alone, so it ends with it
            await self._close_connection()

    def getsockname(self) -> tuple[str | None, int]:
        return self._quic.getsockname()

    def getpeername(self) -> tuple[str | None, int]:
        return self._quic.getpeername()
