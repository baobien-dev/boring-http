import logging
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass
from enum import StrEnum
from http import HTTPStatus
from time import monotonic

from boring_ssl2 import Library
from ssl2.asynchronous import AsyncTransport, TLSStream
from ssl2.tracing import Trace
from ssl2.value import Value

from boring_http.errors import ProtocolError, RemoteDisconnectedError
from boring_http.headers import Headers
from boring_http.profiles import Http1Profile, HTTPVersion
from boring_http.request import Method, Request
from boring_http.response import ConnectionInfo, Response
from boring_http.timing import Deadline, Phase
from boring_http.tracing import Event, Step


class Version(StrEnum):
    HTTP_1_1 = "HTTP/1.1"
    HTTP_1_0 = "HTTP/1.0"


class Token(StrEnum):
    CLOSE = "close"
    KEEP_ALIVE = "keep-alive"
    CHUNKED = "chunked"


class Mark:
    LINE = b"\r\n"
    HEAD = b"\r\n\r\n"
    LAST_CHUNK = b"0\r\n\r\n"


@dataclass(frozen=True, slots=True)
class Framing(Value):
    # how the body ends: chunked, after length bytes, or when the connection closes
    chunked: bool
    length: int | None


class Http1Connection:
    logger = logging.getLogger("boring_http")

    def __init__(
        self,
        transport: AsyncTransport,
        profile: Http1Profile,
        library: Library,
        *,
        leftover: bytes = b"",
        absolute_form: bool = False,
        proxy_authorization: str | None = None,
    ) -> None:
        self._transport = transport
        self._profile = profile
        self._library = library
        self._buffer = bytearray(leftover)
        # requests through a plain HTTP proxy name the whole URL and carry the proxy's credentials
        self._absolute_form = absolute_form
        self._proxy_authorization = proxy_authorization
        self._keep_alive = True
        self.idle = True
        self.closed = False
        self.reused = False
        self.connect_time = 0.0
        self.released: Callable[[], None] = self._nothing

    @property
    def available(self) -> bool:
        return self.idle and not self.closed

    @property
    def shared(self) -> bool:
        return False

    @property
    def info(self) -> ConnectionInfo:
        transport = self._transport
        return ConnectionInfo.of(
            transport.getsockname(),
            transport.getpeername(),
            transport.buffer if isinstance(transport, TLSStream) else None,
        )

    def take(self) -> None:
        self.idle = False

    async def send(self, request: Request, deadline: Deadline, *, decode: bool, trace: Trace | None) -> Response:
        self.idle = False
        headers = request.wire_headers(HTTPVersion.HTTP_1, self._profile)
        if self._proxy_authorization is not None and "proxy-authorization" not in headers:
            headers.add("Proxy-Authorization", self._proxy_authorization)
        target = request.url.origin + request.url.target if self._absolute_form else request.url.target
        lines = [f"{request.method} {target} {Version.HTTP_1_1}", *(header.text for header in headers)]
        started = monotonic()
        try:
            with Trace.timing(trace, Step.SEND):
                async with deadline.phase(Phase.WRITE):
                    await self._transport.write(Mark.LINE.join(line.encode() for line in lines) + Mark.HEAD)
                if request.body is not None:
                    chunked = (headers.get("transfer-encoding") or "").lower() == Token.CHUNKED
                    await self._write_body(request, deadline, chunked=chunked)
            self.logger.debug(
                "%s method=%s url=%s version=%s", Event.REQUEST_SENT, request.method, request.url, HTTPVersion.HTTP_1
            )
            with Trace.timing(trace, Step.HEADERS):
                status, reason, response_headers, old = await self._read_head(deadline)
        except BaseException:
            await self.close()
            raise
        tokens = {
            token.strip().lower()
            for token in (headers.get("connection", "") or "", response_headers.get("connection", "") or "")
            for token in token.split(",")
        }
        self._keep_alive = Token.CLOSE not in tokens and (not old or Token.KEEP_ALIVE in tokens)
        framing = self._framing(request.method, status, response_headers)
        trailers = Headers()
        self.logger.info(
            "%s status=%d version=%s seconds=%.3f",
            Event.RESPONSE_HEADERS,
            status,
            HTTPVersion.HTTP_1,
            monotonic() - started,
        )
        return Response(
            status=status,
            reason=reason,
            version=HTTPVersion.HTTP_1,
            headers=response_headers,
            request=request,
            raw=self._body(framing, trailers, deadline, trace),
            trailers=trailers,
            library=self._library,
            decode=decode,
            trace=trace,
        )

    def detach(self) -> tuple[AsyncTransport, bytes]:
        # the transport leaves with what was read past the response head, for a WebSocket to carry on
        self.closed = True
        self.released()
        return self._transport, bytes(self._buffer)

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            await self._transport.close()
            self.released()

    async def _write_body(self, request: Request, deadline: Deadline, *, chunked: bool) -> None:
        if request.body is None:
            return
        # the write limit covers each wait for the connection to take a chunk, not the whole body
        async for chunk in request.body.chunks():
            async with deadline.phase(Phase.WRITE):
                await self._transport.write(f"{len(chunk):x}\r\n".encode() + chunk + Mark.LINE if chunked else chunk)
        if chunked:
            async with deadline.phase(Phase.WRITE):
                await self._transport.write(Mark.LAST_CHUNK)

    async def _read_head(self, deadline: Deadline) -> tuple[int, str, Headers, bool]:
        # informational answers other than 101 are skipped; the first final status is the response
        while True:
            head = (await self._read_until(Mark.HEAD, self._profile.head_limit, deadline)).decode("latin-1")
            status_line, *lines = head.split("\r\n")
            version, _, rest = status_line.partition(" ")
            code, _, reason = rest.partition(" ")
            if version not in (Version.HTTP_1_1, Version.HTTP_1_0) or not (code.isascii() and code.isdigit()):
                raise ProtocolError(f"malformed status line {status_line!r}")
            headers = Headers()
            for line in lines:
                name, separator, value = line.partition(":")
                if not separator or line[:1] in (" ", "\t"):
                    raise ProtocolError(f"malformed header line {line!r}")
                try:
                    headers.add(name.strip(), value)
                except ValueError as error:
                    raise ProtocolError(str(error)) from None
            status = int(code)
            if HTTPStatus.CONTINUE <= status < HTTPStatus.OK and status != HTTPStatus.SWITCHING_PROTOCOLS:
                continue
            return status, reason, headers, version == Version.HTTP_1_0

    @staticmethod
    def _framing(method: str, status: int, headers: Headers) -> Framing:
        # RFC 9112 section 6.3
        if method == Method.HEAD or status in (
            HTTPStatus.SWITCHING_PROTOCOLS,
            HTTPStatus.NO_CONTENT,
            HTTPStatus.NOT_MODIFIED,
        ):
            return Framing(chunked=False, length=0)
        encoding = headers.get("transfer-encoding")
        if encoding is not None:
            return Framing(chunked=encoding.split(",")[-1].strip().lower() == Token.CHUNKED, length=None)
        length = headers.get("content-length")
        if length is None:
            return Framing(chunked=False, length=None)
        # str.isdigit accepts superscripts and other Unicode digits that int rejects
        if not (length.isascii() and length.isdigit()):
            raise ProtocolError(f"malformed Content-Length {length!r}")
        return Framing(chunked=False, length=int(length))

    async def _body(
        self, framing: Framing, trailers: Headers, deadline: Deadline, trace: Trace | None
    ) -> AsyncGenerator[bytes]:
        received = 0
        try:
            with Trace.timing(trace, Step.BODY):
                async for chunk in self._pieces(framing, trailers, deadline):
                    received += len(chunk)
                    yield chunk
        except BaseException:
            await self.close()
            raise
        self.logger.info("%s bytes=%d version=%s", Event.RESPONSE_DONE, received, HTTPVersion.HTTP_1)
        if self._keep_alive:
            self.idle = True
            self.released()
        else:
            await self.close()

    async def _pieces(self, framing: Framing, trailers: Headers, deadline: Deadline) -> AsyncGenerator[bytes]:
        if framing.chunked:
            async for chunk in self._chunked(trailers, deadline):
                yield chunk
        elif framing.length is None:
            # no length and no chunks: the body ends with the connection
            self._keep_alive = False
            while piece := await self._read_some(self._profile.read_size, deadline):
                yield piece
        else:
            remaining = framing.length
            while remaining:
                piece = await self._read_some(remaining, deadline)
                if not piece:
                    raise ProtocolError(f"the connection closed with {remaining} body bytes missing")
                remaining -= len(piece)
                yield piece

    async def _chunked(self, trailers: Headers, deadline: Deadline) -> AsyncGenerator[bytes]:
        while True:
            line = await self._read_line(deadline)
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                raise ProtocolError(f"malformed chunk size {line!r}") from None
            if size == 0:
                break
            remaining = size
            while remaining:
                piece = await self._read_some(remaining, deadline)
                if not piece:
                    raise ProtocolError(f"the connection closed with {remaining} chunk bytes missing")
                remaining -= len(piece)
                yield piece
            if await self._read_line(deadline):
                raise ProtocolError("chunk data not followed by CRLF")
        while line := await self._read_line(deadline):
            name, separator, value = line.decode("latin-1").partition(":")
            if not separator:
                raise ProtocolError(f"malformed trailer line {line!r}")
            try:
                trailers.add(name.strip(), value)
            except ValueError as error:
                raise ProtocolError(str(error)) from None

    async def _read_some(self, limit: int, deadline: Deadline) -> bytes:
        if not self._buffer:
            async with deadline.phase(Phase.READ):
                return await self._transport.read(min(limit, self._profile.read_size))
        piece = bytes(self._buffer[:limit])
        del self._buffer[:limit]
        return piece

    async def _read_until(self, terminator: bytes, limit: int, deadline: Deadline) -> bytes:
        while (end := self._buffer.find(terminator)) < 0:
            if len(self._buffer) > limit:
                raise ProtocolError(f"the response head exceeds {limit} bytes")
            async with deadline.phase(Phase.READ):
                piece = await self._transport.read(self._profile.read_size)
            if not piece:
                if self._buffer:
                    raise ProtocolError("the connection closed in the middle of the response head")
                raise RemoteDisconnectedError("the server closed the connection before responding")
            self._buffer += piece
        head = bytes(self._buffer[:end])
        del self._buffer[: end + len(terminator)]
        return head

    async def _read_line(self, deadline: Deadline) -> bytes:
        return await self._read_until(Mark.LINE, self._profile.line_limit, deadline)

    @staticmethod
    def _nothing() -> None:
        pass
