from collections.abc import AsyncGenerator, Callable
from typing import Final, final

from ssl2 import AsyncTransport

from boring_http.errors import ProtocolError, RemoteDisconnected
from boring_http.message import Headers, HTTPVersion, Request, Response
from boring_http.timing import Deadline

READ_SIZE: Final = 65536
HEAD_LIMIT: Final = 65536
LINE_LIMIT: Final = 8192


@final
class Http1Connection:
    def __init__(
        self,
        transport: AsyncTransport,
        *,
        leftover: bytes = b"",
        absolute_form: bool = False,
        proxy_authorization: str | None = None,
    ) -> None:
        self._transport = transport
        self._buffer = bytearray(leftover)
        self._absolute_form = absolute_form
        self._proxy_authorization = proxy_authorization
        self._keep_alive = True
        self.idle = True
        self.closed = False
        self.reused = False
        self.released: Callable[[], None] = self._nothing

    @property
    def available(self) -> bool:
        return self.idle and not self.closed

    @property
    def shared(self) -> bool:
        return False

    def take(self) -> None:
        self.idle = False

    async def send(
        self, request: Request, deadline: Deadline, *, decode: bool
    ) -> Response:
        self.idle = False
        headers = request.wire_headers(HTTPVersion.HTTP_1)
        if (
            self._proxy_authorization is not None
            and "proxy-authorization" not in headers
        ):
            headers.add("Proxy-Authorization", self._proxy_authorization)
        target = (
            request.url.origin + request.url.target
            if self._absolute_form
            else request.url.target
        )
        lines = [
            f"{request.method} {target} HTTP/1.1",
            *(f"{name}: {value}" for name, value in headers),
        ]
        try:
            async with deadline.phase("write"):
                await self._transport.write("\r\n".join(lines).encode() + b"\r\n\r\n")
                if request.body is not None:
                    await self._write_body(
                        request,
                        headers.get("transfer-encoding", "").lower() == "chunked",
                    )
            status, reason, response_headers, old = await self._read_head(deadline)
        except BaseException:
            await self.close()
            raise
        tokens = {
            token.strip().lower()
            for token in (
                headers.get("connection", "")
                + ","
                + response_headers.get("connection", "")
            ).split(",")
        }
        self._keep_alive = "close" not in tokens and (not old or "keep-alive" in tokens)
        chunked, length = self._framing(request.method, status, response_headers)
        trailers = Headers()
        body = self._body(chunked, length, trailers, deadline)
        return Response(
            status=status,
            reason=reason,
            version=HTTPVersion.HTTP_1,
            headers=response_headers,
            request=request,
            raw=body,
            trailers=trailers,
            decode=decode,
        )

    def detach(self) -> tuple[AsyncTransport, bytes]:
        self.closed = True
        self.released()
        return self._transport, bytes(self._buffer)

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            await self._transport.close()
            self.released()

    async def _write_body(self, request: Request, chunked: bool) -> None:
        if request.body is None:
            return
        async for chunk in request.body.chunks():
            if chunked:
                await self._transport.write(
                    f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
                )
            else:
                await self._transport.write(chunk)
        if chunked:
            await self._transport.write(b"0\r\n\r\n")

    async def _read_head(self, deadline: Deadline) -> tuple[int, str, Headers, bool]:
        while True:
            head = (await self._read_until(b"\r\n\r\n", HEAD_LIMIT, deadline)).decode(
                "latin-1"
            )
            status_line, *lines = head.split("\r\n")
            version, _, rest = status_line.partition(" ")
            code, _, reason = rest.partition(" ")
            if (
                version not in ("HTTP/1.1", "HTTP/1.0")
                or len(code) != 3
                or not (code.isascii() and code.isdigit())
            ):
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
            if 100 <= status < 200 and status != 101:
                continue
            return status, reason, headers, version == "HTTP/1.0"

    @staticmethod
    def _framing(method: str, status: int, headers: Headers) -> tuple[bool, int | None]:
        if method == "HEAD" or status in (101, 204, 304):
            return False, 0
        encoding = headers.get("transfer-encoding")
        if encoding is not None:
            return encoding.split(",")[-1].strip().lower() == "chunked", None
        length = headers.get("content-length")
        if length is None:
            return False, None
        # str.isdigit accepts superscripts and other Unicode digits that int rejects
        if not (length.isascii() and length.isdigit()):
            raise ProtocolError(f"malformed Content-Length {length!r}")
        return False, int(length)

    async def _body(
        self, chunked: bool, length: int | None, trailers: Headers, deadline: Deadline
    ) -> AsyncGenerator[bytes]:
        try:
            if chunked:
                async for chunk in self._chunked(trailers, deadline):
                    yield chunk
            elif length is None:
                self._keep_alive = False
                while piece := await self._read_some(READ_SIZE, deadline):
                    yield piece
            else:
                async for piece in self._exactly(length, deadline):
                    yield piece
        except BaseException:
            await self.close()
            raise
        if self._keep_alive:
            self.idle = True
            self.released()
        else:
            await self.close()

    async def _chunked(
        self, trailers: Headers, deadline: Deadline
    ) -> AsyncGenerator[bytes]:
        while True:
            line = await self._read_line(deadline)
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                raise ProtocolError(f"malformed chunk size {line!r}") from None
            if size == 0:
                break
            async for piece in self._exactly(size, deadline):
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

    async def _exactly(self, length: int, deadline: Deadline) -> AsyncGenerator[bytes]:
        remaining = length
        while remaining:
            piece = await self._read_some(remaining, deadline)
            if not piece:
                raise ProtocolError(
                    f"the connection closed with {remaining} body bytes missing"
                )
            remaining -= len(piece)
            yield piece

    async def _read_some(self, limit: int, deadline: Deadline) -> bytes:
        if not self._buffer:
            async with deadline.phase("read"):
                return await self._transport.read(min(limit, READ_SIZE))
        piece = bytes(self._buffer[:limit])
        del self._buffer[:limit]
        return piece

    async def _read_until(
        self, terminator: bytes, limit: int, deadline: Deadline
    ) -> bytes:
        while (end := self._buffer.find(terminator)) < 0:
            if len(self._buffer) > limit:
                raise ProtocolError(f"the response head exceeds {limit} bytes")
            async with deadline.phase("read"):
                piece = await self._transport.read(READ_SIZE)
            if not piece:
                if self._buffer:
                    raise ProtocolError(
                        "the connection closed in the middle of the response head"
                    )
                raise RemoteDisconnected(
                    "the server closed the connection before responding"
                )
            self._buffer += piece
        head = bytes(self._buffer[:end])
        del self._buffer[: end + len(terminator)]
        return head

    async def _read_line(self, deadline: Deadline) -> bytes:
        return await self._read_until(b"\r\n", LINE_LIMIT, deadline)

    @staticmethod
    def _nothing() -> None:
        pass
