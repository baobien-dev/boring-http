import json
from collections.abc import AsyncGenerator, AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from http import HTTPStatus
from time import monotonic, time
from typing import Self, cast, override

from boring_ssl2 import Library
from ssl2.interface import TLSBuffer
from ssl2.registry import CipherSuite, TLSVersion
from ssl2.tracing import Trace
from ssl2.value import Value

from boring_http.codings import ContentDecoder
from boring_http.cookies import Cookie
from boring_http.errors import HTTPError
from boring_http.headers import Headers
from boring_http.profiles import HTTPVersion
from boring_http.request import Request
from boring_http.url import Url


@dataclass(frozen=True, slots=True)
class ConnectionInfo(Value):
    local_address: tuple[str | None, int]
    remote_address: tuple[str | None, int]
    tls_version: TLSVersion | None = None
    cipher: CipherSuite | int | None = None
    peer_chain: tuple[bytes, ...] = ()
    reused: bool = False
    # seconds spent opening the connection: TCP, the proxy and the TLS or QUIC handshake
    connect_time: float = 0.0

    @classmethod
    def of(
        cls, local_address: tuple[str | None, int], remote_address: tuple[str | None, int], buffer: TLSBuffer | None
    ) -> Self:
        # an IPv6 socket address carries flow and scope fields after the host and port
        local, remote = local_address[:2], remote_address[:2]
        if buffer is None:
            return cls(local, remote)
        return cls(local, remote, buffer.negotiated_tls_version, buffer.cipher(), buffer.getpeerchain())


class Response:
    REDIRECTS = frozenset(
        {
            HTTPStatus.MOVED_PERMANENTLY,
            HTTPStatus.FOUND,
            HTTPStatus.SEE_OTHER,
            HTTPStatus.TEMPORARY_REDIRECT,
            HTTPStatus.PERMANENT_REDIRECT,
        }
    )

    def __init__(
        self,
        *,
        status: int,
        reason: str,
        version: HTTPVersion,
        headers: Headers,
        request: Request,
        raw: AsyncGenerator[bytes],
        trailers: Headers,
        library: Library,
        decode: bool,
        trace: Trace | None = None,
    ) -> None:
        self.status = status
        self.reason = reason
        self.version = version
        self.headers = headers
        self.request = request
        self.trailers = trailers
        self.history: tuple[Response, ...] = ()
        self.connection: ConnectionInfo | None = None
        self.trace = trace
        self.started = monotonic()
        self.elapsed = 0.0
        self._raw = raw
        self._library = library
        self._decode = decode
        self._body: bytes | None = None
        self._consumed = False

    @override
    def __repr__(self) -> str:
        return f"<Response {self.status} {self.reason} {self.version} {self.url}>"

    @property
    def url(self) -> Url:
        return self.request.url

    @property
    def ok(self) -> bool:
        return self.status < HTTPStatus.BAD_REQUEST

    @property
    def is_redirect(self) -> bool:
        return self.status in self.REDIRECTS and "location" in self.headers

    @property
    def location(self) -> Url | None:
        location = self.headers.get("location")
        if location is None:
            return None
        try:
            return self.url.join(location)
        except ValueError:
            # a Location that is not a URL is no redirect target, the way an unparseable Date is no date
            return None

    @property
    def content_type(self) -> str | None:
        value = self.headers.get("content-type")
        return None if value is None else value.split(";", 1)[0].strip().lower()

    @property
    def charset(self) -> str | None:
        value = self.headers.get("content-type", "") or ""
        for parameter in value.split(";")[1:]:
            name, _, argument = parameter.strip().partition("=")
            if name.lower() == "charset":
                return argument.strip().strip('"').lower()
        return None

    @property
    def content_length(self) -> int | None:
        value = self.headers.get("content-length")
        return int(value) if value is not None and value.isascii() and value.isdigit() else None

    @property
    def content_encoding(self) -> tuple[str, ...]:
        value = self.headers.get("content-encoding")
        if value is None:
            return ()
        return tuple(coding.strip().lower() for coding in value.split(",") if coding.strip())

    @property
    def cookies(self) -> tuple[Cookie, ...]:
        parsed = (
            Cookie.parse(value, self.url.host, self.url.path or "/") for value in self.headers.get_all("set-cookie")
        )
        return tuple(cookie for cookie in parsed if cookie is not None)

    @property
    def retry_after(self) -> float | None:
        value = self.headers.get("retry-after")
        if value is None:
            return None
        if value.isascii() and value.isdigit():
            return float(value)
        date = self._date(value)
        return None if date is None else max(0.0, date.timestamp() - time())

    @property
    def etag(self) -> str | None:
        return self.headers.get("etag")

    @property
    def last_modified(self) -> datetime | None:
        return self._date(self.headers.get("last-modified"))

    @property
    def date(self) -> datetime | None:
        return self._date(self.headers.get("date"))

    @property
    def body(self) -> bytes:
        if self._body is None:
            raise HTTPError("the body has not been read; await response.read() or iterate aiter_bytes()")
        return self._body

    @property
    def text(self) -> str:
        return self.body.decode(self.charset or "utf-8", "replace")

    def json(self) -> object:
        return cast("object", json.loads(self.body))

    def raise_for_status(self) -> None:
        if self.status >= HTTPStatus.BAD_REQUEST:
            raise HTTPStatusError(self)

    async def read(self) -> bytes:
        if self._body is None:
            self._body = b"".join([chunk async for chunk in self.aiter_bytes()])
            self.elapsed = monotonic() - self.started
        return self._body

    async def aiter_raw(self) -> AsyncIterator[bytes]:
        if self._consumed:
            raise HTTPError("the body stream was already consumed")
        self._consumed = True
        async for chunk in self._raw:
            yield chunk

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        codings = self.content_encoding if self._decode else ()
        if not codings:
            async for chunk in self.aiter_raw():
                if chunk:
                    yield chunk
            return
        decoder = ContentDecoder(codings, self._library)
        async for chunk in self.aiter_raw():
            decoded = decoder.decode(chunk)
            if decoded:
                yield decoded
        tail = decoder.finish()
        if tail:
            yield tail

    async def close(self) -> None:
        await self._raw.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    @staticmethod
    def _date(value: str | None) -> datetime | None:
        if value is None:
            return None
        try:
            return parsedate_to_datetime(value)
        except ValueError, TypeError:
            return None


class HTTPStatusError(HTTPError):
    def __init__(self, response: Response) -> None:
        super().__init__(f"{response.status} {response.reason} for {response.url}")
        self.response = response
