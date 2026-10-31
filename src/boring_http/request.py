import json
import secrets
from collections.abc import AsyncIterable, AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import ClassVar, Self
from urllib.parse import urlencode

from ssl2.errors import ConfigurationError
from ssl2.value import Value

from boring_http.headers import Headers
from boring_http.profiles import Http1Profile, HTTPVersion
from boring_http.url import Url

type FormFields = Mapping[str, str] | Sequence[tuple[str, str]]
type FileField = bytes | str | tuple[str, bytes | str] | tuple[str, bytes | str, str]


class Method(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"

    @property
    def carries_body(self) -> bool:
        # the methods a Content-Length of zero is sent for when there is no body at all
        return self in (Method.POST, Method.PUT, Method.PATCH)

    @property
    def safe(self) -> bool:
        # RFC 9110 section 9.2.1; RFC 8470 section 5.2 lets these go out in 0-RTT, since a server may see them twice
        return self in (Method.GET, Method.HEAD, Method.OPTIONS)


class ContentType(StrEnum):
    JSON = "application/json"
    FORM = "application/x-www-form-urlencoded"
    OCTETS = "application/octet-stream"
    MULTIPART = "multipart/form-data"


class Size(IntEnum):
    BOUNDARY_RANDOM_BYTES = 16


class Body:
    # bytes known up front, or a stream read once as it is sent
    def __init__(
        self, data: bytes | None = None, stream: AsyncIterable[bytes] | None = None, content_type: str | None = None
    ) -> None:
        self.data = data
        self.stream = stream
        self.content_type = content_type

    @classmethod
    def json(cls, value: object) -> Self:
        return cls(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode(), content_type=ContentType.JSON)

    @classmethod
    def form(cls, fields: FormFields) -> Self:
        pairs = fields.items() if isinstance(fields, Mapping) else fields
        return cls(urlencode(list(pairs)).encode(), content_type=ContentType.FORM)

    @classmethod
    def content(cls, value: bytes | str | AsyncIterable[bytes]) -> Self:
        match value:
            case bytes():
                return cls(value)
            case str():
                return cls(value.encode())
            case _:
                return cls(stream=value)

    @classmethod
    def multipart(cls, fields: FormFields | None, files: Mapping[str, FileField]) -> Self:
        boundary = secrets.token_hex(Size.BOUNDARY_RANDOM_BYTES)
        parts: list[bytes] = []
        pairs = fields.items() if isinstance(fields, Mapping) else fields or ()
        for name, value in pairs:
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
        for name, field in files.items():
            match field:
                case (filename, content, content_type):
                    pass
                case (filename, content):
                    content_type = ContentType.OCTETS
                case _:
                    filename, content, content_type = name, field, ContentType.OCTETS
            head = (
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                f"Content-Type: {content_type}\r\n\r\n"
            )
            parts.append(head.encode() + (content.encode() if isinstance(content, str) else content) + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        return cls(b"".join(parts), content_type=f"{ContentType.MULTIPART}; boundary={boundary}")

    @property
    def length(self) -> int | None:
        return None if self.data is None else len(self.data)

    @property
    def replayable(self) -> bool:
        return self.data is not None

    async def chunks(self) -> AsyncIterator[bytes]:
        if self.data is not None:
            if self.data:
                yield self.data
        elif self.stream is not None:
            async for chunk in self.stream:
                yield chunk


@dataclass(frozen=True, slots=True)
class Request(Value):
    method: str
    url: Url
    headers: Headers
    body: Body | None = None

    # RFC 9113 section 8.2.2: fields about the connection do not travel in HTTP/2 or HTTP/3
    CONNECTION_SPECIFIC: ClassVar[frozenset[str]] = frozenset(
        {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host"}
    )
    TE: ClassVar[str] = "te"
    TRAILERS: ClassVar[str] = "trailers"

    def __post_init__(self) -> None:
        if not self.method or not self.method.isascii() or " " in self.method:
            raise ConfigurationError(f"{self.method!r} is not an HTTP method")

    def wire_headers(self, version: HTTPVersion, profile: Http1Profile | None = None) -> Headers:
        # the fields as this version sends them: Host and framing for HTTP/1.1, lowercase names without the
        # connection-specific ones for HTTP/2 and HTTP/3
        if version is HTTPVersion.HTTP_1:
            return self._http1_headers(profile or Http1Profile())
        wire = Headers()
        for header in self.headers:
            lowered = header.lowered
            if lowered in self.CONNECTION_SPECIFIC or (lowered == self.TE and header.value.lower() != self.TRAILERS):
                continue
            wire.add(lowered, header.value)
        if self.body is not None and self.body.length is not None and "content-length" not in wire:
            wire.add("content-length", str(self.body.length))
        return wire

    def _http1_headers(self, profile: Http1Profile) -> Headers:
        wire = self.headers.copy()
        if "host" not in wire:
            if profile.host_first:
                wire.insert(0, "Host", self.url.authority)
            else:
                wire.add("Host", self.url.authority)
        if "content-length" not in wire and "transfer-encoding" not in wire:
            if self.body is None:
                if self.method in Method and Method(self.method).carries_body:
                    wire.add("Content-Length", "0")
            elif self.body.length is None:
                wire.add("Transfer-Encoding", "chunked")
            else:
                wire.add("Content-Length", str(self.body.length))
        return wire
