import json
import re
import secrets
from collections.abc import (
    AsyncGenerator,
    AsyncIterable,
    AsyncIterator,
    Iterator,
    Mapping,
    Sequence,
)
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from enum import StrEnum
from functools import lru_cache
from time import monotonic, time
from typing import Self, cast, overload, override
from urllib.parse import quote, urlencode, urljoin, urlsplit

from ssl2 import CipherSuite, TLSBuffer, TLSVersion

from boring_http.codings import ContentDecoder
from boring_http.cookies import Cookie
from boring_http.errors import HTTPError

TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
PATH_SAFE = "/%:@!$&'()*+,;=~-._"
QUERY_SAFE = PATH_SAFE + "?"
CONNECTION_SPECIFIC = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "host",
    }
)
BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
DEFAULT_PORTS = {"http": 80, "ws": 80, "https": 443, "wss": 443}

type HeaderItems = Mapping[str, str] | Sequence[tuple[str, str]] | Headers
type ParamValue = str | int | float | bool | None
type Params = Mapping[str, ParamValue] | Sequence[tuple[str, ParamValue]]
type FormFields = Mapping[str, str] | Sequence[tuple[str, str]]
type FileField = bytes | str | tuple[str, bytes | str] | tuple[str, bytes | str, str]


class HTTPVersion(StrEnum):
    HTTP_1 = "http/1.1"
    HTTP_2 = "h2"
    HTTP_3 = "h3"

    @classmethod
    @override
    def _missing_(cls, value: object) -> HTTPVersion | None:
        spelled = str(value).lower().removeprefix("http/")
        return {
            "h1": cls.HTTP_1,
            "1.1": cls.HTTP_1,
            "1": cls.HTTP_1,
            "2": cls.HTTP_2,
            "3": cls.HTTP_3,
        }.get(spelled)


class Headers:
    def __init__(self, items: HeaderItems | None = None) -> None:
        self._items: list[tuple[str, str]] = []
        self._lowered: list[str] = []
        pairs = (
            list(items.items())
            if isinstance(items, Mapping)
            else []
            if items is None
            else list(items)
        )
        for name, value in pairs:
            self.add(name, value)

    @overload
    def __getitem__(self, key: int) -> tuple[str, str]: ...

    @overload
    def __getitem__(self, key: str) -> str: ...

    def __getitem__(self, key: int | str) -> tuple[str, str] | str:
        if isinstance(key, int):
            return self._items[key]
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __contains__(self, name: str) -> bool:
        return self._index(name) is not None

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    @override
    def __eq__(self, other: object) -> bool:
        return isinstance(other, Headers) and other._items == self._items

    @override
    def __repr__(self) -> str:
        return f"Headers({self._items!r})"

    @overload
    def get(self, name: str) -> str | None: ...

    @overload
    def get(self, name: str, default: str) -> str: ...

    def get(self, name: str, default: str | None = None) -> str | None:
        index = self._index(name)
        return default if index is None else self._items[index][1]

    def get_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [
            value
            for (_, value), key in zip(self._items, self._lowered, strict=True)
            if key == lowered
        ]

    def add(self, name: str, value: str) -> None:
        self._items.append(self._checked(name, value))
        self._lowered.append(name.lower())

    def set(self, name: str, value: str) -> None:
        index = self._index(name)
        if index is None:
            self.add(name, value)
        else:
            self._items[index] = self._checked(name, value)
            self._lowered[index] = name.lower()

    def insert(self, index: int, name: str, value: str) -> None:
        self._items.insert(index, self._checked(name, value))
        self._lowered.insert(index, name.lower())

    def remove(self, name: str) -> None:
        lowered = name.lower()
        self._items = [
            pair
            for pair, key in zip(self._items, self._lowered, strict=True)
            if key != lowered
        ]
        self._lowered = [key for key in self._lowered if key != lowered]

    def copy(self) -> Self:
        # the items passed the checks when they came in, so a copy does not run them again
        copied = type(self)()
        copied._items = list(self._items)
        copied._lowered = list(self._lowered)
        return copied

    def merged(self, other: Self) -> Self:
        result = self.copy()
        for lowered in dict.fromkeys(name.lower() for name, _ in other):
            position = result._index(lowered)
            result.remove(lowered)
            replacements = [pair for pair in other if pair[0].lower() == lowered]
            for offset, (name, value) in enumerate(replacements):
                if position is None:
                    result.add(name, value)
                else:
                    result.insert(position + offset, name, value)
        return result

    def _index(self, name: str) -> int | None:
        lowered = name.lower()
        return self._lowered.index(lowered) if lowered in self._lowered else None

    @staticmethod
    def _checked(name: str, value: str) -> tuple[str, str]:
        if not TOKEN.fullmatch(name):
            raise ValueError(f"invalid header name {name!r}")
        value = value.strip()
        if "\r" in value or "\n" in value or "\0" in value:
            raise ValueError(f"invalid header value for {name}")
        return name, value


@dataclass(frozen=True, slots=True)
class URL:
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str
    username: str | None
    password: str | None

    @staticmethod
    @lru_cache(maxsize=512)
    def parse(text: str) -> URL:
        parts = urlsplit(text)
        scheme = parts.scheme.lower()
        if scheme not in DEFAULT_PORTS:
            raise ValueError(f"unsupported URL scheme {parts.scheme!r} in {text!r}")
        if not parts.hostname:
            raise ValueError(f"URL without a host: {text!r}")
        host = parts.hostname.encode("idna").decode("ascii")
        return URL(
            scheme,
            host,
            parts.port,
            quote(parts.path, PATH_SAFE),
            quote(parts.query, QUERY_SAFE),
            parts.fragment,
            parts.username,
            parts.password,
        )

    @property
    def default_port(self) -> int:
        return DEFAULT_PORTS[self.scheme]

    @property
    def secure(self) -> bool:
        return self.scheme in ("https", "wss")

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port or self.default_port

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return (
            host
            if self.port is None or self.port == self.default_port
            else f"{host}:{self.port}"
        )

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.authority}"

    @property
    def target(self) -> str:
        return (self.path or "/") + (f"?{self.query}" if self.query else "")

    @property
    def text(self) -> str:
        return f"{self.origin}{self.target}" + (
            f"#{self.fragment}" if self.fragment else ""
        )

    @override
    def __str__(self) -> str:
        return self.text

    def join(self, reference: str) -> URL:
        return URL.parse(urljoin(self.text, reference))

    def with_params(self, params: Params) -> URL:
        pairs = params.items() if isinstance(params, Mapping) else params
        rendered = [
            (name, self._param(value)) for name, value in pairs if value is not None
        ]
        query = "&".join(part for part in (self.query, urlencode(rendered)) if part)
        return URL(
            self.scheme,
            self.host,
            self.port,
            self.path,
            query,
            self.fragment,
            self.username,
            self.password,
        )

    @staticmethod
    def _param(value: str | float | bool) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)


class Body:
    def __init__(
        self,
        data: bytes | None = None,
        stream: AsyncIterable[bytes] | None = None,
        content_type: str | None = None,
    ) -> None:
        self.data = data
        self.stream = stream
        self.content_type = content_type

    @classmethod
    def json(cls, value: object) -> Self:
        return cls(
            json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode(),
            content_type="application/json",
        )

    @classmethod
    def form(cls, fields: FormFields) -> Self:
        pairs = fields.items() if isinstance(fields, Mapping) else fields
        return cls(
            urlencode(list(pairs)).encode(),
            content_type="application/x-www-form-urlencoded",
        )

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
    def multipart(
        cls, fields: FormFields | None, files: Mapping[str, FileField]
    ) -> Self:
        boundary = secrets.token_hex(16)
        parts: list[bytes] = []
        pairs = fields.items() if isinstance(fields, Mapping) else fields or ()
        for name, value in pairs:
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
            )
        for name, field in files.items():
            match field:
                case (filename, content, content_type):
                    pass
                case (filename, content):
                    content_type = "application/octet-stream"
                case _:
                    filename, content, content_type = (
                        name,
                        field,
                        "application/octet-stream",
                    )
            head = f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n'
            parts.append(
                head.encode()
                + (content.encode() if isinstance(content, str) else content)
                + b"\r\n"
            )
        parts.append(f"--{boundary}--\r\n".encode())
        return cls(
            b"".join(parts), content_type=f"multipart/form-data; boundary={boundary}"
        )

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
class Request:
    method: str
    url: URL
    headers: Headers
    body: Body | None = None

    def wire_headers(self, version: HTTPVersion) -> Headers:
        if version is HTTPVersion.HTTP_1:
            wire = self.headers.copy()
            if "host" not in wire:
                wire.insert(0, "Host", self.url.authority)
            if "content-length" not in wire and "transfer-encoding" not in wire:
                if self.body is None:
                    if self.method in BODY_METHODS:
                        wire.add("Content-Length", "0")
                elif self.body.length is None:
                    wire.add("Transfer-Encoding", "chunked")
                else:
                    wire.add("Content-Length", str(self.body.length))
            return wire
        wire = Headers()
        for name, value in self.headers:
            lowered = name.lower()
            if lowered in CONNECTION_SPECIFIC or (
                lowered == "te" and value.lower() != "trailers"
            ):
                continue
            wire.add(lowered, value)
        if (
            self.body is not None
            and self.body.length is not None
            and "content-length" not in wire
        ):
            wire.add("content-length", str(self.body.length))
        return wire


@dataclass(frozen=True, slots=True)
class ConnectionInfo:
    local_address: tuple[str | None, int]
    remote_address: tuple[str | None, int]
    tls_version: TLSVersion | None = None
    cipher: CipherSuite | int | None = None
    peer_chain: tuple[bytes, ...] = ()
    reused: bool = False

    @classmethod
    def of(
        cls,
        local_address: tuple[str | None, int],
        remote_address: tuple[str | None, int],
        buffer: TLSBuffer | None,
    ) -> Self:
        # an IPv6 socket address carries flow and scope fields after the host and port
        local, remote = local_address[:2], remote_address[:2]
        if buffer is None:
            return cls(local, remote)
        return cls(
            local,
            remote,
            buffer.negotiated_tls_version,
            buffer.cipher(),
            buffer.getpeerchain(),
        )


class Response:
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
        decode: bool,
    ) -> None:
        self.status = status
        self.reason = reason
        self.version = version
        self.headers = headers
        self.request = request
        self.trailers = trailers
        self.history: tuple[Response, ...] = ()
        self.connection: ConnectionInfo | None = None
        self.started = monotonic()
        self.elapsed = 0.0
        self._raw = raw
        self._decode = decode
        self._body: bytes | None = None
        self._consumed = False

    @override
    def __repr__(self) -> str:
        return f"<Response {self.status} {self.reason} {self.version} {self.url}>"

    @property
    def url(self) -> URL:
        return self.request.url

    @property
    def ok(self) -> bool:
        return self.status < 400

    @property
    def is_redirect(self) -> bool:
        return self.status in REDIRECT_STATUSES and "location" in self.headers

    @property
    def location(self) -> URL | None:
        location = self.headers.get("location")
        if location is None:
            return None
        try:
            return self.url.join(location)
        except ValueError:
            # a Location that is not a URL is no redirect target, the same way an unparseable Date is no date
            return None

    @property
    def content_type(self) -> str | None:
        value = self.headers.get("content-type")
        return None if value is None else value.split(";", 1)[0].strip().lower()

    @property
    def charset(self) -> str | None:
        value = self.headers.get("content-type", "")
        for parameter in value.split(";")[1:]:
            name, _, argument = parameter.strip().partition("=")
            if name.lower() == "charset":
                return argument.strip().strip('"').lower()
        return None

    @property
    def content_length(self) -> int | None:
        value = self.headers.get("content-length")
        return (
            int(value)
            if value is not None and value.isascii() and value.isdigit()
            else None
        )

    @property
    def content_encoding(self) -> tuple[str, ...]:
        value = self.headers.get("content-encoding")
        return (
            ()
            if value is None
            else tuple(
                coding.strip().lower() for coding in value.split(",") if coding.strip()
            )
        )

    @property
    def cookies(self) -> tuple[Cookie, ...]:
        parsed = (
            Cookie.parse(value, self.url.host, self.url.path or "/")
            for value in self.headers.get_all("set-cookie")
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
            raise HTTPError(
                "the body has not been read; use await response.read() or iterate aiter_bytes()"
            )
        return self._body

    @property
    def text(self) -> str:
        return self.body.decode(self.charset or "utf-8", "replace")

    def json(self) -> object:
        return cast(object, json.loads(self.body))

    def raise_for_status(self) -> None:
        if self.status >= 400:
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
        decoder = ContentDecoder(codings)
        async for chunk in self.aiter_raw():
            decoded = decoder.decode(chunk)
            if decoded:
                yield decoded

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
        self.response: Response = response
