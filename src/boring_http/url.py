from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from functools import lru_cache
from typing import Self, override
from urllib.parse import quote, urlencode, urljoin, urlsplit

from ssl2.errors import ParseError
from ssl2.value import Value

type ParamValue = str | int | float | bool | None
type Params = Mapping[str, ParamValue] | Sequence[tuple[str, ParamValue]]


class Port(IntEnum):
    HTTP = 80
    HTTPS = 443


class Scheme(StrEnum):
    HTTP = "http"
    HTTPS = "https"
    WS = "ws"
    WSS = "wss"

    @property
    def default_port(self) -> int:
        return Port.HTTPS if self.secure else Port.HTTP

    @property
    def secure(self) -> bool:
        return self in (Scheme.HTTPS, Scheme.WSS)

    @property
    def http(self) -> Scheme:
        # a WebSocket URL is an HTTP URL on the wire, RFC 6455 section 4.1 and RFC 8441 section 4
        match self:
            case Scheme.WS:
                return Scheme.HTTP
            case Scheme.WSS:
                return Scheme.HTTPS
            case _:
                return self


class Safe:
    # the characters quote() leaves alone in each part, RFC 3986 sections 3.3 and 3.4
    PATH = "/%:@!$&'()*+,;=~-._"
    QUERY = PATH + "?"


class CacheSize(IntEnum):
    PARSED_URLS = 512


@dataclass(frozen=True, slots=True)
class Url(Value):
    raw: str
    scheme: Scheme
    host: str
    port: int
    path: str
    query: str
    fragment: str
    username: str | None
    password: str | None

    @staticmethod
    @lru_cache(maxsize=CacheSize.PARSED_URLS)
    def parse(text: str) -> Url:
        parts = urlsplit(text)
        try:
            scheme = Scheme(parts.scheme.lower())
        except ValueError:
            raise ParseError(f"{parts.scheme!r} is not a scheme this client speaks, in {text!r}") from None
        if not parts.hostname:
            raise ParseError(f"the URL {text!r} names no host")
        try:
            port = parts.port
        except ValueError:
            raise ParseError(f"the URL {text!r} has a port that is not a number") from None
        return Url(
            text,
            scheme,
            parts.hostname.encode("idna").decode("ascii"),
            port if port is not None else scheme.default_port,
            quote(parts.path, Safe.PATH),
            quote(parts.query, Safe.QUERY),
            parts.fragment,
            parts.username,
            parts.password,
        )

    @property
    def secure(self) -> bool:
        return self.scheme.secure

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port

    @property
    def authority(self) -> str:
        # the host, with the port only when it is not the scheme's own
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == self.scheme.default_port else f"{host}:{self.port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.authority}"

    @property
    def target(self) -> str:
        return (self.path or "/") + (f"?{self.query}" if self.query else "")

    @property
    def text(self) -> str:
        return f"{self.origin}{self.target}" + (f"#{self.fragment}" if self.fragment else "")

    @override
    def __str__(self) -> str:
        return self.text

    def join(self, reference: str) -> Url:
        return Url.parse(urljoin(self.text, reference))

    def with_params(self, params: Params) -> Url:
        pairs = params.items() if isinstance(params, Mapping) else params
        # a boolean is spelled the way the web spells it, every other value as Python prints it
        rendered = [
            (name, str(value).lower() if isinstance(value, bool) else str(value))
            for name, value in pairs
            if value is not None
        ]
        query = "&".join(part for part in (self.query, urlencode(rendered)) if part)
        fragment = f"#{self.fragment}" if self.fragment else ""
        return Url.parse(
            f"{self.origin}{self.path or '/'}?{query}{fragment}"
            if query
            else f"{self.origin}{self.path or '/'}{fragment}"
        )

    def with_fragment(self, fragment: str) -> Self:
        return type(self)(
            self.raw, self.scheme, self.host, self.port, self.path, self.query, fragment, self.username, self.password
        )
