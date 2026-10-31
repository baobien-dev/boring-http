import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from enum import StrEnum
from typing import Self

from ssl2.value import Value

from boring_http.public_suffixes import PublicSuffixes


class CookieAttribute(StrEnum):
    DOMAIN = "domain"
    PATH = "path"
    MAX_AGE = "max-age"
    EXPIRES = "expires"
    SECURE = "secure"
    HTTP_ONLY = "httponly"


@dataclass(frozen=True, slots=True)
class Cookie(Value):
    name: str
    value: str
    domain: str
    path: str
    expires: float | None
    secure: bool
    http_only: bool
    host_only: bool
    created: float

    @classmethod
    def parse(cls, header: str, host: str, request_path: str) -> Self | None:
        # RFC 6265 section 5.2; None is a header the jar ignores
        pair, _, rest = header.partition(";")
        name, equals, value = pair.strip().partition("=")
        if not equals or not name.strip():
            return None
        domain, path, expires, secure, http_only = "", "", None, False, False
        for attribute in rest.split(";"):
            key, _, argument = attribute.strip().partition("=")
            argument = argument.strip()
            match key.lower():
                case CookieAttribute.DOMAIN:
                    domain = argument.lstrip(".").lower()
                case CookieAttribute.PATH:
                    path = argument
                case CookieAttribute.MAX_AGE if argument.lstrip("-").isascii() and argument.lstrip("-").isdigit():
                    expires = time.time() + int(argument)
                case CookieAttribute.EXPIRES if expires is None:
                    expires = cls._date(argument)
                case CookieAttribute.SECURE:
                    secure = True
                case CookieAttribute.HTTP_ONLY:
                    http_only = True
                case _:
                    pass
        if domain and not (host == domain or host.endswith("." + domain)):
            return None
        # RFC 6265 section 5.3 step 5: a public suffix as Domain is refused, unless it is the host itself,
        # which then keeps the cookie to that host
        if domain and cls.is_public_suffix(domain):
            if domain != host:
                return None
            domain = ""
        if not path.startswith("/"):
            path = request_path[: request_path.rfind("/")] or "/"
        return cls(
            name.strip(),
            value.strip().strip('"'),
            domain or host,
            path,
            expires,
            secure,
            http_only,
            not domain,
            time.time(),
        )

    @property
    def expired(self) -> bool:
        return self.expires is not None and self.expires <= time.time()

    @property
    def pair(self) -> str:
        return f"{self.name}={self.value}"

    def matches(self, host: str, path: str, *, secure: bool) -> bool:
        if self.host_only:
            domain_matches = host == self.domain
        else:
            domain_matches = host == self.domain or host.endswith("." + self.domain)
        path_matches = path == self.path or (
            path.startswith(self.path) and (self.path.endswith("/") or path[len(self.path)] == "/")
        )
        return domain_matches and path_matches and (secure or not self.secure) and not self.expired

    @staticmethod
    def is_public_suffix(domain: str) -> bool:
        # publicsuffix.org's algorithm: an exception rule wins, then a listed rule or a wildcard over the parent,
        # and a lone top-level label is one
        if domain in PublicSuffixes.EXCEPTIONS:
            return False
        parent = domain.partition(".")[2]
        return domain in PublicSuffixes.RULES or f"*.{parent}" in PublicSuffixes.RULES or not parent

    @staticmethod
    def _date(text: str) -> float | None:
        try:
            return parsedate_to_datetime(text).timestamp()
        except ValueError, TypeError:
            return None


class CookieJar:
    def __init__(self) -> None:
        self._cookies: dict[tuple[str, str, str], Cookie] = {}

    def __iter__(self) -> Iterator[Cookie]:
        return iter(tuple(self._cookies.values()))

    def __len__(self) -> int:
        return len(self._cookies)

    def get(self, name: str, domain: str | None = None) -> str | None:
        for cookie in self._cookies.values():
            if cookie.name == name and (domain is None or cookie.domain == domain):
                return cookie.value
        return None

    def set(self, cookie: Cookie) -> None:
        key = (cookie.domain, cookie.path, cookie.name)
        if cookie.expired:
            self._cookies.pop(key, None)
        else:
            self._cookies[key] = cookie

    def store(self, cookies: Iterable[Cookie]) -> None:
        for cookie in cookies:
            self.set(cookie)

    def clear(self) -> None:
        self._cookies.clear()

    def header(self, host: str, path: str, *, secure: bool) -> str | None:
        # RFC 6265 section 5.4: longer paths first, then the older cookie first
        matching = [cookie for cookie in self._cookies.values() if cookie.matches(host, path, secure=secure)]
        matching.sort(key=lambda cookie: (-len(cookie.path), cookie.created))
        return "; ".join(cookie.pair for cookie in matching) or None
