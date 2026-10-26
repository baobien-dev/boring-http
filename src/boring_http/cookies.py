import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Self

from boring_http.public_suffixes import EXCEPTIONS, RULES


@dataclass(frozen=True, slots=True)
class Cookie:
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
        pair, _, rest = header.partition(";")
        name, equals, value = pair.strip().partition("=")
        if not equals or not name.strip():
            return None
        domain, path, expires, secure, http_only = "", "", None, False, False
        for attribute in rest.split(";"):
            key, _, argument = attribute.strip().partition("=")
            match key.lower():
                case "domain":
                    domain = argument.strip().lstrip(".").lower()
                case "path":
                    path = argument.strip()
                case "max-age" if (
                    argument.strip().lstrip("-").isascii()
                    and argument.strip().lstrip("-").isdigit()
                ):
                    expires = time.time() + int(argument.strip())
                case "expires" if expires is None:
                    expires = cls._date(argument.strip())
                case "secure":
                    secure = True
                case "httponly":
                    http_only = True
                case _:
                    pass
        if domain and not (host == domain or host.endswith("." + domain)):
            return None
        # RFC 6265 section 5.3 step 5: a public suffix as Domain is refused, unless it is the host itself, which keeps the cookie to that host
        if domain and cls._public_suffix(domain):
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

    def matches(self, host: str, path: str, secure: bool) -> bool:
        if self.host_only:
            domain_ok = host == self.domain
        else:
            domain_ok = host == self.domain or host.endswith("." + self.domain)
        path_ok = path == self.path or (
            path.startswith(self.path)
            and (self.path.endswith("/") or path[len(self.path)] == "/")
        )
        return (
            domain_ok and path_ok and (secure or not self.secure) and not self.expired
        )

    @staticmethod
    def _public_suffix(domain: str) -> bool:
        # publicsuffix.org's algorithm: an exception rule wins, then a listed rule or a wildcard over the parent, and an unlisted top-level label is one
        if domain in EXCEPTIONS:
            return False
        parent = domain.partition(".")[2]
        return domain in RULES or f"*.{parent}" in RULES or not parent

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

    def header(self, host: str, path: str, secure: bool) -> str | None:
        matching = [
            cookie
            for cookie in self._cookies.values()
            if cookie.matches(host, path, secure)
        ]
        matching.sort(key=lambda cookie: (-len(cookie.path), cookie.created))
        return "; ".join(f"{cookie.name}={cookie.value}" for cookie in matching) or None
