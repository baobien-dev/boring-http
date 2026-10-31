import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import ClassVar, Self, cast, override

from ssl2.errors import ConfigurationError
from ssl2.value import Value


@dataclass(frozen=True, slots=True)
class Header(Value):
    name: str
    value: str

    # RFC 9110 section 5.6.2: a field name is a token
    TOKEN: ClassVar[re.Pattern[str]] = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")

    def __post_init__(self) -> None:
        if not self.TOKEN.fullmatch(self.name):
            raise ConfigurationError(f"header name {self.name!r} is not a token")
        stripped = self.value.strip()
        if "\r" in stripped or "\n" in stripped or "\0" in stripped:
            raise ConfigurationError(f"header {self.name} holds a line break or a NUL in its value")
        object.__setattr__(self, "value", stripped)

    @property
    def lowered(self) -> str:
        return self.name.lower()

    @property
    def text(self) -> str:
        return f"{self.name}: {self.value}"


type HeaderItems = Mapping[str, str] | Iterable[tuple[str, str] | Header] | Headers


class Headers:
    # the fields of a message in the order they are sent, looked up without regard to case
    def __init__(self, items: HeaderItems | None = None) -> None:
        self._headers: list[Header] = []
        self._lowered: list[str] = []
        if items is None:
            return
        if isinstance(items, Mapping):
            # the checker cannot tell a mapping of names from an iterable of pairs here; the runtime check above can
            mapping = cast("Mapping[str, str]", items)
            for name, value in mapping.items():
                self.add(name, value)
            return
        for item in items:
            match item:
                case Header():
                    self.append(item)
                case (name, value):
                    self.add(name, value)

    def __iter__(self) -> Iterator[Header]:
        return iter(self._headers)

    def __len__(self) -> int:
        return len(self._headers)

    def __contains__(self, name: str) -> bool:
        return name.lower() in self._lowered

    def __getitem__(self, name: str) -> str:
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    @override
    def __eq__(self, other: object) -> bool:
        return isinstance(other, Headers) and other._headers == self._headers

    @override
    def __hash__(self) -> int:
        return hash(tuple(self._headers))

    @override
    def __repr__(self) -> str:
        return f"Headers({self._headers!r})"

    def keys(self) -> list[str]:
        # the distinct names, first spelling kept, so dict(headers) maps each name to its first value
        seen: dict[str, str] = {}
        for header in self._headers:
            seen.setdefault(header.lowered, header.name)
        return list(seen.values())

    def get(self, name: str, default: str | None = None) -> str | None:
        index = self._index(name)
        return default if index is None else self._headers[index].value

    def get_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [header.value for header, key in zip(self._headers, self._lowered, strict=True) if key == lowered]

    def add(self, name: str, value: str) -> None:
        self.append(Header(name, value))

    def append(self, header: Header) -> None:
        self._headers.append(header)
        self._lowered.append(header.lowered)

    def set(self, name: str, value: str) -> None:
        header = Header(name, value)
        index = self._index(name)
        if index is None:
            self.append(header)
        else:
            self._headers[index] = header
            self._lowered[index] = header.lowered

    def insert(self, index: int, name: str, value: str) -> None:
        header = Header(name, value)
        self._headers.insert(index, header)
        self._lowered.insert(index, header.lowered)

    def remove(self, name: str) -> None:
        lowered = name.lower()
        kept = [header for header in self._headers if header.lowered != lowered]
        self._headers = kept
        self._lowered = [header.lowered for header in kept]

    def copy(self) -> Self:
        # the headers passed their checks when they came in, so a copy does not run them again
        return type(self)(self._headers)

    def merged(self, other: Headers) -> Self:
        # other's fields replace same-named ones where they stood, and the rest go at the end
        merged = list(self._headers)
        for lowered in dict.fromkeys(header.lowered for header in other):
            positions = [index for index, header in enumerate(merged) if header.lowered == lowered]
            replacements = [header for header in other if header.lowered == lowered]
            if positions:
                merged = [header for header in merged if header.lowered != lowered]
                merged[positions[0] : positions[0]] = replacements
            else:
                merged += replacements
        return type(self)(merged)

    def _index(self, name: str) -> int | None:
        lowered = name.lower()
        return self._lowered.index(lowered) if lowered in self._lowered else None
