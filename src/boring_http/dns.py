import asyncio
import ipaddress
import logging
import secrets
import socket
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum, IntFlag, StrEnum
from http import HTTPStatus
from time import monotonic
from typing import Protocol, Self, override

from ssl2.errors import ConfigurationError
from ssl2.value import Value

from boring_http.errors import HTTPError, ProtocolError, ResolveError
from boring_http.headers import HeaderItems
from boring_http.response import Response
from boring_http.tracing import Event
from boring_http.url import Url


class Port(IntEnum):
    DNS = 53


class Size(IntEnum):
    # RFC 1035 section 2.3.4: labels of 63 octets in names of 255 on the wire; section 4.2.2: two octets of length
    # before a message over TCP; section 4.1.1: a sixteen bit id
    LABEL = 63
    NAME = 255
    LENGTH_PREFIX = 2
    IDENTIFIER_BITS = 16
    IPV4_ADDRESS = 4
    IPV6_ADDRESS = 16
    # a reply longer than the 512 octets RFC 1035 allows over UDP is still read whole, so the parser sees it, not a cut
    DATAGRAM = 65535


class Bits(IntEnum):
    # RFC 1035 section 4.1.1: the second header word is QR, a four bit opcode, AA, TC, RD, RA, three bits RFC 4035
    # gives to AD and CD, and a four bit response code; section 4.1.4: a label length with both high bits set points
    # into the message
    OPCODE_SHIFT = 11
    OPCODE = 0x7800
    FLAGS = 0x87F0
    RESPONSE_CODE = 0x000F
    POINTER = 0xC0
    POINTER_OFFSET = 0x3FFF
    UINT16 = 0xFFFF


class Limit(IntEnum):
    # each attempt asks the next server
    ATTEMPTS = 3
    CACHE_ENTRIES = 1024


class Seconds:
    QUERY = 2.0


class Transport(StrEnum):
    UDP = "udp"
    TCP = "tcp"
    HTTPS = "https"


class MediaType(StrEnum):
    # RFC 8484 section 6
    DNS_MESSAGE = "application/dns-message"


class Loopback(StrEnum):
    # RFC 6761 section 6.3: what localhost resolves to without a query
    IPV6 = "::1"
    IPV4 = "127.0.0.1"
    NAME = "localhost"


class Flag(IntFlag):
    # RFC 1035 section 4.1.1 and RFC 4035 section 3.1.6: the one bit fields of the second header word
    RESPONSE = 0x8000
    AUTHORITATIVE = 0x0400
    TRUNCATED = 0x0200
    RECURSION_DESIRED = 0x0100
    RECURSION_AVAILABLE = 0x0080
    AUTHENTIC_DATA = 0x0020
    CHECKING_DISABLED = 0x0010


class Registry(IntEnum):
    # a code point this file does not name still parses, as unassigned_N, so an answer with a new record type is read
    @classmethod
    @override
    def _missing_(cls, value: object) -> Self | None:
        if not isinstance(value, int) or value < 0 or value > Bits.UINT16:
            return None
        member = int.__new__(cls, value)
        member._name_ = f"unassigned_{value}"
        member._value_ = value
        return member


class Opcode(Registry):
    # RFC 1035 section 4.1.1, RFC 1996, RFC 2136 and RFC 8490
    QUERY = 0
    INVERSE_QUERY = 1
    STATUS = 2
    NOTIFY = 4
    UPDATE = 5
    STATEFUL_OPERATIONS = 6


class ResponseCode(Registry):
    # RFC 1035 section 4.1.1, RFC 2136 section 2.2 and RFC 8490 section 10.1.2
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5
    NAME_EXISTS = 6
    RECORD_SET_EXISTS = 7
    RECORD_SET_MISSING = 8
    NOT_AUTHORITATIVE = 9
    NOT_IN_ZONE = 10
    STATEFUL_TYPE_NOT_IMPLEMENTED = 11


class RecordType(Registry):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    NAPTR = 35
    OPT = 41
    DS = 43
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    TLSA = 52
    SVCB = 64
    HTTPS = 65
    ANY = 255
    CAA = 257


class RecordClass(Registry):
    IN = 1
    CH = 3
    HS = 4
    NONE = 254
    ANY = 255


class MessageReader:
    # reads one message field by field; a name may point back into it, RFC 1035 section 4.1.4
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._end = len(data)
        self.position = 0

    @property
    def remaining(self) -> int:
        return self._end - self.position

    def take(self, length: int) -> bytes:
        position = self.position
        if position + length > self._end:
            raise ProtocolError("the DNS message ends inside a field")
        self.position = position + length
        return self._data[position : position + length]

    def uint16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def uint32(self) -> int:
        return int.from_bytes(self.take(Size.IPV4_ADDRESS), "big")

    def name(self) -> str:
        # RFC 1035 sections 3.1 and 4.1.4: labels up to a zero octet, or a pointer to where an earlier name goes on;
        # a pointer has to point backwards, which is what keeps the walk finite
        labels: list[bytes] = []
        position = self.position
        resumed: int | None = None
        length = 0
        while True:
            if position >= self._end:
                raise ProtocolError("the DNS message ends inside a name")
            octet = self._data[position]
            if octet & Bits.POINTER == Bits.POINTER:
                if position + 1 >= self._end:
                    raise ProtocolError("the DNS message ends inside a name pointer")
                offset = int.from_bytes(self._data[position : position + 2], "big") & Bits.POINTER_OFFSET
                if offset >= position:
                    raise ProtocolError(f"a DNS name pointer to offset {offset} that does not point back")
                if resumed is None:
                    resumed = position + 2
                position = offset
                continue
            if octet & Bits.POINTER:
                raise ProtocolError(f"a DNS label with the reserved length bits {octet:#04x}")
            position += 1
            if octet == 0:
                break
            if position + octet > self._end:
                raise ProtocolError("the DNS message ends inside a label")
            length += octet + 1
            if length >= Size.NAME:
                raise ProtocolError(f"a DNS name longer than {Size.NAME} octets")
            labels.append(self._data[position : position + octet])
            position += octet
        self.position = position if resumed is None else resumed
        try:
            return b".".join(labels).decode("ascii")
        except UnicodeDecodeError as error:
            raise ProtocolError(f"a DNS name with octets outside ASCII: {b'.'.join(labels)!r}") from error


class MessageWriter:
    def __init__(self) -> None:
        self._data = bytearray()

    def put(self, data: bytes) -> None:
        self._data += data

    def uint16(self, value: int) -> None:
        self._data += value.to_bytes(2, "big")

    def uint32(self, value: int) -> None:
        self._data += value.to_bytes(Size.IPV4_ADDRESS, "big")

    def name(self, text: str) -> None:
        # RFC 1035 section 3.1: each label as its length and octets, then the zero octet of the root; nothing is
        # compressed, which every reader accepts
        stripped = text.rstrip(".")
        encoded = bytearray()
        for label in stripped.split(".") if stripped else ():
            try:
                octets = label.encode("ascii")
            except UnicodeEncodeError as error:
                raise ConfigurationError(f"the name {text!r} is not ASCII; encode it with IDNA first") from error
            if not octets or len(octets) > Size.LABEL:
                raise ConfigurationError(f"the label {label!r} of {text!r} is not 1 to {Size.LABEL} octets")
            encoded.append(len(octets))
            encoded += octets
        if len(encoded) >= Size.NAME:
            raise ConfigurationError(f"the name {text!r} is longer than {Size.NAME} octets on the wire")
        self._data += encoded
        self._data.append(0)

    def finish(self) -> bytes:
        return bytes(self._data)


@dataclass(frozen=True, slots=True)
class Header(Value):
    # RFC 1035 section 4.1.1
    id: int
    flags: Flag
    opcode: Opcode
    response_code: ResponseCode
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int

    @classmethod
    def read(cls, reader: MessageReader) -> Self:
        identifier = reader.uint16()
        word = reader.uint16()
        return cls(
            identifier,
            Flag(word & Bits.FLAGS),
            Opcode((word & Bits.OPCODE) >> Bits.OPCODE_SHIFT),
            ResponseCode(word & Bits.RESPONSE_CODE),
            reader.uint16(),
            reader.uint16(),
            reader.uint16(),
            reader.uint16(),
        )

    def write(self, writer: MessageWriter) -> None:
        writer.uint16(self.id)
        writer.uint16(int(self.flags) | (self.opcode << Bits.OPCODE_SHIFT) | self.response_code)
        for count in (self.question_count, self.answer_count, self.authority_count, self.additional_count):
            writer.uint16(count)


@dataclass(frozen=True, slots=True)
class Question(Value):
    # RFC 1035 section 4.1.2
    name: str
    type: RecordType
    class_: RecordClass = RecordClass.IN

    @classmethod
    def read(cls, reader: MessageReader) -> Self:
        return cls(reader.name(), RecordType(reader.uint16()), RecordClass(reader.uint16()))

    def write(self, writer: MessageWriter) -> None:
        writer.name(self.name)
        writer.uint16(self.type)
        writer.uint16(self.class_)

    def matches(self, other: Self) -> bool:
        # RFC 4343: names compare without regard to case
        return self.name.lower() == other.name.lower() and self.type == other.type and self.class_ == other.class_


@dataclass(frozen=True, slots=True)
class StartOfAuthority(Value):
    # RFC 1035 section 3.3.13
    primary: str
    mailbox: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int

    @classmethod
    def read(cls, reader: MessageReader) -> Self:
        return cls(
            reader.name(),
            reader.name(),
            reader.uint32(),
            reader.uint32(),
            reader.uint32(),
            reader.uint32(),
            reader.uint32(),
        )

    def write(self, writer: MessageWriter) -> None:
        writer.name(self.primary)
        writer.name(self.mailbox)
        for value in (self.serial, self.refresh, self.retry, self.expire, self.minimum):
            writer.uint32(value)


@dataclass(frozen=True, slots=True)
class Record(Value):
    # RFC 1035 section 4.1.3; the RDATA is kept as it would be on the wire with nothing compressed, so it stands alone
    name: str
    type: RecordType
    class_: RecordClass
    ttl: int
    data: bytes

    @classmethod
    def read(cls, reader: MessageReader) -> Self:
        name = reader.name()
        record_type = RecordType(reader.uint16())
        record_class = RecordClass(reader.uint16())
        ttl = reader.uint32()
        length = reader.uint16()
        end = reader.position + length
        match record_type:
            case RecordType.A | RecordType.AAAA:
                data = reader.take(length)
                if length != (Size.IPV4_ADDRESS if record_type is RecordType.A else Size.IPV6_ADDRESS):
                    raise ProtocolError(f"a {record_type.name} record for {name} with {length} octets of RDATA")
            case RecordType.CNAME | RecordType.NS | RecordType.PTR:
                # RFC 1035 section 3.3: one domain name, which may be compressed against the whole message
                writer = MessageWriter()
                writer.name(reader.name())
                data = writer.finish()
            case RecordType.SOA:
                writer = MessageWriter()
                StartOfAuthority.read(reader).write(writer)
                data = writer.finish()
            case _:
                data = reader.take(length)
        if reader.position != end:
            raise ProtocolError(
                f"the RDATA of a {record_type.name} record for {name} does not fill its {length} octets"
            )
        return cls(name, record_type, record_class, ttl, data)

    def write(self, writer: MessageWriter) -> None:
        writer.name(self.name)
        writer.uint16(self.type)
        writer.uint16(self.class_)
        writer.uint32(self.ttl)
        writer.uint16(len(self.data))
        writer.put(self.data)

    @property
    def address(self) -> str:
        match self.type:
            case RecordType.A:
                return str(ipaddress.IPv4Address(self.data))
            case RecordType.AAAA:
                return str(ipaddress.IPv6Address(self.data))
            case _:
                raise ProtocolError(f"a {self.type.name} record carries no address")

    @property
    def target(self) -> str:
        match self.type:
            case RecordType.CNAME | RecordType.NS | RecordType.PTR:
                return MessageReader(self.data).name()
            case _:
                raise ProtocolError(f"a {self.type.name} record names no target")

    @property
    def start_of_authority(self) -> StartOfAuthority:
        if self.type is not RecordType.SOA:
            raise ProtocolError(f"a {self.type.name} record is no SOA")
        return StartOfAuthority.read(MessageReader(self.data))


@dataclass(frozen=True, slots=True)
class Message(Value):
    # RFC 1035 section 4.1
    header: Header
    questions: tuple[Question, ...]
    answers: tuple[Record, ...]
    authorities: tuple[Record, ...]
    additionals: tuple[Record, ...]

    @classmethod
    def query(cls, name: str, record_type: RecordType, *, identifier: int) -> Self:
        header = Header(identifier, Flag.RECURSION_DESIRED, Opcode.QUERY, ResponseCode.NO_ERROR, 1, 0, 0, 0)
        return cls(header, (Question(name, record_type),), (), (), ())

    @classmethod
    def parse(cls, data: bytes) -> Self:
        reader = MessageReader(data)
        header = Header.read(reader)
        questions = tuple(Question.read(reader) for _ in range(header.question_count))
        answers = tuple(Record.read(reader) for _ in range(header.answer_count))
        authorities = tuple(Record.read(reader) for _ in range(header.authority_count))
        additionals = tuple(Record.read(reader) for _ in range(header.additional_count))
        if reader.remaining:
            raise ProtocolError(f"{reader.remaining} octets after the last record of a DNS message")
        return cls(header, questions, answers, authorities, additionals)

    @property
    def wire(self) -> bytes:
        writer = MessageWriter()
        self.header.write(writer)
        for question in self.questions:
            question.write(writer)
        for record in (*self.answers, *self.authorities, *self.additionals):
            record.write(writer)
        return writer.finish()


@dataclass(frozen=True, slots=True)
class Answer(Value):
    # what one record type answered for a name: the addresses, how long they hold, and the code the server gave
    addresses: tuple[str, ...]
    ttl: int
    code: ResponseCode


@dataclass(frozen=True, slots=True)
class CacheEntry(Value):
    answer: Answer
    expires: float


class DnsCache:
    # answers by name and record type until their TTL runs out, on the monotonic clock; when it is full the entry
    # nearest to expiry makes room
    def __init__(self, limit: int = Limit.CACHE_ENTRIES) -> None:
        self._limit = limit
        self._entries: dict[tuple[str, RecordType], CacheEntry] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, name: str, record_type: RecordType) -> Answer | None:
        key = (name, record_type)
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expires <= monotonic():
            del self._entries[key]
            return None
        return entry.answer

    def put(self, name: str, record_type: RecordType, answer: Answer) -> None:
        if answer.ttl <= 0 or self._limit <= 0:
            return
        key = (name, record_type)
        if key not in self._entries and len(self._entries) >= self._limit:
            del self._entries[min(self._entries, key=lambda held: self._entries[held].expires)]
        self._entries[key] = CacheEntry(answer, monotonic() + answer.ttl)

    def clear(self) -> None:
        self._entries.clear()


class Resolver(Protocol):
    # the addresses to try for a host, in that order, each with the port to connect to
    async def resolve(self, host: str, port: int) -> tuple[tuple[str, int], ...]: ...


class SystemResolver:
    # the operating system's resolver through getaddrinfo, in the order it gives
    async def resolve(self, host: str, port: int) -> tuple[tuple[str, int], ...]:
        loop = asyncio.get_running_loop()
        try:
            found = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            raise ResolveError(f"cannot resolve {host}: {error}") from error
        addresses: dict[tuple[str, int], None] = {}
        for _, _, _, _, socket_address in found:
            match socket_address:
                case (str() as address, int() as number, *_):
                    addresses[address, number] = None
                case _:
                    raise ResolveError(f"getaddrinfo gave {host} an address of an unexpected shape: {socket_address!r}")
        if not addresses:
            raise ResolveError(f"{host} resolves to no address")
        return tuple(addresses)


class MessageResolver(ABC):
    # asks A and AAAA for a name at the same time, through exchange(), and keeps what came back for its TTL
    logger = logging.getLogger("boring_http")

    def __init__(self, cache: DnsCache | None) -> None:
        self._cache = DnsCache() if cache is None else cache

    @property
    def cache(self) -> DnsCache:
        return self._cache

    @abstractmethod
    async def exchange(self, query: Message) -> Message: ...

    def identifier(self) -> int:
        # RFC 5452 section 9.2: an id the sender of a forged answer cannot guess
        return secrets.randbits(Size.IDENTIFIER_BITS)

    async def resolve(self, host: str, port: int) -> tuple[tuple[str, int], ...]:
        literal = self.literal(host)
        if literal is not None:
            return ((literal, port),)
        name = host.rstrip(".").lower()
        if name == Loopback.NAME or name.endswith(f".{Loopback.NAME}"):
            return ((Loopback.IPV6.value, port), (Loopback.IPV4.value, port))
        found: dict[RecordType, Answer] = {}
        wanted: list[RecordType] = []
        for record_type in (RecordType.AAAA, RecordType.A):
            cached = self._cache.get(name, record_type)
            if cached is None:
                wanted.append(record_type)
            else:
                found[record_type] = cached
        if wanted:
            results = await asyncio.gather(*(self.ask(name, kind) for kind in wanted), return_exceptions=True)
            failures: list[Exception] = []
            for record_type, result in zip(wanted, results, strict=True):
                match result:
                    case Answer():
                        found[record_type] = result
                        self._cache.put(name, record_type, result)
                    case ResolveError() | ProtocolError():
                        failures.append(result)
                        self.logger.warning(
                            "%s name=%s type=%s error=%s", Event.RESOLVE_FAILED, name, record_type.name, result
                        )
                    case BaseException():
                        raise result
            if len(failures) == len(wanted):
                raise ResolveError(f"cannot resolve {host}: {failures[0]}") from failures[0]
        answers = tuple(found[kind] for kind in (RecordType.AAAA, RecordType.A) if kind in found)
        addresses = tuple((address, port) for answer in answers for address in answer.addresses)
        if not addresses:
            if any(answer.code is ResponseCode.NAME_ERROR for answer in answers):
                raise ResolveError(f"{host} does not exist")
            raise ResolveError(f"{host} has no address")
        return addresses

    async def ask(self, name: str, record_type: RecordType) -> Answer:
        query = Message.query(name, record_type, identifier=self.identifier())
        return self.answer(query, await self.exchange(query))

    @classmethod
    def answer(cls, query: Message, response: Message) -> Answer:
        question = query.questions[0]
        header = response.header
        if header.id != query.header.id:
            raise ProtocolError(f"a DNS answer with id {header.id} to the question with id {query.header.id}")
        if Flag.RESPONSE not in header.flags:
            raise ProtocolError(f"a DNS message about {question.name} {question.type.name} that is no answer")
        if len(response.questions) != 1 or not response.questions[0].matches(question):
            raise ProtocolError(f"a DNS answer whose question is not {question.name} {question.type.name}")
        match header.response_code:
            case ResponseCode.NO_ERROR:
                matching = tuple(
                    record
                    for record in response.answers
                    if record.type == question.type and record.class_ == question.class_
                )
                if not matching:
                    return Answer((), cls.negative_ttl(response), header.response_code)
                # a CNAME on the way holds the chain only as long as its own TTL
                ttl = min(record.ttl for record in response.answers)
                return Answer(tuple(record.address for record in matching), ttl, header.response_code)
            case ResponseCode.NAME_ERROR:
                return Answer((), cls.negative_ttl(response), header.response_code)
            case code:
                raise ResolveError(f"the DNS server answered {code.name} to {question.name} {question.type.name}")

    @staticmethod
    def negative_ttl(response: Message) -> int:
        # RFC 2308 section 5: an empty answer holds for the lesser of the authority SOA's TTL and its MINIMUM field
        for record in response.authorities:
            if record.type is RecordType.SOA:
                return min(record.ttl, record.start_of_authority.minimum)
        return 0

    @staticmethod
    def literal(host: str) -> str | None:
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return None


@dataclass(frozen=True, slots=True)
class Server(Value):
    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    port: int = Port.DNS

    @classmethod
    def of(cls, entry: str | tuple[str, int]) -> Self:
        match entry:
            case str():
                host, port = entry, int(Port.DNS)
            case (host, port):
                pass
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ConfigurationError(f"a DNS server is named by its IP address, not {host!r}") from None
        return cls(address, port)

    @property
    def family(self) -> socket.AddressFamily:
        return socket.AF_INET6 if isinstance(self.address, ipaddress.IPv6Address) else socket.AF_INET

    @property
    def socket_address(self) -> tuple[str, int]:
        return str(self.address), self.port


class DnsResolver(MessageResolver):
    # RFC 1035 section 4.2: queries over UDP, and over TCP when the answer came back truncated, RFC 7766 section 5
    def __init__(
        self,
        servers: Sequence[str | tuple[str, int]],
        *,
        timeout: float = Seconds.QUERY,
        cache: DnsCache | None = None,
        attempts: int = Limit.ATTEMPTS,
    ) -> None:
        super().__init__(cache)
        self._servers = tuple(Server.of(entry) for entry in servers)
        if not self._servers:
            raise ConfigurationError("DnsResolver needs at least one server")
        if attempts < 1:
            raise ConfigurationError(f"attempts is at least 1, not {attempts}")
        self._timeout = timeout
        self._attempts = attempts

    @property
    def servers(self) -> tuple[Server, ...]:
        return self._servers

    @override
    async def exchange(self, query: Message) -> Message:
        # each attempt asks the next server within the timeout; a server that fails or has no answer passes the turn
        question = query.questions[0]
        failure: Exception | None = None
        for attempt in range(self._attempts):
            server = self._servers[attempt % len(self._servers)]
            try:
                async with asyncio.timeout(self._timeout):
                    response = await self._over_udp(server, query)
                    if Flag.TRUNCATED in response.header.flags:
                        self.logger.info(
                            "%s server=%s name=%s type=%s",
                            Event.DNS_TRUNCATED,
                            server.address,
                            question.name,
                            question.type.name,
                        )
                        response = await self._over_tcp(server, query)
            except TimeoutError:
                failure = ResolveError(f"{server.address} did not answer within {self._timeout:g} s")
            except (OSError, ProtocolError) as error:
                failure = error
            else:
                if response.header.response_code not in (ResponseCode.SERVER_FAILURE, ResponseCode.REFUSED):
                    return response
                failure = ResolveError(f"{server.address} answered {response.header.response_code.name}")
            self.logger.warning(
                "%s server=%s name=%s type=%s attempt=%d error=%s",
                Event.RESOLVE_FAILED,
                server.address,
                question.name,
                question.type.name,
                attempt + 1,
                failure,
            )
        servers = ", ".join(str(server.address) for server in self._servers)
        raise ResolveError(
            f"no answer about {question.name} {question.type.name} from {servers} in {self._attempts} attempts: {failure}"
        ) from failure

    async def _over_udp(self, server: Server, query: Message) -> Message:
        loop = asyncio.get_running_loop()
        udp = socket.socket(server.family, socket.SOCK_DGRAM)
        try:
            # a zero timeout is the non-blocking mode the event loop works with; a connected socket takes datagrams
            # from the server alone, RFC 5452 section 9.1
            udp.settimeout(0)
            udp.connect(server.socket_address)
            wire = query.wire
            await loop.sock_sendall(udp, wire)
            self._log_query(server, query, Transport.UDP, len(wire))
            while True:
                response = Message.parse(await loop.sock_recv(udp, Size.DATAGRAM))
                if response.header.id == query.header.id:
                    return response
                self.logger.debug(
                    "%s server=%s id=%d expected=%d",
                    Event.DNS_IGNORED,
                    server.address,
                    response.header.id,
                    query.header.id,
                )
        finally:
            udp.close()

    async def _over_tcp(self, server: Server, query: Message) -> Message:
        # RFC 1035 section 4.2.2: each message behind two octets of length
        reader, writer = await asyncio.open_connection(*server.socket_address)
        try:
            wire = query.wire
            writer.write(len(wire).to_bytes(Size.LENGTH_PREFIX, "big") + wire)
            await writer.drain()
            self._log_query(server, query, Transport.TCP, len(wire))
            length = int.from_bytes(await reader.readexactly(Size.LENGTH_PREFIX), "big")
            response = Message.parse(await reader.readexactly(length))
        except asyncio.IncompleteReadError as error:
            raise ProtocolError(f"{server.address} closed the TCP connection inside a DNS answer") from error
        finally:
            writer.close()
        if response.header.id != query.header.id:
            raise ProtocolError(f"a DNS answer over TCP with id {response.header.id}, not {query.header.id}")
        return response

    def _log_query(self, server: Server, query: Message, transport: Transport, size: int) -> None:
        question = query.questions[0]
        self.logger.debug(
            "%s server=%s name=%s type=%s transport=%s bytes=%d",
            Event.DNS_QUERY,
            server.address,
            question.name,
            question.type.name,
            transport,
            size,
        )


class Poster(Protocol):
    # what a DoH resolver asks of a Client
    async def post(self, url: str, *, content: bytes, headers: HeaderItems) -> Response: ...


class DohResolver(MessageResolver):
    # RFC 8484: the query is the body of a POST and the answer the body of its 200; the Client's HTTP/2 or HTTP/3
    # carries both, so several questions share one connection
    def __init__(self, url: str, *, client: Poster, cache: DnsCache | None = None) -> None:
        super().__init__(cache)
        parsed = Url.parse(url)
        if not parsed.secure:
            raise ConfigurationError(f"a DoH server is reached over https, not {parsed.scheme}")
        self._url = url
        self._client = client

    @property
    def url(self) -> str:
        return self._url

    @override
    def identifier(self) -> int:
        # RFC 8484 section 4.1: the id is zero in every query, so one answer serves everyone asking the same question
        return 0

    @override
    async def exchange(self, query: Message) -> Message:
        question = query.questions[0]
        wire = query.wire
        self.logger.debug(
            "%s server=%s name=%s type=%s transport=%s bytes=%d",
            Event.DNS_QUERY,
            self._url,
            question.name,
            question.type.name,
            Transport.HTTPS,
            len(wire),
        )
        headers = (("Accept", MediaType.DNS_MESSAGE.value), ("Content-Type", MediaType.DNS_MESSAGE.value))
        try:
            response = await self._client.post(self._url, content=wire, headers=headers)
        except HTTPError as error:
            raise ResolveError(f"{self._url} did not answer {question.name} {question.type.name}: {error}") from error
        if response.status != HTTPStatus.OK:
            raise ResolveError(f"{self._url} answered {response.status} to {question.name} {question.type.name}")
        if response.content_type != MediaType.DNS_MESSAGE:
            raise ProtocolError(f"{self._url} answered {response.content_type!r}, not {MediaType.DNS_MESSAGE}")
        return Message.parse(response.body)
