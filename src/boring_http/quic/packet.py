from dataclasses import dataclass
from enum import IntEnum
from typing import Self

from boring_ssl2 import QuicVersion
from ssl2.value import Value

from boring_http.errors import ProtocolError
from boring_http.quic.wire import Reader, Writer


class Bit(IntEnum):
    # RFC 9000 section 17: the first byte of a packet
    LONG_FORM = 0x80
    FIXED = 0x40
    KEY_PHASE = 0x04
    LONG_TYPE_SHIFT = 4
    LONG_TYPE_MASK = 0x03
    NUMBER_LENGTH_MASK = 0x03
    # RFC 9001 section 5.4.1: the bits of the first byte that header protection covers
    LONG_PROTECTED = 0x0F
    SHORT_PROTECTED = 0x1F


class Width(IntEnum):
    VERSION = 4
    CONNECTION_ID_LIMIT = 20
    RETRY_TAG = 16
    RESET_TOKEN = 16
    PATH_DATA = 8
    # the length of a long header packet is always written in two bytes, so a header's size is known before its payload
    LENGTH = 2
    LENGTH_PREFIX = 0x4000
    NUMBER_MAXIMUM = 4
    # RFC 9001 section 5.4.2: the header protection sample starts four bytes into the packet number field
    SAMPLE_OFFSET = 4
    SAMPLE = 16
    TAG = 16
    BITS_PER_BYTE = 8


class PacketType(IntEnum):
    INITIAL = 0
    ZERO_RTT = 1
    HANDSHAKE = 2
    RETRY = 3
    ONE_RTT = 4
    VERSION_NEGOTIATION = 5

    def code(self, version: QuicVersion) -> int:
        return self.long_types(version).index(self)

    @classmethod
    def long(cls, version: QuicVersion, code: int) -> PacketType:
        return cls.long_types(version)[code]

    @staticmethod
    def long_types(version: QuicVersion) -> tuple[PacketType, ...]:
        # RFC 9000 section 17.2 and RFC 9369 section 3.2: v2 rotates the long header type values of v1
        match version:
            case QuicVersion.V1:
                return (PacketType.INITIAL, PacketType.ZERO_RTT, PacketType.HANDSHAKE, PacketType.RETRY)
            case QuicVersion.V2:
                return (PacketType.RETRY, PacketType.INITIAL, PacketType.ZERO_RTT, PacketType.HANDSHAKE)


class FrameType(IntEnum):
    # RFC 9000 section 19 and RFC 9221 section 4
    PADDING = 0x00
    PING = 0x01
    ACK = 0x02
    ACK_ECN = 0x03
    RESET_STREAM = 0x04
    STOP_SENDING = 0x05
    CRYPTO = 0x06
    NEW_TOKEN = 0x07
    STREAM = 0x08
    STREAM_LAST = 0x0F
    MAX_DATA = 0x10
    MAX_STREAM_DATA = 0x11
    MAX_STREAMS_BIDI = 0x12
    MAX_STREAMS_UNI = 0x13
    DATA_BLOCKED = 0x14
    STREAM_DATA_BLOCKED = 0x15
    STREAMS_BLOCKED_BIDI = 0x16
    STREAMS_BLOCKED_UNI = 0x17
    NEW_CONNECTION_ID = 0x18
    RETIRE_CONNECTION_ID = 0x19
    PATH_CHALLENGE = 0x1A
    PATH_RESPONSE = 0x1B
    CONNECTION_CLOSE = 0x1C
    APPLICATION_CLOSE = 0x1D
    HANDSHAKE_DONE = 0x1E
    DATAGRAM = 0x30
    DATAGRAM_WITH_LENGTH = 0x31


class StreamBit(IntEnum):
    # RFC 9000 section 19.8: the low bits of a STREAM frame type say which fields follow
    FIN = 0x01
    LENGTH = 0x02
    OFFSET = 0x04


class TransportError(IntEnum):
    # RFC 9000 section 20.1; a TLS alert is reported as CRYPTO_ERROR plus the alert code
    NO_ERROR = 0x00
    INTERNAL_ERROR = 0x01
    CONNECTION_REFUSED = 0x02
    FLOW_CONTROL_ERROR = 0x03
    STREAM_LIMIT_ERROR = 0x04
    STREAM_STATE_ERROR = 0x05
    FINAL_SIZE_ERROR = 0x06
    FRAME_ENCODING_ERROR = 0x07
    TRANSPORT_PARAMETER_ERROR = 0x08
    CONNECTION_ID_LIMIT_ERROR = 0x09
    PROTOCOL_VIOLATION = 0x0A
    INVALID_TOKEN = 0x0B
    APPLICATION_ERROR = 0x0C
    CRYPTO_BUFFER_EXCEEDED = 0x0D
    KEY_UPDATE_ERROR = 0x0E
    AEAD_LIMIT_REACHED = 0x0F
    NO_VIABLE_PATH = 0x10
    CRYPTO_ERROR = 0x100


@dataclass(frozen=True, slots=True)
class Padding(Value):
    count: int


@dataclass(frozen=True, slots=True)
class Ping(Value):
    pass


@dataclass(frozen=True, slots=True)
class Ack(Value):
    largest: int
    delay: int
    # (smallest, largest) pairs from the newest range down, the first one ending at largest
    ranges: tuple[tuple[int, int], ...]
    ecn: tuple[int, int, int] | None = None


@dataclass(frozen=True, slots=True)
class ResetStream(Value):
    stream_id: int
    error: int
    final_size: int


@dataclass(frozen=True, slots=True)
class StopSending(Value):
    stream_id: int
    error: int


@dataclass(frozen=True, slots=True)
class Crypto(Value):
    offset: int
    data: bytes


@dataclass(frozen=True, slots=True)
class NewToken(Value):
    token: bytes


@dataclass(frozen=True, slots=True)
class Stream(Value):
    stream_id: int
    offset: int
    data: bytes
    fin: bool


@dataclass(frozen=True, slots=True)
class MaxData(Value):
    maximum: int


@dataclass(frozen=True, slots=True)
class MaxStreamData(Value):
    stream_id: int
    maximum: int


@dataclass(frozen=True, slots=True)
class MaxStreams(Value):
    bidirectional: bool
    maximum: int


@dataclass(frozen=True, slots=True)
class DataBlocked(Value):
    limit: int


@dataclass(frozen=True, slots=True)
class StreamDataBlocked(Value):
    stream_id: int
    limit: int


@dataclass(frozen=True, slots=True)
class StreamsBlocked(Value):
    bidirectional: bool
    limit: int


@dataclass(frozen=True, slots=True)
class NewConnectionId(Value):
    sequence: int
    retire_prior_to: int
    connection_id: bytes
    reset_token: bytes


@dataclass(frozen=True, slots=True)
class RetireConnectionId(Value):
    sequence: int


@dataclass(frozen=True, slots=True)
class PathChallenge(Value):
    data: bytes


@dataclass(frozen=True, slots=True)
class PathResponse(Value):
    data: bytes


@dataclass(frozen=True, slots=True)
class ConnectionClose(Value):
    error: int
    # the type of the frame that caused a transport close; None for an application close
    frame_type: int | None
    reason: bytes
    application: bool


@dataclass(frozen=True, slots=True)
class HandshakeDone(Value):
    pass


@dataclass(frozen=True, slots=True)
class Datagram(Value):
    data: bytes


type Frame = (
    Padding
    | Ping
    | Ack
    | ResetStream
    | StopSending
    | Crypto
    | NewToken
    | Stream
    | MaxData
    | MaxStreamData
    | MaxStreams
    | DataBlocked
    | StreamDataBlocked
    | StreamsBlocked
    | NewConnectionId
    | RetireConnectionId
    | PathChallenge
    | PathResponse
    | ConnectionClose
    | HandshakeDone
    | Datagram
)


class FrameReader(Reader):
    # RFC 9000 section 12.4: the frames that do not call for an acknowledgement
    NOT_ACK_ELICITING = (Ack, Padding, ConnectionClose)

    def frame(self) -> Frame:
        kind = self.varint()
        if FrameType.STREAM <= kind <= FrameType.STREAM_LAST:
            stream_id = self.varint()
            offset = self.varint() if kind & StreamBit.OFFSET else 0
            data = self.take(self.varint()) if kind & StreamBit.LENGTH else self.rest()
            return Stream(stream_id, offset, data, fin=bool(kind & StreamBit.FIN))
        match kind:
            case FrameType.PADDING:
                return Padding(self._padding())
            case FrameType.PING:
                return Ping()
            case FrameType.ACK:
                return self._ack(ecn=False)
            case FrameType.ACK_ECN:
                return self._ack(ecn=True)
            case FrameType.RESET_STREAM:
                return ResetStream(self.varint(), self.varint(), self.varint())
            case FrameType.STOP_SENDING:
                return StopSending(self.varint(), self.varint())
            case FrameType.CRYPTO:
                offset = self.varint()
                return Crypto(offset, self.take(self.varint()))
            case FrameType.NEW_TOKEN:
                return NewToken(self.take(self.varint()))
            case FrameType.MAX_DATA:
                return MaxData(self.varint())
            case FrameType.MAX_STREAM_DATA:
                return MaxStreamData(self.varint(), self.varint())
            case FrameType.MAX_STREAMS_BIDI:
                return MaxStreams(bidirectional=True, maximum=self.varint())
            case FrameType.MAX_STREAMS_UNI:
                return MaxStreams(bidirectional=False, maximum=self.varint())
            case FrameType.DATA_BLOCKED:
                return DataBlocked(self.varint())
            case FrameType.STREAM_DATA_BLOCKED:
                return StreamDataBlocked(self.varint(), self.varint())
            case FrameType.STREAMS_BLOCKED_BIDI:
                return StreamsBlocked(bidirectional=True, limit=self.varint())
            case FrameType.STREAMS_BLOCKED_UNI:
                return StreamsBlocked(bidirectional=False, limit=self.varint())
            case FrameType.NEW_CONNECTION_ID:
                sequence, retire_prior_to = self.varint(), self.varint()
                connection_id = self.take(self.byte())
                if len(connection_id) > Width.CONNECTION_ID_LIMIT:
                    raise ProtocolError(f"a connection id of {len(connection_id)} bytes is longer than QUIC allows")
                return NewConnectionId(sequence, retire_prior_to, connection_id, self.take(Width.RESET_TOKEN))
            case FrameType.RETIRE_CONNECTION_ID:
                return RetireConnectionId(self.varint())
            case FrameType.PATH_CHALLENGE:
                return PathChallenge(self.take(Width.PATH_DATA))
            case FrameType.PATH_RESPONSE:
                return PathResponse(self.take(Width.PATH_DATA))
            case FrameType.CONNECTION_CLOSE:
                error, frame_type = self.varint(), self.varint()
                return ConnectionClose(error, frame_type, self.take(self.varint()), application=False)
            case FrameType.APPLICATION_CLOSE:
                error = self.varint()
                return ConnectionClose(error, None, self.take(self.varint()), application=True)
            case FrameType.HANDSHAKE_DONE:
                return HandshakeDone()
            case FrameType.DATAGRAM:
                return Datagram(self.rest())
            case FrameType.DATAGRAM_WITH_LENGTH:
                return Datagram(self.take(self.varint()))
            case _:
                raise ProtocolError(f"unknown QUIC frame type {kind:#x}")

    def _padding(self) -> int:
        # one PADDING frame per byte on the wire; a run of them is read as one
        count = 1
        while self.remaining and self.peek() == FrameType.PADDING:
            self.position += 1
            count += 1
        return count

    def _ack(self, *, ecn: bool) -> Ack:
        # RFC 9000 section 19.3: the largest number, then ranges counted downwards by gaps
        largest, delay, count, first = self.varint(), self.varint(), self.varint(), self.varint()
        smallest = largest - first
        ranges = [(smallest, largest)]
        for _ in range(count):
            gap, length = self.varint(), self.varint()
            top = smallest - gap - 2
            smallest = top - length
            if smallest < 0:
                raise ProtocolError("an ACK frame reaches below packet number zero")
            ranges.append((smallest, top))
        counts = (self.varint(), self.varint(), self.varint()) if ecn else None
        return Ack(largest, delay, tuple(ranges), counts)


class FrameWriter(Writer):
    def frame(self, frame: Frame) -> None:
        match frame:
            case Stream():
                self.put(self.stream_frame(frame))
            case Padding(count):
                self.put(bytes(count))
            case Ping():
                self.varint(FrameType.PING)
            case Ack(largest, delay, ranges, ecn):
                self.varint(FrameType.ACK_ECN if ecn is not None else FrameType.ACK)
                self.varint(largest)
                self.varint(delay)
                self.varint(len(ranges) - 1)
                self.varint(ranges[0][1] - ranges[0][0])
                previous = ranges[0][0]
                for smallest, top in ranges[1:]:
                    self.varint(previous - top - 2)
                    self.varint(top - smallest)
                    previous = smallest
                if ecn is not None:
                    for count in ecn:
                        self.varint(count)
            case ResetStream(stream_id, error, final_size):
                self.varint(FrameType.RESET_STREAM)
                self.varint(stream_id)
                self.varint(error)
                self.varint(final_size)
            case StopSending(stream_id, error):
                self.varint(FrameType.STOP_SENDING)
                self.varint(stream_id)
                self.varint(error)
            case Crypto(offset, data):
                self.varint(FrameType.CRYPTO)
                self.varint(offset)
                self.varint(len(data))
                self.put(data)
            case NewToken(token):
                self.varint(FrameType.NEW_TOKEN)
                self.varint(len(token))
                self.put(token)
            case MaxData(maximum):
                self.varint(FrameType.MAX_DATA)
                self.varint(maximum)
            case MaxStreamData(stream_id, maximum):
                self.varint(FrameType.MAX_STREAM_DATA)
                self.varint(stream_id)
                self.varint(maximum)
            case MaxStreams(bidirectional, maximum):
                self.varint(FrameType.MAX_STREAMS_BIDI if bidirectional else FrameType.MAX_STREAMS_UNI)
                self.varint(maximum)
            case DataBlocked(limit):
                self.varint(FrameType.DATA_BLOCKED)
                self.varint(limit)
            case StreamDataBlocked(stream_id, limit):
                self.varint(FrameType.STREAM_DATA_BLOCKED)
                self.varint(stream_id)
                self.varint(limit)
            case StreamsBlocked(bidirectional, limit):
                self.varint(FrameType.STREAMS_BLOCKED_BIDI if bidirectional else FrameType.STREAMS_BLOCKED_UNI)
                self.varint(limit)
            case NewConnectionId(sequence, retire_prior_to, connection_id, reset_token):
                self.varint(FrameType.NEW_CONNECTION_ID)
                self.varint(sequence)
                self.varint(retire_prior_to)
                self.byte(len(connection_id))
                self.put(connection_id)
                self.put(reset_token)
            case RetireConnectionId(sequence):
                self.varint(FrameType.RETIRE_CONNECTION_ID)
                self.varint(sequence)
            case PathChallenge(data):
                self.varint(FrameType.PATH_CHALLENGE)
                self.put(data)
            case PathResponse(data):
                self.varint(FrameType.PATH_RESPONSE)
                self.put(data)
            case ConnectionClose(error, frame_type, reason, application):
                self.varint(FrameType.APPLICATION_CLOSE if application else FrameType.CONNECTION_CLOSE)
                self.varint(error)
                if not application:
                    self.varint(frame_type or 0)
                self.varint(len(reason))
                self.put(reason)
            case HandshakeDone():
                self.varint(FrameType.HANDSHAKE_DONE)
            case Datagram(data):
                self.varint(FrameType.DATAGRAM_WITH_LENGTH)
                self.varint(len(data))
                self.put(data)

    @classmethod
    def stream_frame(cls, frame: Stream) -> bytes:
        # the frame a transfer repeats thousands of times, built in one expression
        kind = FrameType.STREAM | StreamBit.LENGTH
        if frame.offset:
            kind |= StreamBit.OFFSET
        if frame.fin:
            kind |= StreamBit.FIN
        return (
            cls.encode_varint(kind)
            + cls.encode_varint(frame.stream_id)
            + (cls.encode_varint(frame.offset) if frame.offset else b"")
            + cls.encode_varint(len(frame.data))
            + frame.data
        )

    @classmethod
    def length(cls, frame: Frame) -> int:
        if isinstance(frame, Stream):
            # sized without building the frame; the type takes one byte
            return (
                1
                + cls.varint_length(frame.stream_id)
                + (cls.varint_length(frame.offset) if frame.offset else 0)
                + cls.varint_length(len(frame.data))
                + len(frame.data)
            )
        writer = cls()
        writer.frame(frame)
        return len(writer)


@dataclass(frozen=True, slots=True)
class Header(Value):
    # the unprotected part of a packet, and where the rest of it lies within the datagram
    packet_type: PacketType
    version: int
    destination: bytes
    source: bytes
    token: bytes
    number_offset: int
    end: int
    supported_versions: tuple[int, ...] = ()
    retry_tag: bytes = b""

    @classmethod
    def parse(cls, data: bytes, offset: int, destination_length: int) -> Self:
        reader = Reader(data, offset)
        first = reader.byte()
        if not first & Bit.LONG_FORM:
            # a short header carries the id this endpoint chose; its length is known only here
            destination = reader.take(destination_length)
            return cls(PacketType.ONE_RTT, 0, destination, b"", b"", reader.position, len(data))
        version = int.from_bytes(reader.take(Width.VERSION), "big")
        destination = reader.take(reader.byte())
        source = reader.take(reader.byte())
        if version == 0:
            # RFC 9000 section 17.2.1: a Version Negotiation packet lists what the server speaks
            versions: list[int] = []
            while reader.remaining >= Width.VERSION:
                versions.append(int.from_bytes(reader.take(Width.VERSION), "big"))
            return cls(
                PacketType.VERSION_NEGOTIATION, 0, destination, source, b"", reader.position, len(data), tuple(versions)
            )
        try:
            quic_version = QuicVersion(version)
        except ValueError:
            raise ProtocolError(f"unknown QUIC version {version:#010x}") from None
        packet_type = PacketType.long(quic_version, (first >> Bit.LONG_TYPE_SHIFT) & Bit.LONG_TYPE_MASK)
        if packet_type is PacketType.RETRY:
            # RFC 9000 section 17.2.5: the token runs to the integrity tag that ends the packet
            body = reader.rest()
            if len(body) < Width.RETRY_TAG:
                raise ProtocolError("a Retry packet shorter than its integrity tag")
            tag_start = len(body) - Width.RETRY_TAG
            return cls(
                packet_type,
                version,
                destination,
                source,
                body[:tag_start],
                reader.position,
                len(data),
                (),
                body[tag_start:],
            )
        token = reader.take(reader.varint()) if packet_type is PacketType.INITIAL else b""
        length = reader.varint()
        end = reader.position + length
        if end > len(data):
            raise ProtocolError("a QUIC packet longer than its datagram")
        return cls(packet_type, version, destination, source, token, reader.position, end)

    @staticmethod
    def long_bytes(
        packet_type: PacketType,
        version: QuicVersion,
        destination: bytes,
        source: bytes,
        token: bytes,
        number: bytes,
        payload_length: int,
    ) -> bytes:
        first = Bit.LONG_FORM | Bit.FIXED | (packet_type.code(version) << Bit.LONG_TYPE_SHIFT) | (len(number) - 1)
        head = (
            bytes((first,))
            + version.to_bytes(Width.VERSION, "big")
            + bytes((len(destination),))
            + destination
            + bytes((len(source),))
            + source
        )
        if packet_type is PacketType.INITIAL:
            head += Writer.encode_varint(len(token)) + token
        return head + (Width.LENGTH_PREFIX | (len(number) + payload_length)).to_bytes(Width.LENGTH, "big") + number

    @staticmethod
    def short_bytes(destination: bytes, number: bytes, *, key_phase: bool) -> bytes:
        first = Bit.FIXED | (Bit.KEY_PHASE if key_phase else 0) | (len(number) - 1)
        return bytes((first,)) + destination + number
