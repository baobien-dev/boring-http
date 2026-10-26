from dataclasses import dataclass
from enum import IntEnum

from boring_ssl2 import QuicVersion

from boring_http.errors import ProtocolError

FORM_LONG = 0x80
FIXED_BIT = 0x40
KEY_PHASE_BIT = 0x04
MAX_CONNECTION_ID = 20


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
        # RFC 9369 section 3.2: v2 rotates the long header type values of v1
        if version is QuicVersion.V1:
            return (
                PacketType.INITIAL,
                PacketType.ZERO_RTT,
                PacketType.HANDSHAKE,
                PacketType.RETRY,
            )
        return (
            PacketType.RETRY,
            PacketType.INITIAL,
            PacketType.ZERO_RTT,
            PacketType.HANDSHAKE,
        )


class FrameType(IntEnum):
    PADDING = 0x00
    PING = 0x01
    ACK = 0x02
    ACK_ECN = 0x03
    RESET_STREAM = 0x04
    STOP_SENDING = 0x05
    CRYPTO = 0x06
    NEW_TOKEN = 0x07
    STREAM = 0x08
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


class TransportError(IntEnum):
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
class Padding:
    count: int


@dataclass(frozen=True, slots=True)
class Ping:
    pass


@dataclass(frozen=True, slots=True)
class Ack:
    largest: int
    delay: int
    ranges: tuple[tuple[int, int], ...]
    ecn: tuple[int, int, int] | None = None


@dataclass(frozen=True, slots=True)
class ResetStream:
    stream_id: int
    error: int
    final_size: int


@dataclass(frozen=True, slots=True)
class StopSending:
    stream_id: int
    error: int


@dataclass(frozen=True, slots=True)
class Crypto:
    offset: int
    data: bytes


@dataclass(frozen=True, slots=True)
class NewToken:
    token: bytes


@dataclass(frozen=True, slots=True)
class Stream:
    stream_id: int
    offset: int
    data: bytes
    fin: bool


@dataclass(frozen=True, slots=True)
class MaxData:
    maximum: int


@dataclass(frozen=True, slots=True)
class MaxStreamData:
    stream_id: int
    maximum: int


@dataclass(frozen=True, slots=True)
class MaxStreams:
    bidirectional: bool
    maximum: int


@dataclass(frozen=True, slots=True)
class DataBlocked:
    limit: int


@dataclass(frozen=True, slots=True)
class StreamDataBlocked:
    stream_id: int
    limit: int


@dataclass(frozen=True, slots=True)
class StreamsBlocked:
    bidirectional: bool
    limit: int


@dataclass(frozen=True, slots=True)
class NewConnectionId:
    sequence: int
    retire_prior_to: int
    connection_id: bytes
    reset_token: bytes


@dataclass(frozen=True, slots=True)
class RetireConnectionId:
    sequence: int


@dataclass(frozen=True, slots=True)
class PathChallenge:
    data: bytes


@dataclass(frozen=True, slots=True)
class PathResponse:
    data: bytes


@dataclass(frozen=True, slots=True)
class ConnectionClose:
    error: int
    frame_type: int | None
    reason: bytes
    application: bool


@dataclass(frozen=True, slots=True)
class HandshakeDone:
    pass


@dataclass(frozen=True, slots=True)
class Datagram:
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
ACK_ELICITING_EXCLUSIONS = (Ack, Padding, ConnectionClose)


class Reader:
    def __init__(self, data: bytes, position: int = 0) -> None:
        self._data = data
        self._end = len(data)
        self.position = position

    @property
    def remaining(self) -> int:
        return self._end - self.position

    def byte(self) -> int:
        if self.position >= self._end:
            raise ProtocolError("packet ended inside a field")
        value = self._data[self.position]
        self.position += 1
        return value

    def take(self, length: int) -> bytes:
        position = self.position
        if position + length > self._end:
            raise ProtocolError("packet ended inside a field")
        self.position = position + length
        return self._data[position : position + length]

    def varint(self) -> int:
        position = self.position
        if position >= self._end:
            raise ProtocolError("packet ended inside a field")
        first = self._data[position]
        length = 1 << (first >> 6)
        if length == 1:
            self.position = position + 1
            return first & 0x3F
        end = position + length
        if end > self._end:
            raise ProtocolError("packet ended inside a field")
        self.position = end
        return int.from_bytes(self._data[position:end]) & ((1 << (8 * length - 2)) - 1)

    def rest(self) -> bytes:
        return self.take(self.remaining)

    def frame(self) -> Frame:
        kind = self.varint()
        if FrameType.STREAM <= kind <= FrameType.STREAM + 7:
            stream_id = self.varint()
            offset = self.varint() if kind & 0x04 else 0
            data = self.take(self.varint()) if kind & 0x02 else self.rest()
            return Stream(stream_id, offset, data, bool(kind & 0x01))
        match kind:
            case FrameType.PADDING:
                count = 1
                while self.remaining and self._data[self.position] == 0:
                    self.position += 1
                    count += 1
                return Padding(count)
            case FrameType.PING:
                return Ping()
            case FrameType.ACK | FrameType.ACK_ECN:
                largest, delay, count, first = (
                    self.varint(),
                    self.varint(),
                    self.varint(),
                    self.varint(),
                )
                ranges = [(largest - first, largest)]
                smallest = largest - first
                for _ in range(count):
                    gap, length = self.varint(), self.varint()
                    largest = smallest - gap - 2
                    smallest = largest - length
                    ranges.append((smallest, largest))
                ecn = (
                    (self.varint(), self.varint(), self.varint())
                    if kind == FrameType.ACK_ECN
                    else None
                )
                return Ack(ranges[0][1], delay, tuple(ranges), ecn)
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
            case FrameType.MAX_STREAMS_BIDI | FrameType.MAX_STREAMS_UNI:
                return MaxStreams(kind == FrameType.MAX_STREAMS_BIDI, self.varint())
            case FrameType.DATA_BLOCKED:
                return DataBlocked(self.varint())
            case FrameType.STREAM_DATA_BLOCKED:
                return StreamDataBlocked(self.varint(), self.varint())
            case FrameType.STREAMS_BLOCKED_BIDI | FrameType.STREAMS_BLOCKED_UNI:
                return StreamsBlocked(
                    kind == FrameType.STREAMS_BLOCKED_BIDI, self.varint()
                )
            case FrameType.NEW_CONNECTION_ID:
                sequence, retire = self.varint(), self.varint()
                connection_id = self.take(self.byte())
                return NewConnectionId(sequence, retire, connection_id, self.take(16))
            case FrameType.RETIRE_CONNECTION_ID:
                return RetireConnectionId(self.varint())
            case FrameType.PATH_CHALLENGE:
                return PathChallenge(self.take(8))
            case FrameType.PATH_RESPONSE:
                return PathResponse(self.take(8))
            case FrameType.CONNECTION_CLOSE | FrameType.APPLICATION_CLOSE:
                error = self.varint()
                frame_type = (
                    self.varint() if kind == FrameType.CONNECTION_CLOSE else None
                )
                return ConnectionClose(
                    error,
                    frame_type,
                    self.take(self.varint()),
                    kind == FrameType.APPLICATION_CLOSE,
                )
            case FrameType.HANDSHAKE_DONE:
                return HandshakeDone()
            case FrameType.DATAGRAM | FrameType.DATAGRAM_WITH_LENGTH:
                return Datagram(
                    self.take(self.varint())
                    if kind == FrameType.DATAGRAM_WITH_LENGTH
                    else self.rest()
                )
            case _:
                raise ProtocolError(f"unknown QUIC frame type {kind:#x}")


class Writer:
    def __init__(self) -> None:
        self._data = bytearray()

    def __len__(self) -> int:
        return len(self._data)

    def byte(self, value: int) -> None:
        self._data.append(value)

    def put(self, data: bytes) -> None:
        self._data += data

    def varint(self, value: int) -> None:
        if value < 0x40:
            self._data.append(value)
        elif value < 0x4000:
            self._data += (value | 0x4000).to_bytes(2, "big")
        else:
            self._data += self.encode_varint(value)

    def finish(self) -> bytes:
        return bytes(self._data)

    @staticmethod
    def varint_length(value: int) -> int:
        if value < 0x40:
            return 1
        if value < 0x4000:
            return 2
        return 4 if value < 0x40000000 else 8

    @staticmethod
    def encode_varint(value: int) -> bytes:
        if value < 0x40:
            return bytes((value,))
        if value < 0x4000:
            return (value | 0x4000).to_bytes(2, "big")
        if value < 0x40000000:
            return (value | 0x80000000).to_bytes(4, "big")
        if value < 0x4000000000000000:
            return (value | 0xC000000000000000).to_bytes(8, "big")
        raise ValueError(f"{value} does not fit a QUIC varint")

    @classmethod
    def stream_frame(cls, frame: Stream) -> bytes:
        # the frame a transfer repeats thousands of times, built as bytes without the growing buffer
        encode = cls.encode_varint
        return (
            encode(
                FrameType.STREAM
                | 0x02
                | (0x04 if frame.offset else 0)
                | (0x01 if frame.fin else 0)
            )
            + encode(frame.stream_id)
            + (encode(frame.offset) if frame.offset else b"")
            + encode(len(frame.data))
            + frame.data
        )

    def frame(self, frame: Frame) -> None:
        match frame:
            case Stream():
                self._data += self.stream_frame(frame)
            case Padding(count):
                self._data += bytes(count)
            case Ping():
                self.varint(FrameType.PING)
            case Ack(largest, delay, ranges, ecn):
                self.varint(FrameType.ACK_ECN if ecn else FrameType.ACK)
                self.varint(largest)
                self.varint(delay)
                self.varint(len(ranges) - 1)
                self.varint(ranges[0][1] - ranges[0][0])
                previous = ranges[0][0]
                for smallest, biggest in ranges[1:]:
                    self.varint(previous - biggest - 2)
                    self.varint(biggest - smallest)
                    previous = smallest
                if ecn:
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
                self._data += data
            case NewToken(token):
                self.varint(FrameType.NEW_TOKEN)
                self.varint(len(token))
                self._data += token
            case MaxData(maximum):
                self.varint(FrameType.MAX_DATA)
                self.varint(maximum)
            case MaxStreamData(stream_id, maximum):
                self.varint(FrameType.MAX_STREAM_DATA)
                self.varint(stream_id)
                self.varint(maximum)
            case MaxStreams(bidirectional, maximum):
                self.varint(
                    FrameType.MAX_STREAMS_BIDI
                    if bidirectional
                    else FrameType.MAX_STREAMS_UNI
                )
                self.varint(maximum)
            case DataBlocked(limit):
                self.varint(FrameType.DATA_BLOCKED)
                self.varint(limit)
            case StreamDataBlocked(stream_id, limit):
                self.varint(FrameType.STREAM_DATA_BLOCKED)
                self.varint(stream_id)
                self.varint(limit)
            case StreamsBlocked(bidirectional, limit):
                self.varint(
                    FrameType.STREAMS_BLOCKED_BIDI
                    if bidirectional
                    else FrameType.STREAMS_BLOCKED_UNI
                )
                self.varint(limit)
            case NewConnectionId(sequence, retire, connection_id, reset_token):
                self.varint(FrameType.NEW_CONNECTION_ID)
                self.varint(sequence)
                self.varint(retire)
                self.byte(len(connection_id))
                self._data += connection_id + reset_token
            case RetireConnectionId(sequence):
                self.varint(FrameType.RETIRE_CONNECTION_ID)
                self.varint(sequence)
            case PathChallenge(data):
                self.varint(FrameType.PATH_CHALLENGE)
                self._data += data
            case PathResponse(data):
                self.varint(FrameType.PATH_RESPONSE)
                self._data += data
            case ConnectionClose(error, frame_type, reason, application):
                self.varint(
                    FrameType.APPLICATION_CLOSE
                    if application
                    else FrameType.CONNECTION_CLOSE
                )
                self.varint(error)
                if not application:
                    self.varint(frame_type or 0)
                self.varint(len(reason))
                self._data += reason
            case HandshakeDone():
                self.varint(FrameType.HANDSHAKE_DONE)
            case Datagram(data):
                self.varint(FrameType.DATAGRAM_WITH_LENGTH)
                self.varint(len(data))
                self._data += data


@dataclass(frozen=True, slots=True)
class Header:
    packet_type: PacketType
    version: int
    destination: bytes
    source: bytes
    token: bytes
    number_offset: int
    end: int
    supported_versions: tuple[int, ...] = ()
    retry_token: bytes = b""
    retry_tag: bytes = b""

    @classmethod
    def parse(cls, data: bytes, offset: int, destination_length: int) -> Header:
        reader = Reader(data, offset)
        first = reader.byte()
        if not first & FORM_LONG:
            destination = reader.take(destination_length)
            return cls(
                PacketType.ONE_RTT, 0, destination, b"", b"", reader.position, len(data)
            )
        version = int.from_bytes(reader.take(4), "big")
        destination = reader.take(reader.byte())
        source = reader.take(reader.byte())
        if version == 0:
            versions: list[int] = []
            while reader.remaining >= 4:
                versions.append(int.from_bytes(reader.take(4), "big"))
            return cls(
                PacketType.VERSION_NEGOTIATION,
                0,
                destination,
                source,
                b"",
                reader.position,
                len(data),
                tuple(versions),
            )
        try:
            quic_version = QuicVersion(version)
        except ValueError:
            raise ProtocolError(f"unknown QUIC version {version:#010x}") from None
        packet_type = PacketType.long(quic_version, (first >> 4) & 0x03)
        if packet_type is PacketType.RETRY:
            body = reader.rest()
            return cls(
                packet_type,
                version,
                destination,
                source,
                b"",
                reader.position,
                len(data),
                (),
                body[:-16],
                body[-16:],
            )
        token = (
            reader.take(reader.varint()) if packet_type is PacketType.INITIAL else b""
        )
        length = reader.varint()
        end = reader.position + length
        if end > len(data):
            raise ProtocolError("QUIC packet length exceeds the datagram")
        return cls(
            packet_type, version, destination, source, token, reader.position, end
        )

    @staticmethod
    def build(
        packet_type: PacketType,
        version: QuicVersion,
        destination: bytes,
        source: bytes,
        token: bytes,
        number: bytes,
        payload_length: int,
    ) -> bytes:
        first = (
            FORM_LONG | FIXED_BIT | (packet_type.code(version) << 4) | (len(number) - 1)
        )
        head = (
            bytes((first,))
            + version.to_bytes(4, "big")
            + bytes((len(destination),))
            + destination
            + bytes((len(source),))
            + source
        )
        if packet_type is PacketType.INITIAL:
            head += Writer.encode_varint(len(token)) + token
        # the length always takes two bytes so that a header's size is known before its payload is built
        return (
            head + (0x4000 | (len(number) + payload_length)).to_bytes(2, "big") + number
        )

    @staticmethod
    def build_short(destination: bytes, number: bytes, key_phase: bool) -> bytes:
        return (
            bytes(
                (FIXED_BIT | (KEY_PHASE_BIT if key_phase else 0) | (len(number) - 1),)
            )
            + destination
            + number
        )
