import secrets
from dataclasses import dataclass
from enum import IntEnum

from boring_ssl2 import QuicVersion
from ssl2.errors import ConfigurationError
from ssl2.value import Value

from boring_http.quic.wire import Reader, Writer


class Parameter(IntEnum):
    # RFC 9000 section 18.2, RFC 9221, RFC 9287, RFC 9368 and Google's own
    ORIGINAL_DESTINATION_CONNECTION_ID = 0x00
    MAX_IDLE_TIMEOUT = 0x01
    STATELESS_RESET_TOKEN = 0x02
    MAX_UDP_PAYLOAD_SIZE = 0x03
    INITIAL_MAX_DATA = 0x04
    INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05
    INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06
    INITIAL_MAX_STREAM_DATA_UNI = 0x07
    INITIAL_MAX_STREAMS_BIDI = 0x08
    INITIAL_MAX_STREAMS_UNI = 0x09
    ACK_DELAY_EXPONENT = 0x0A
    MAX_ACK_DELAY = 0x0B
    DISABLE_ACTIVE_MIGRATION = 0x0C
    PREFERRED_ADDRESS = 0x0D
    ACTIVE_CONNECTION_ID_LIMIT = 0x0E
    INITIAL_SOURCE_CONNECTION_ID = 0x0F
    RETRY_SOURCE_CONNECTION_ID = 0x10
    VERSION_INFORMATION = 0x11
    MAX_DATAGRAM_FRAME_SIZE = 0x20
    GREASE_QUIC_BIT = 0x2AB2
    INITIAL_ROUND_TRIP_TIME = 0x3127
    GOOGLE_CONNECTION_OPTIONS = 0x3128

    @property
    def absent(self) -> int:
        # RFC 9000 section 18.2 and RFC 9221 section 3: the value a peer assumes when the parameter is left out
        match self:
            case Parameter.MAX_UDP_PAYLOAD_SIZE:
                return Absent.MAX_UDP_PAYLOAD_SIZE
            case Parameter.ACK_DELAY_EXPONENT:
                return Absent.ACK_DELAY_EXPONENT
            case Parameter.MAX_ACK_DELAY:
                return Absent.MAX_ACK_DELAY
            case Parameter.ACTIVE_CONNECTION_ID_LIMIT:
                return Absent.ACTIVE_CONNECTION_ID_LIMIT
            case _:
                return Absent.ZERO


class Absent(IntEnum):
    ZERO = 0
    MAX_UDP_PAYLOAD_SIZE = 65527
    ACK_DELAY_EXPONENT = 3
    MAX_ACK_DELAY = 25
    ACTIVE_CONNECTION_ID_LIMIT = 2


class Grease(IntEnum):
    # RFC 9000 section 18.1: a transport parameter id of the form 31 * N + 27 is reserved and ignored by the peer;
    # RFC 9368 section 2.1: a version of the form 0x?a?a?a?a is reserved
    PARAMETER_STEP = 31
    PARAMETER_OFFSET = 27
    PARAMETER_LIMIT = 1 << 62
    VALUE_LIMIT = 16
    VERSION_MASK = 0xF0F0F0F0
    VERSION_PATTERN = 0x0A0A0A0A
    VERSION_BITS = 32


@dataclass(frozen=True, slots=True)
class TransportParameters(Value):
    max_idle_timeout: int
    max_udp_payload_size: int
    initial_max_data: int
    initial_max_stream_data_bidi_local: int
    initial_max_stream_data_bidi_remote: int
    initial_max_stream_data_uni: int
    initial_max_streams_bidi: int
    initial_max_streams_uni: int
    # the parameters to send, in this order; a value left out of it never reaches the peer
    order: tuple[Parameter, ...]
    ack_delay_exponent: int = Absent.ACK_DELAY_EXPONENT
    max_ack_delay: int = Absent.MAX_ACK_DELAY
    active_connection_id_limit: int = Absent.ACTIVE_CONNECTION_ID_LIMIT
    max_datagram_frame_size: int = Absent.ZERO
    google_connection_options: tuple[bytes, ...] = ()
    initial_round_trip_time: int | None = None
    grease: bool = False
    grease_version: bool = False
    shuffle: bool = False

    def __post_init__(self) -> None:
        applied = {parameter: value != parameter.absent for parameter, value in self._integers().items()}
        applied[Parameter.VERSION_INFORMATION] = self.grease_version
        applied[Parameter.GOOGLE_CONNECTION_OPTIONS] = bool(self.google_connection_options)
        applied[Parameter.INITIAL_ROUND_TRIP_TIME] = self.initial_round_trip_time is not None
        unsent = [parameter.name for parameter, changed in applied.items() if changed and parameter not in self.order]
        if unsent:
            raise ConfigurationError(f"{', '.join(unsent)} must be in order to reach the peer")

    def _integers(self) -> dict[Parameter, int]:
        return {
            Parameter.MAX_IDLE_TIMEOUT: self.max_idle_timeout,
            Parameter.MAX_UDP_PAYLOAD_SIZE: self.max_udp_payload_size,
            Parameter.INITIAL_MAX_DATA: self.initial_max_data,
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: self.initial_max_stream_data_bidi_local,
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: self.initial_max_stream_data_bidi_remote,
            Parameter.INITIAL_MAX_STREAM_DATA_UNI: self.initial_max_stream_data_uni,
            Parameter.INITIAL_MAX_STREAMS_BIDI: self.initial_max_streams_bidi,
            Parameter.INITIAL_MAX_STREAMS_UNI: self.initial_max_streams_uni,
            Parameter.ACK_DELAY_EXPONENT: self.ack_delay_exponent,
            Parameter.MAX_ACK_DELAY: self.max_ack_delay,
            Parameter.ACTIVE_CONNECTION_ID_LIMIT: self.active_connection_id_limit,
            Parameter.MAX_DATAGRAM_FRAME_SIZE: self.max_datagram_frame_size,
        }

    def encode(
        self,
        source_connection_id: bytes,
        version: QuicVersion,
        versions: tuple[QuicVersion, ...],
        round_trip_time: int | None = None,
    ) -> bytes:
        integers = self._integers()
        pairs: list[tuple[int, bytes]] = []
        for parameter in self.order:
            match parameter:
                case Parameter.INITIAL_SOURCE_CONNECTION_ID:
                    value = source_connection_id
                case Parameter.VERSION_INFORMATION:
                    value = self._version_information(version, versions)
                case Parameter.GREASE_QUIC_BIT:
                    value = b""
                case Parameter.GOOGLE_CONNECTION_OPTIONS:
                    value = b"".join(self.google_connection_options)
                case Parameter.INITIAL_ROUND_TRIP_TIME:
                    microseconds = self.initial_round_trip_time or round_trip_time
                    if microseconds is None:
                        continue
                    value = Writer.encode_varint(microseconds)
                case _ if parameter in integers:
                    value = Writer.encode_varint(integers[parameter])
                case _:
                    raise ConfigurationError(f"{parameter.name} is not a parameter a client sends")
            pairs.append((parameter, value))
        if self.grease:
            identifier = Grease.PARAMETER_STEP * secrets.randbelow(Grease.PARAMETER_LIMIT // Grease.PARAMETER_STEP)
            pairs.insert(
                secrets.randbelow(len(pairs) + 1),
                (identifier + Grease.PARAMETER_OFFSET, secrets.token_bytes(secrets.randbelow(Grease.VALUE_LIMIT))),
            )
        if self.shuffle:
            secrets.SystemRandom().shuffle(pairs)
        writer = Writer()
        for identifier, value in pairs:
            writer.varint(identifier)
            writer.varint(len(value))
            writer.put(value)
        return writer.finish()

    def _version_information(self, version: QuicVersion, versions: tuple[QuicVersion, ...]) -> bytes:
        # RFC 9368 section 3: the version in use, then the ones available, a reserved one among them when asked
        available: list[int] = list(versions)
        if self.grease_version:
            reserved = secrets.randbits(Grease.VERSION_BITS) & Grease.VERSION_MASK | Grease.VERSION_PATTERN
            available.insert(secrets.randbelow(len(available) + 1), reserved)
        return b"".join(candidate.to_bytes(4, "big") for candidate in (version, *available))


class PeerParameters:
    # what the server sent, by identifier, read as needed
    def __init__(self, data: bytes) -> None:
        self.raw: dict[int, bytes] = {}
        reader = Reader(data)
        while reader.remaining:
            identifier = reader.varint()
            self.raw[identifier] = reader.take(reader.varint())

    def integer(self, parameter: Parameter) -> int:
        value = self.raw.get(parameter)
        return parameter.absent if value is None else Reader(value).varint()

    def connection_id(self, parameter: Parameter) -> bytes | None:
        return self.raw.get(parameter)

    def forget(self, parameter: Parameter) -> None:
        self.raw.pop(parameter, None)
