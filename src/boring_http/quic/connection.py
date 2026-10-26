import secrets
from collections import deque
from dataclasses import dataclass
from enum import IntEnum

from boring_ssl2 import (
    ClientContext,
    EncryptionLevel,
    PacketProtection,
    QuicHandshake,
    QuicVersion,
)
from ssl2 import NextProtocol, TLSError

from boring_http.errors import ConnectError, ProtocolError
from boring_http.quic.packet import (
    ACK_ELICITING_EXCLUSIONS,
    FORM_LONG,
    Ack,
    ConnectionClose,
    Crypto,
    DataBlocked,
    Datagram,
    Frame,
    HandshakeDone,
    Header,
    MaxData,
    MaxStreamData,
    MaxStreams,
    NewConnectionId,
    NewToken,
    PacketType,
    Padding,
    PathChallenge,
    PathResponse,
    Ping,
    Reader,
    ResetStream,
    RetireConnectionId,
    StopSending,
    Stream,
    StreamDataBlocked,
    StreamsBlocked,
    TransportError,
    Writer,
)
from boring_http.quic.recovery import GRANULARITY, Recovery, SentPacket
from boring_http.quic.streams import ReceiveStream, SendStream

DATAGRAM_SIZE = 1200
# RFC 9000 section 14.2: what a 1500 byte link carries under IPv6 and UDP headers
PROBED_DATAGRAM_SIZE = 1452
TAG_LENGTH = 16
SAMPLE_LENGTH = 16
CRYPTO_STREAM = -1
MAX_BURST = 10
ACK_THRESHOLD = 2
PACING_GAIN = 1.25
INTERNAL_ERROR_ALERT = 80
LEVEL_OF = {
    PacketType.INITIAL: EncryptionLevel.INITIAL,
    PacketType.ZERO_RTT: EncryptionLevel.EARLY_DATA,
    PacketType.HANDSHAKE: EncryptionLevel.HANDSHAKE,
    PacketType.ONE_RTT: EncryptionLevel.APPLICATION,
}
PACKET_TYPE_OF = {
    EncryptionLevel.INITIAL: PacketType.INITIAL,
    EncryptionLevel.EARLY_DATA: PacketType.ZERO_RTT,
    EncryptionLevel.HANDSHAKE: PacketType.HANDSHAKE,
    EncryptionLevel.APPLICATION: PacketType.ONE_RTT,
}


class Parameter(IntEnum):
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


EARLY_DATA_LIMITS = (
    Parameter.INITIAL_MAX_DATA,
    Parameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
    Parameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
    Parameter.INITIAL_MAX_STREAM_DATA_UNI,
    Parameter.INITIAL_MAX_STREAMS_BIDI,
    Parameter.INITIAL_MAX_STREAMS_UNI,
)
# RFC 9000 section 7.4.1: values a client must take from the new handshake, never from the previous one
NEVER_REMEMBERED = (
    Parameter.ACK_DELAY_EXPONENT,
    Parameter.MAX_ACK_DELAY,
    Parameter.ACTIVE_CONNECTION_ID_LIMIT,
    Parameter.INITIAL_SOURCE_CONNECTION_ID,
    Parameter.ORIGINAL_DESTINATION_CONNECTION_ID,
    Parameter.RETRY_SOURCE_CONNECTION_ID,
)
# RFC 9000 section 18.2 and RFC 9221 section 3: the values a peer assumes when a parameter is absent
ABSENT = {
    Parameter.MAX_IDLE_TIMEOUT: 0,
    Parameter.MAX_UDP_PAYLOAD_SIZE: 65527,
    Parameter.INITIAL_MAX_DATA: 0,
    Parameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: 0,
    Parameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: 0,
    Parameter.INITIAL_MAX_STREAM_DATA_UNI: 0,
    Parameter.INITIAL_MAX_STREAMS_BIDI: 0,
    Parameter.INITIAL_MAX_STREAMS_UNI: 0,
    Parameter.ACK_DELAY_EXPONENT: 3,
    Parameter.MAX_ACK_DELAY: 25,
    Parameter.ACTIVE_CONNECTION_ID_LIMIT: 2,
    Parameter.MAX_DATAGRAM_FRAME_SIZE: 0,
}


@dataclass(frozen=True, slots=True)
class TransportParameters:
    max_idle_timeout: int
    max_udp_payload_size: int
    initial_max_data: int
    initial_max_stream_data_bidi_local: int
    initial_max_stream_data_bidi_remote: int
    initial_max_stream_data_uni: int
    initial_max_streams_bidi: int
    initial_max_streams_uni: int
    order: tuple[Parameter, ...]
    ack_delay_exponent: int = ABSENT[Parameter.ACK_DELAY_EXPONENT]
    max_ack_delay: int = ABSENT[Parameter.MAX_ACK_DELAY]
    active_connection_id_limit: int = ABSENT[Parameter.ACTIVE_CONNECTION_ID_LIMIT]
    max_datagram_frame_size: int = ABSENT[Parameter.MAX_DATAGRAM_FRAME_SIZE]
    google_connection_options: tuple[bytes, ...] = ()
    initial_round_trip_time: int | None = None
    grease: bool = False
    grease_version: bool = False
    shuffle: bool = False

    def __post_init__(self) -> None:
        # a value left out of order never reaches the peer, which then works from the absent value instead
        applied = {
            parameter: value != ABSENT[parameter]
            for parameter, value in self._integers.items()
        } | {
            Parameter.VERSION_INFORMATION: self.grease_version,
            Parameter.GOOGLE_CONNECTION_OPTIONS: bool(self.google_connection_options),
            Parameter.INITIAL_ROUND_TRIP_TIME: self.initial_round_trip_time is not None,
        }
        unsent = [
            parameter.name
            for parameter, changed in applied.items()
            if changed and parameter not in self.order
        ]
        if unsent:
            raise ValueError(f"{', '.join(unsent)} must be in order to take effect")

    @property
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
        writer = Writer()
        integers = self._integers
        pairs: list[tuple[int, bytes]] = []
        for parameter in self.order:
            if parameter in integers:
                value = Writer.encode_varint(integers[parameter])
            elif parameter is Parameter.INITIAL_SOURCE_CONNECTION_ID:
                value = source_connection_id
            elif parameter is Parameter.VERSION_INFORMATION:
                available: list[int] = list(versions)
                if self.grease_version:
                    # RFC 9368 section 2.1: a reserved version at a random place among the available ones
                    available.insert(
                        secrets.randbelow(len(available) + 1),
                        secrets.randbits(32) & 0xF0F0F0F0 | 0x0A0A0A0A,
                    )
                value = b"".join(
                    candidate.to_bytes(4, "big") for candidate in (version, *available)
                )
            elif parameter is Parameter.GREASE_QUIC_BIT:
                value = b""
            elif parameter is Parameter.GOOGLE_CONNECTION_OPTIONS:
                value = b"".join(self.google_connection_options)
            elif parameter is Parameter.INITIAL_ROUND_TRIP_TIME:
                microseconds = self.initial_round_trip_time or round_trip_time
                if microseconds is None:
                    continue
                value = Writer.encode_varint(microseconds)
            else:
                raise ValueError(f"{parameter.name} is not a parameter a client sends")
            pairs.append((parameter, value))
        if self.grease:
            # RFC 9000 section 18.1: a reserved identifier the peer must ignore
            pairs.insert(
                secrets.randbelow(len(pairs) + 1),
                (
                    31 * secrets.randbelow((1 << 62) // 31) + 27,
                    secrets.token_bytes(secrets.randbelow(16)),
                ),
            )
        if self.shuffle:
            secrets.SystemRandom().shuffle(pairs)
        for identifier, value in pairs:
            writer.varint(identifier)
            writer.varint(len(value))
            writer.put(value)
        return writer.finish()


class PeerParameters:
    def __init__(self, data: bytes) -> None:
        self.raw: dict[int, bytes] = {}
        reader = Reader(data)
        while reader.remaining:
            identifier = reader.varint()
            self.raw[identifier] = reader.take(reader.varint())

    def integer(self, parameter: Parameter, default: int) -> int:
        value = self.raw.get(parameter)
        return default if value is None else Reader(value).varint()

    def connection_id(self, parameter: Parameter) -> bytes | None:
        return self.raw.get(parameter)


@dataclass(frozen=True, slots=True)
class StreamDataReceived:
    stream_id: int
    data: bytes
    end: bool


@dataclass(frozen=True, slots=True)
class StreamReset:
    stream_id: int
    error: int


@dataclass(frozen=True, slots=True)
class StopSendingReceived:
    stream_id: int
    error: int


@dataclass(frozen=True, slots=True)
class HandshakeCompleted:
    pass


@dataclass(frozen=True, slots=True)
class ConnectionTerminated:
    error: int
    reason: str
    application: bool


@dataclass(frozen=True, slots=True)
class VersionNegotiated:
    version: QuicVersion


@dataclass(frozen=True, slots=True)
class EarlyDataAvailable:
    pass


@dataclass(frozen=True, slots=True)
class EarlyDataRejected:
    pass


@dataclass(frozen=True, slots=True)
class DatagramReceived:
    data: bytes


type Event = (
    StreamDataReceived
    | StreamReset
    | StopSendingReceived
    | HandshakeCompleted
    | ConnectionTerminated
    | DatagramReceived
    | VersionNegotiated
    | EarlyDataAvailable
    | EarlyDataRejected
)


class QuicConnection:
    def __init__(
        self,
        context: ClientContext,
        server_name: str,
        parameters: TransportParameters,
        now: float,
        *,
        version: QuicVersion = QuicVersion.V1,
        token: bytes = b"",
        remembered: bytes = b"",
        round_trip_time: int | None = None,
    ) -> None:
        # RFC 9368: the first flight is always v1; a preferred v2 is offered in version_information and the server may switch
        self._version = QuicVersion.V1
        self._available = (
            (version, QuicVersion.V1) if version is not QuicVersion.V1 else (version,)
        )
        self._parameters = parameters
        self._source_id = PacketProtection.random(8)
        self._destination_id = PacketProtection.random(8)
        self._original_destination = self._destination_id
        self._retry_source: bytes | None = None
        self._token = token
        self._server_name = server_name
        self._context = context
        self._handshake = QuicHandshake(
            context,
            server_name,
            parameters.encode(
                self._source_id, self._version, self._available, round_trip_time
            ),
            remembered,
        )
        self._recovery = Recovery(DATAGRAM_SIZE)
        send, receive = PacketProtection.initial(self._version, self._destination_id)
        self._keys: dict[
            EncryptionLevel, tuple[PacketProtection | None, PacketProtection | None]
        ] = {EncryptionLevel.INITIAL: (receive, send)}
        self._next_keys: PacketProtection | None = None
        self._key_phase = False
        self._crypto_send: dict[EncryptionLevel, SendStream] = {
            level: SendStream(CRYPTO_STREAM, 1 << 62) for level in EncryptionLevel
        }
        self._crypto_receive: dict[EncryptionLevel, ReceiveStream] = {
            level: ReceiveStream(CRYPTO_STREAM, 1 << 62) for level in EncryptionLevel
        }
        self._send_streams: dict[int, SendStream] = {}
        self._receive_streams: dict[int, ReceiveStream] = {}
        # streams holding data the application has not been handed yet, in arrival order
        self._readable: dict[int, ReceiveStream] = {}
        self._next_bidi = 0
        self._next_uni = 2
        self._peer_max_streams = {True: 0, False: 0}
        self._local_max_streams = {
            True: parameters.initial_max_streams_bidi,
            False: parameters.initial_max_streams_uni,
        }
        self._peer_opened = {True: 0, False: 0}
        self._peer: PeerParameters | None = None
        self._peer_max_data = 0
        self._data_sent = 0
        self._local_max_data = parameters.initial_max_data
        self._data_received = 0
        self._pending: dict[EncryptionLevel, list[Frame]] = {
            level: [] for level in EncryptionLevel
        }
        self._events: deque[Event] = deque()
        self._handshake_done = False
        self._handshake_confirmed = False
        self._datagram_size = DATAGRAM_SIZE
        self._mtu_probe: int | None = None
        self._closing: ConnectionClose | None = None
        self._close_sent = False
        self._terminated = False
        self._idle_timeout: float | None = parameters.max_idle_timeout / 1000 or None
        self._last_activity = now
        self._ack_timer: float | None = None
        self._peer_connection_ids: dict[int, tuple[bytes, bytes]] = {}
        self._retire_prior_to = 0
        self._datagrams_out: deque[bytes] = deque()
        self._probe_levels: deque[EncryptionLevel] = deque()
        self._initial_hello = b""
        self.new_token: bytes = b""
        self.alpn: NextProtocol | bytes | None = None
        self.early_data = self._handshake.early_data_offered
        if self.early_data:
            # 0-RTT runs under the limits the server granted last time until the handshake brings the new ones
            granted = PeerParameters(self._handshake.remembered_transport_parameters)
            for parameter in NEVER_REMEMBERED:
                granted.raw.pop(parameter, None)
            self._apply_peer_parameters(granted)
        self._drive_handshake()

    @property
    def handshake_complete(self) -> bool:
        return self._handshake_done

    @property
    def early_data_pending(self) -> bool:
        return self.early_data and not self._handshake_done

    @property
    def peer_transport_parameters(self) -> bytes:
        return (
            self._handshake.peer_transport_parameters if self._handshake_done else b""
        )

    @property
    def round_trip_time(self) -> int:
        return int(self._recovery.smoothed_rtt * 1_000_000)

    @property
    def version(self) -> int:
        return self._version

    @property
    def peer_chain(self) -> tuple[bytes, ...]:
        return self._handshake.buffer.getpeerchain()

    @property
    def terminated(self) -> bool:
        return self._terminated

    @property
    def peer_certificate(self) -> bytes | None:
        return self._handshake.buffer.getpeercert()

    def next_event(self) -> Event | None:
        if self._events:
            return self._events.popleft()
        if self._readable:
            # one event carries everything a stream received since the last read, not one event per packet
            stream_id = next(iter(self._readable))
            receive = self._readable.pop(stream_id)
            chunks, receive.chunks = receive.chunks, []
            return StreamDataReceived(
                stream_id,
                chunks[0] if len(chunks) == 1 else b"".join(chunks),
                receive.final_size is not None
                and receive.next_offset == receive.final_size,
            )
        return None

    def can_open_stream(self, *, bidirectional: bool = True) -> bool:
        return (
            self._next_bidi if bidirectional else self._next_uni
        ) // 4 < self._peer_max_streams[bidirectional]

    def open_stream(self, *, bidirectional: bool = True) -> int:
        if not self.can_open_stream(bidirectional=bidirectional):
            raise ConnectError("the server allows no more streams right now")
        if bidirectional:
            stream_id, self._next_bidi = self._next_bidi, self._next_bidi + 4
        else:
            stream_id, self._next_uni = self._next_uni, self._next_uni + 4
        limit = self._peer_parameter(
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
            if bidirectional
            else Parameter.INITIAL_MAX_STREAM_DATA_UNI,
            0,
        )
        self._send_streams[stream_id] = SendStream(stream_id, limit)
        if bidirectional:
            self._receive_streams[stream_id] = ReceiveStream(
                stream_id, self._parameters.initial_max_stream_data_bidi_local
            )
        return stream_id

    def send_stream_data(
        self, stream_id: int, data: bytes, *, end: bool = False
    ) -> None:
        stream = self._send_streams[stream_id]
        stream.write(data)
        if end:
            stream.end()

    def unsent(self, stream_id: int) -> int:
        stream = self._send_streams.get(stream_id)
        return 0 if stream is None else stream.unsent

    def stream_read(self, stream_id: int, size: int) -> bool:
        # the stream window opens again as the application takes data, so a reader that stops holds the server at one window
        receive = self._receive_streams.get(stream_id)
        if receive is None or receive.final_size is not None:
            return False
        receive.read += size
        window = (
            self._parameters.initial_max_stream_data_bidi_local
            if stream_id % 4 < 2
            else self._parameters.initial_max_stream_data_uni
        )
        if receive.max_data - receive.read >= window // 2:
            return False
        receive.max_data = receive.read + window
        self._pending[EncryptionLevel.APPLICATION].append(
            MaxStreamData(stream_id, receive.max_data)
        )
        return True

    def reset_stream(self, stream_id: int, error: int) -> None:
        stream = self._send_streams.get(stream_id)
        if stream is not None and not stream.reset_sent:
            stream.reset_error = error
            stream.reset_sent = True
            stream.pending.clear()
            self._pending[EncryptionLevel.APPLICATION].append(
                ResetStream(stream_id, error, stream.offset)
            )

    def stop_sending(self, stream_id: int, error: int) -> None:
        stream = self._receive_streams.get(stream_id)
        if stream is not None and not stream.stop_sent:
            stream.stop_sent = True
            self._pending[EncryptionLevel.APPLICATION].append(
                StopSending(stream_id, error)
            )

    def send_datagram(self, data: bytes) -> None:
        self._pending[EncryptionLevel.APPLICATION].append(Datagram(data))

    def close(
        self, error: int = 0, reason: str = "", *, application: bool = True
    ) -> None:
        if self._closing is None and not self._terminated:
            self._closing = ConnectionClose(error, None, reason.encode(), application)

    def datagram_received(self, data: bytes, now: float) -> None:
        if self._terminated:
            return
        self._last_activity = now
        offset = 0
        size = len(data)
        while offset < size:
            if not data[offset] & FORM_LONG:
                # a short header packet is the last in its datagram; only where its number starts matters here
                keys = self._keys.get(EncryptionLevel.APPLICATION)
                if keys is not None and keys[0] is not None:
                    self._receive_packet(
                        data,
                        offset,
                        offset + 1 + len(self._source_id),
                        size,
                        EncryptionLevel.APPLICATION,
                        keys[0],
                        now,
                        b"",
                    )
                return
            try:
                header = Header.parse(data, offset, len(self._source_id))
            except ProtocolError:
                return
            if header.packet_type is PacketType.VERSION_NEGOTIATION:
                self._on_version_negotiation(header)
                return
            if header.packet_type is PacketType.RETRY:
                self._on_retry(header, data[offset:])
                return
            if header.version != self._version:
                if header.version not in self._available or self._handshake_done:
                    return
                self._switch_version(header.version)
            level = LEVEL_OF[header.packet_type]
            keys = self._keys.get(level)
            if keys is None or keys[0] is None:
                offset = header.end
                continue
            self._receive_packet(
                data,
                offset,
                header.number_offset,
                header.end,
                level,
                keys[0],
                now,
                header.source,
            )
            offset = header.end

    def datagrams_to_send(self, now: float) -> list[bytes]:
        if self._terminated:
            return []
        if self._closing is not None:
            if self._close_sent:
                return []
            self._close_sent = True
            datagram = self._close_datagram(now)
            self._terminated = True
            self._events.append(
                ConnectionTerminated(
                    self._closing.error,
                    self._closing.reason.decode("utf-8", "replace"),
                    self._closing.application,
                )
            )
            return [datagram] if datagram else []
        datagrams: list[bytes] = []
        while len(datagrams) < MAX_BURST:
            datagram = self._build_datagram(now)
            if datagram is None:
                break
            datagrams.append(datagram)
        if datagrams:
            self._last_activity = now
        return datagrams

    def pacing_delay(self, size: int) -> float:
        # RFC 9002 section 7.7: spread a window over a round trip instead of sending it as one burst
        recovery = self._recovery
        rate = (
            PACING_GAIN
            * max(recovery.window, 2 * DATAGRAM_SIZE)
            / max(recovery.smoothed_rtt, GRANULARITY)
        )
        return size / rate

    def datagram_too_long(self) -> None:
        # the kernel refused a datagram for its size, so from here on only the size every path carries goes out
        self._datagram_size = DATAGRAM_SIZE
        self._mtu_probe = None

    def next_timer(self) -> float | None:
        candidates: list[float] = []
        if self._idle_timeout is not None:
            candidates.append(self._last_activity + self._idle_timeout)
        if self._ack_timer is not None:
            candidates.append(self._ack_timer)
        timer = self._recovery.loss_timer(EncryptionLevel.HANDSHAKE in self._keys)
        if timer is not None:
            candidates.append(timer[0])
        return min(candidates, default=None)

    def handle_timer(self, now: float) -> None:
        if self._terminated:
            return
        if (
            self._idle_timeout is not None
            and now >= self._last_activity + self._idle_timeout
        ):
            self._terminated = True
            self._events.append(
                ConnectionTerminated(TransportError.NO_ERROR, "idle timeout", False)
            )
            return
        if self._ack_timer is not None and now >= self._ack_timer:
            self._ack_timer = None
            self._recovery.space(EncryptionLevel.APPLICATION).ack_pending = True
        timer = self._recovery.loss_timer(EncryptionLevel.HANDSHAKE in self._keys)
        if timer is None or now < timer[0]:
            return
        _, level, is_loss = timer
        if is_loss:
            for packet in self._recovery.detect_lost(level, now):
                self._on_lost(EncryptionLevel(level), packet)
            return
        self._recovery.on_pto()
        wanted = EncryptionLevel(level)
        if (
            wanted is EncryptionLevel.APPLICATION
            and wanted not in self._keys
            and EncryptionLevel.EARLY_DATA in self._keys
        ):
            wanted = EncryptionLevel.EARLY_DATA
        probe_level = wanted if wanted in self._keys else next(iter(self._keys))
        self._resend_unacknowledged(probe_level)
        self._probe_levels.extend((probe_level, probe_level))

    def _resend_unacknowledged(self, level: EncryptionLevel) -> None:
        # RFC 9002 section 6.2.4: a probe carries unacknowledged data again; a bare PING tells a server that lost the first flight nothing
        space = self._recovery.space(self._space_of(level))
        unacknowledged = [
            packet for _, packet in sorted(space.sent.items()) if packet.ack_eliciting
        ]
        # the handshake flights are small and go out whole; afterwards the oldest packet alone is enough
        for packet in (
            unacknowledged
            if level is not EncryptionLevel.APPLICATION
            else unacknowledged[:1]
        ):
            del space.sent[packet.number]
            if packet.in_flight:
                self._recovery.bytes_in_flight -= packet.size
            self._on_lost(self._space_of(level), packet)

    def _receive_packet(
        self,
        data: bytes,
        offset: int,
        number_offset: int,
        end: int,
        level: EncryptionLevel,
        keys: PacketProtection,
        now: float,
        source: bytes,
    ) -> None:
        if end - number_offset < 4 + SAMPLE_LENGTH:
            return
        mask = keys.mask(data[number_offset + 4 : number_offset + 4 + SAMPLE_LENGTH])
        first = data[offset] ^ (mask[0] & (0x0F if data[offset] & 0x80 else 0x1F))
        length = (first & 0x03) + 1
        truncated = int.from_bytes(
            data[number_offset : number_offset + length]
        ) ^ int.from_bytes(mask[1 : 1 + length])
        number = self._recovery.space(level).decode_number(truncated, length * 8)
        protected = (
            bytes((first,))
            + data[offset + 1 : number_offset]
            + truncated.to_bytes(length)
        )
        ciphertext = data[number_offset + length : end]
        if (
            level is EncryptionLevel.APPLICATION
            and bool(first & 0x04) != self._key_phase
        ):
            candidate = self._next_keys or keys.update()
            try:
                payload = candidate.open(number, protected, ciphertext)
            except ValueError:
                return
            self._next_keys = None
            self._key_phase = not self._key_phase
            send = self._keys[level][1]
            self._keys[level] = (candidate, send.update() if send is not None else None)
        else:
            try:
                payload = keys.open(number, protected, ciphertext)
            except ValueError:
                return
        if (
            level is EncryptionLevel.INITIAL
            and not self._handshake_done
            and self._destination_id in (self._original_destination, self._retry_source)
        ):
            self._destination_id = source
        self._process_payload(level, number, payload, now)

    def _process_payload(
        self, level: EncryptionLevel, number: int, payload: bytes, now: float
    ) -> None:
        reader = Reader(payload)
        ack_eliciting = False
        while reader.remaining:
            frame = reader.frame()
            if not isinstance(frame, ACK_ELICITING_EXCLUSIONS):
                ack_eliciting = True
            match frame:
                case Stream():
                    self._on_stream(frame)
                case Ack():
                    self._on_ack(level, frame, now)
                case Crypto(offset, data):
                    received = self._crypto_receive[level].on_frame(
                        Stream(CRYPTO_STREAM, offset, data, False)
                    )
                    if received:
                        self._handshake.provide(level, received)
                        if self._handshake_done:
                            # NewSessionTicket and the other post-handshake messages; this is what fills the session cache
                            self._handshake.process_post_handshake()
                        else:
                            self._drive_handshake()
                case MaxData(maximum):
                    self._peer_max_data = max(self._peer_max_data, maximum)
                case MaxStreamData(stream_id, maximum):
                    stream = self._send_streams.get(stream_id)
                    if stream is not None:
                        stream.max_data = max(stream.max_data, maximum)
                case MaxStreams(bidirectional, maximum):
                    self._peer_max_streams[bidirectional] = max(
                        self._peer_max_streams[bidirectional], maximum
                    )
                case NewConnectionId(
                    sequence, retire_prior_to, connection_id, reset_token
                ):
                    self._peer_connection_ids[sequence] = (connection_id, reset_token)
                    for old in [
                        key
                        for key in self._peer_connection_ids
                        if key < retire_prior_to
                    ]:
                        del self._peer_connection_ids[old]
                        self._pending[EncryptionLevel.APPLICATION].append(
                            RetireConnectionId(old)
                        )
                case ResetStream(stream_id, error, _):
                    stream = self._receive_streams.pop(stream_id, None)
                    if stream is not None:
                        self._events.append(StreamReset(stream_id, error))
                case StopSending(stream_id, error):
                    self.reset_stream(stream_id, error)
                    self._events.append(StopSendingReceived(stream_id, error))
                case NewToken(token):
                    self.new_token = token
                case PathChallenge(challenge):
                    self._pending[EncryptionLevel.APPLICATION].append(
                        PathResponse(challenge)
                    )
                case ConnectionClose(error, _, reason, application):
                    self._terminated = True
                    self._events.append(
                        ConnectionTerminated(
                            error, reason.decode("utf-8", "replace"), application
                        )
                    )
                    return
                case HandshakeDone():
                    self._confirm_handshake()
                case Datagram(data):
                    self._events.append(DatagramReceived(data))
                case (
                    Padding()
                    | Ping()
                    | PathResponse()
                    | DataBlocked()
                    | StreamDataBlocked()
                    | StreamsBlocked()
                    | RetireConnectionId()
                ):
                    pass
        space = self._recovery.space(level)
        in_order = space.record_received(number, now, ack_eliciting)
        if ack_eliciting:
            # RFC 9000 section 13.2.1: an ACK after every second ack-eliciting packet, at once when one arrives out of order
            if (
                level is not EncryptionLevel.APPLICATION
                or not in_order
                or space.ack_eliciting_received >= ACK_THRESHOLD
            ):
                space.ack_pending = True
                self._ack_timer = None
            elif self._ack_timer is None:
                self._ack_timer = now + self._parameters.max_ack_delay / 1000

    def _on_ack(self, level: EncryptionLevel, ack: Ack, now: float) -> None:
        exponent = self._peer_parameter(Parameter.ACK_DELAY_EXPONENT, 3)
        acked, lost = self._recovery.on_ack_received(level, ack, now, exponent)
        space = self._recovery.space(level)
        for packet in acked:
            if packet.mtu_probe:
                # the path carried the probe, so every datagram from here on may be that large
                self._datagram_size = packet.size
            for frame in packet.frames:
                if isinstance(frame, Ack):
                    space.forget(frame.largest)
                elif isinstance(frame, Stream):
                    self._stream_acked(frame.stream_id)
                elif isinstance(frame, ResetStream):
                    self._send_streams.pop(frame.stream_id, None)
        for packet in lost:
            self._on_lost(level, packet)
        # RFC 9001 section 4.1.2: an acknowledgement of a 1-RTT packet confirms the handshake; one of a 0-RTT packet does not
        if (
            level is EncryptionLevel.APPLICATION
            and self._handshake_done
            and not self._handshake_confirmed
            and any(not packet.early for packet in acked)
        ):
            self._confirm_handshake()

    def _stream_acked(self, stream_id: int) -> None:
        stream = self._send_streams.get(stream_id)
        if stream is None:
            return
        stream.unacked -= 1
        if stream.fin_sent and not stream.pending and stream.unacked == 0:
            del self._send_streams[stream_id]

    def _on_lost(self, level: EncryptionLevel, packet: SentPacket) -> None:
        for frame in packet.frames:
            match frame:
                case Crypto(offset, data):
                    self._crypto_send[level].requeue(
                        Stream(CRYPTO_STREAM, offset, data, False)
                    )
                case Stream():
                    stream = self._send_streams.get(frame.stream_id)
                    if stream is not None and not stream.reset_sent:
                        stream.requeue(frame)
                case Ack() | Ping() | Padding() | PathResponse() | Datagram():
                    pass
                case _:
                    self._pending[level].append(frame)

    def _on_stream(self, frame: Stream) -> None:
        stream_id = frame.stream_id
        client_initiated = stream_id % 2 == 0
        bidirectional = stream_id % 4 < 2
        if client_initiated and not bidirectional:
            raise ProtocolError(
                f"the server sent data on our unidirectional stream {stream_id}"
            )
        receive = self._receive_streams.get(stream_id)
        if receive is None:
            if client_initiated:
                return
            if stream_id // 4 >= self._local_max_streams[bidirectional]:
                raise ProtocolError("the server opened more streams than allowed")
            limit = (
                self._parameters.initial_max_stream_data_bidi_remote
                if bidirectional
                else self._parameters.initial_max_stream_data_uni
            )
            receive = self._receive_streams[stream_id] = ReceiveStream(stream_id, limit)
            self._peer_opened[bidirectional] = max(
                self._peer_opened[bidirectional], stream_id // 4 + 1
            )
            if bidirectional:
                self._send_streams[stream_id] = SendStream(
                    stream_id,
                    self._peer_parameter(
                        Parameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 0
                    ),
                )
            if (
                self._peer_opened[bidirectional] * 2
                > self._local_max_streams[bidirectional]
            ):
                self._local_max_streams[bidirectional] += (
                    self._parameters.initial_max_streams_bidi
                    if bidirectional
                    else self._parameters.initial_max_streams_uni
                )
                self._pending[EncryptionLevel.APPLICATION].append(
                    MaxStreams(bidirectional, self._local_max_streams[bidirectional])
                )
        before = receive.next_offset
        data = receive.on_frame(frame)
        self._data_received += receive.next_offset - before
        end = (
            receive.final_size is not None and receive.next_offset == receive.final_size
        )
        if data or end:
            if data:
                receive.chunks.append(data)
            self._readable[stream_id] = receive
            if end:
                del self._receive_streams[stream_id]
        if (
            self._data_received
            > self._local_max_data - self._parameters.initial_max_data // 2
        ):
            self._local_max_data = (
                self._data_received + self._parameters.initial_max_data
            )
            self._pending[EncryptionLevel.APPLICATION].append(
                MaxData(self._local_max_data)
            )

    def _drive_handshake(self) -> None:
        try:
            done = self._handshake.advance()
        except TLSError as error:
            # the peer gets the TLS alert in a CONNECTION_CLOSE and the caller gets the reason when it goes out
            alert = (
                self._handshake.alert[1]
                if self._handshake.alert is not None
                else INTERNAL_ERROR_ALERT
            )
            self._closing = ConnectionClose(
                TransportError.CRYPTO_ERROR + alert,
                None,
                f"TLS handshake failed: {error}".encode(),
                False,
            )
            return
        for level, is_write, suite, secret in self._handshake.take_secrets():
            protection = PacketProtection(suite, secret, self._version)
            receive, send = self._keys.get(level, (None, None))
            self._keys[level] = (
                (receive, protection) if is_write else (protection, send)
            )
            if level is EncryptionLevel.EARLY_DATA:
                self._events.append(EarlyDataAvailable())
        for level in EncryptionLevel:
            data = self._handshake.take_outgoing(level)
            if data:
                self._crypto_send[level].write(data)
                if level is EncryptionLevel.INITIAL:
                    self._initial_hello += data
        if self._handshake.alert is not None:
            level, alert = self._handshake.alert
            self._closing = ConnectionClose(
                TransportError.CRYPTO_ERROR + alert, None, b"TLS alert", False
            )
        if done and not self._handshake_done:
            self._handshake_done = True
            peer = PeerParameters(self._handshake.peer_transport_parameters)
            if (
                peer.connection_id(Parameter.ORIGINAL_DESTINATION_CONNECTION_ID)
                != self._original_destination
            ):
                raise ProtocolError(
                    "the server's original_destination_connection_id does not match"
                )
            if (
                peer.connection_id(Parameter.INITIAL_SOURCE_CONNECTION_ID)
                != self._destination_id
            ):
                raise ProtocolError(
                    "the server's initial_source_connection_id does not match"
                )
            if (
                self._retry_source is not None
                and peer.connection_id(Parameter.RETRY_SOURCE_CONNECTION_ID)
                != self._retry_source
            ):
                raise ProtocolError(
                    "the server's retry_source_connection_id does not match"
                )
            information = peer.connection_id(Parameter.VERSION_INFORMATION)
            if information is not None and information[:4] != self._version.to_bytes(
                4, "big"
            ):
                # RFC 9368 section 4: the server's chosen version must be the one the packets carry
                raise ProtocolError(
                    "the server's version_information names another version"
                )
            if self._handshake.early_data_accepted and self._peer is not None:
                # RFC 9000 section 7.4.1: accepted 0-RTT data keeps the limits it was sent under
                for parameter in EARLY_DATA_LIMITS:
                    if peer.integer(parameter, 0) < self._peer.integer(parameter, 0):
                        raise ProtocolError(
                            f"the server lowered {parameter.name} below the value it granted for early data"
                        )
            self._apply_peer_parameters(peer)
            self.alpn = self._handshake.buffer.negotiated_protocol()
            if self._handshake.early_data_rejected:
                self._reject_early_data()
            if self.early_data:
                self._discard(EncryptionLevel.EARLY_DATA)
            self._events.append(HandshakeCompleted())

    def _apply_peer_parameters(self, peer: PeerParameters) -> None:
        self._peer = peer
        self._peer_max_data = peer.integer(Parameter.INITIAL_MAX_DATA, 0)
        self._peer_max_streams[True] = peer.integer(
            Parameter.INITIAL_MAX_STREAMS_BIDI, 0
        )
        self._peer_max_streams[False] = peer.integer(
            Parameter.INITIAL_MAX_STREAMS_UNI, 0
        )
        # RFC 9000 section 10.1: the smaller advertised timeout, where 0 means that side sets none
        timeouts = [
            value / 1000
            for value in (
                peer.integer(Parameter.MAX_IDLE_TIMEOUT, 0),
                self._parameters.max_idle_timeout,
            )
            if value
        ]
        self._idle_timeout = min(timeouts) if timeouts else None
        self._recovery.max_ack_delay = peer.integer(Parameter.MAX_ACK_DELAY, 25) / 1000

    def _reject_early_data(self) -> None:
        self._requeue_early_packets()
        self._events.append(EarlyDataRejected())

    def _requeue_early_packets(self) -> None:
        # RFC 9001 section 4.6.2: everything that went out in 0-RTT packets is sent again under the 1-RTT keys
        space = self._recovery.space(EncryptionLevel.APPLICATION)
        for packet in [packet for packet in space.sent.values() if packet.early]:
            del space.sent[packet.number]
            if packet.in_flight:
                self._recovery.bytes_in_flight -= packet.size
            self._on_lost(EncryptionLevel.APPLICATION, packet)

    def _confirm_handshake(self) -> None:
        if self._handshake_confirmed:
            return
        self._handshake_confirmed = True
        self._recovery.handshake_confirmed = True
        self._discard(EncryptionLevel.HANDSHAKE)
        target = min(
            PROBED_DATAGRAM_SIZE,
            self._peer_parameter(Parameter.MAX_UDP_PAYLOAD_SIZE, 65527),
        )
        if target > self._datagram_size:
            self._mtu_probe = target

    def _discard(self, level: EncryptionLevel) -> None:
        self._keys.pop(level, None)
        self._recovery.discard_space(level)
        self._crypto_send[level].pending.clear()
        self._pending[level].clear()

    def _peer_parameter(self, parameter: Parameter, default: int) -> int:
        return default if self._peer is None else self._peer.integer(parameter, default)

    def _switch_version(self, version: int) -> None:
        # RFC 9368 section 2.3: the server answered in another version we offered; the Initial keys follow it,
        # derived from the id the first flight went to, not from the id the server has chosen since
        self._version = QuicVersion(version)
        chosen = (
            self._original_destination
            if self._retry_source is None
            else self._retry_source
        )
        send, receive = PacketProtection.initial(self._version, chosen)
        self._keys[EncryptionLevel.INITIAL] = (receive, send)

    def _on_version_negotiation(self, header: Header) -> None:
        if self._version in header.supported_versions or self._handshake_done:
            return
        for candidate in QuicVersion:
            if candidate in header.supported_versions and candidate != self._version:
                self._terminated = True
                self._events.append(VersionNegotiated(candidate))
                return
        self._terminated = True
        self._events.append(
            ConnectionTerminated(
                TransportError.NO_ERROR, "no common QUIC version", False
            )
        )

    def _on_retry(self, header: Header, packet: bytes) -> None:
        if (
            self._retry_source is not None
            or self._handshake_done
            or header.destination != self._source_id
        ):
            return
        if (
            PacketProtection.retry_tag(
                self._version, self._destination_id, packet[:-TAG_LENGTH]
            )
            != header.retry_tag
        ):
            return
        self._retry_source = header.source
        self._token = header.retry_token
        self._destination_id = header.source
        send, receive = PacketProtection.initial(self._version, self._destination_id)
        self._keys[EncryptionLevel.INITIAL] = (receive, send)
        self._recovery.discard_space(EncryptionLevel.INITIAL)
        self._crypto_send[EncryptionLevel.INITIAL] = SendStream(CRYPTO_STREAM, 1 << 62)
        self._crypto_send[EncryptionLevel.INITIAL].write(self._initial_hello)
        # the server dropped the 0-RTT packets along with the Initial; they go again with the new connection id
        self._requeue_early_packets()

    def _build_datagram(self, now: float) -> bytes | None:
        if self._mtu_probe is not None:
            keys = self._keys.get(EncryptionLevel.APPLICATION)
            if (
                keys is not None
                and keys[1] is not None
                and self._recovery.can_send(self._mtu_probe)
            ):
                # RFC 9000 section 14.2.1: a padded PING in a datagram of its own asks the path whether it carries the size
                target, self._mtu_probe = self._mtu_probe, None
                built = self._build_packet(
                    EncryptionLevel.APPLICATION,
                    keys[1],
                    target,
                    now,
                    pad=True,
                    frames=(Ping(),),
                    probe=True,
                )
                if built is not None:
                    self._recovery.on_packet_sent(EncryptionLevel.APPLICATION, built[1])
                    return built[0]
        packets: list[tuple[EncryptionLevel, bytes, SentPacket]] = []
        remaining = self._datagram_size
        for level in (
            EncryptionLevel.INITIAL,
            EncryptionLevel.EARLY_DATA,
            EncryptionLevel.HANDSHAKE,
            EncryptionLevel.APPLICATION,
        ):
            keys = self._keys.get(level)
            if keys is None or keys[1] is None:
                continue
            built = self._build_packet(level, keys[1], remaining, now, pad=False)
            if built is not None:
                packets.append((level, built[0], built[1]))
                remaining -= len(built[0])
        if not packets:
            return None
        if packets[0][0] is EncryptionLevel.INITIAL and remaining > 0:
            level, _, record = packets[0]
            keys = self._keys[level]
            if keys[1] is not None:
                self._recovery.space(level).next_number -= 1
                rebuilt = self._build_packet(
                    level,
                    keys[1],
                    DATAGRAM_SIZE - sum(len(packet) for _, packet, _ in packets[1:]),
                    now,
                    pad=True,
                    frames=record.frames,
                )
                if rebuilt is not None:
                    packets[0] = (level, rebuilt[0], rebuilt[1])
        for level, _, record in packets:
            self._recovery.on_packet_sent(self._space_of(level), record)
            if (
                level is EncryptionLevel.HANDSHAKE
                and EncryptionLevel.INITIAL in self._keys
            ):
                self._discard(EncryptionLevel.INITIAL)
        return b"".join(packet for _, packet, _ in packets)

    @staticmethod
    def _space_of(level: EncryptionLevel) -> EncryptionLevel:
        # 0-RTT and 1-RTT packets share one packet number space
        return (
            EncryptionLevel.APPLICATION
            if level is EncryptionLevel.EARLY_DATA
            else level
        )

    def _build_packet(
        self,
        level: EncryptionLevel,
        keys: PacketProtection,
        space_left: int,
        now: float,
        *,
        pad: bool,
        frames: tuple[Frame, ...] | None = None,
        probe: bool = False,
    ) -> tuple[bytes, SentPacket] | None:
        space = self._recovery.space(self._space_of(level))
        number = space.next_number
        number_bytes = space.encode_number(number)
        overhead = self._header_length(level, len(number_bytes)) + TAG_LENGTH
        if space_left <= overhead + 4:
            return None
        capacity = space_left - overhead
        collected = (
            list(frames)
            if frames is not None
            else self._collect_frames(level, capacity, now)
        )
        if not collected:
            return None
        if len(collected) == 1 and isinstance(collected[0], Stream) and not pad:
            # a packet of one STREAM frame, the shape of every packet in an upload, needs no writer
            payload = Writer.stream_frame(collected[0])
        else:
            writer = Writer()
            for frame in collected:
                writer.frame(frame)
            if pad and len(writer) < capacity:
                collected.append(Padding(capacity - len(writer)))
                writer.frame(collected[-1])
            if len(writer) + len(number_bytes) < 4:
                padding = Padding(4 - len(writer) - len(number_bytes))
                collected.append(padding)
                writer.frame(padding)
            payload = writer.finish()
        header = self._header(level, number_bytes, len(payload) + TAG_LENGTH)
        sealed = keys.seal(number, header, payload)
        length = len(number_bytes)
        mask = keys.mask(sealed[4 - length : 4 - length + SAMPLE_LENGTH])
        first = header[0] ^ (mask[0] & (0x0F if header[0] & 0x80 else 0x1F))
        masked_number = (
            int.from_bytes(number_bytes) ^ int.from_bytes(mask[1 : 1 + length])
        ).to_bytes(length)
        packet = bytes((first,)) + header[1:-length] + masked_number + sealed
        space.next_number += 1
        ack_eliciting = in_flight = False
        for frame in collected:
            if not isinstance(frame, ACK_ELICITING_EXCLUSIONS):
                ack_eliciting = in_flight = True
                break
            if isinstance(frame, Padding):
                in_flight = True
        return packet, SentPacket(
            number,
            now,
            ack_eliciting,
            in_flight,
            len(packet),
            tuple(collected),
            level is EncryptionLevel.EARLY_DATA,
            probe,
        )

    def _collect_frames(
        self, level: EncryptionLevel, capacity: int, now: float
    ) -> list[Frame]:
        frames: list[Frame] = []
        used = 0
        early = level is EncryptionLevel.EARLY_DATA
        space = self._recovery.space(self._space_of(level))
        exponent = self._parameters.ack_delay_exponent
        # RFC 9000 section 12.5: a 0-RTT packet never carries an ACK frame
        if not early and (
            space.ack_pending
            or (
                space.received
                and level is not EncryptionLevel.APPLICATION
                and space.ack_eliciting_received
            )
        ):
            ack = space.ack_frame(now, exponent)
            if ack is not None:
                frames.append(ack)
                used += self._frame_length(ack)
                space.ack_pending = False
                space.ack_eliciting_received = 0
        if self._probe_levels and self._probe_levels[0] is level:
            self._probe_levels.popleft()
            frames.append(Ping())
            used += 1
        pending = self._pending[self._space_of(level)]
        for frame in list(pending):
            length = self._frame_length(frame)
            if used + length > capacity:
                break
            frames.append(frame)
            pending.remove(frame)
            used += length
        crypto = self._crypto_send[level]
        while crypto.active and used + 8 < capacity:
            frame = crypto.next_frame(capacity - used - 8, 1 << 62)
            if frame is None:
                break
            crypto_frame = Crypto(frame.offset, frame.data)
            frames.append(crypto_frame)
            used += self._frame_length(crypto_frame)
        if early or (level is EncryptionLevel.APPLICATION and self._handshake_done):
            for stream in list(self._send_streams.values()):
                if not stream.active or stream.reset_sent:
                    continue
                if not self._recovery.can_send(used + 32):
                    break
                while stream.active and used + 12 < capacity:
                    high = stream.sent_offset
                    frame = stream.next_frame(
                        capacity - used - 12, self._peer_max_data - self._data_sent
                    )
                    if frame is None:
                        if stream.blocked:
                            blocked = StreamDataBlocked(
                                stream.stream_id, stream.max_data
                            )
                            frames.append(blocked)
                            used += self._frame_length(blocked)
                            stream.blocked = False
                        break
                    frames.append(frame)
                    # a retransmission was charged to the connection window when it first went out
                    self._data_sent += stream.sent_offset - high
                    used += self._frame_length(frame)
        return frames

    def _close_datagram(self, now: float) -> bytes:
        if self._closing is None:
            return b""
        for level in (
            EncryptionLevel.APPLICATION,
            EncryptionLevel.HANDSHAKE,
            EncryptionLevel.INITIAL,
        ):
            keys = self._keys.get(level)
            if keys is None or keys[1] is None:
                continue
            close = (
                self._closing
                if level is EncryptionLevel.APPLICATION
                else ConnectionClose(
                    TransportError.APPLICATION_ERROR
                    if self._closing.application
                    else self._closing.error,
                    None,
                    b"",
                    False,
                )
            )
            built = self._build_packet(
                level,
                keys[1],
                DATAGRAM_SIZE,
                now,
                pad=level is EncryptionLevel.INITIAL,
                frames=(close,),
            )
            if built is not None:
                return built[0]
        return b""

    def _header_length(self, level: EncryptionLevel, number_length: int) -> int:
        if level is EncryptionLevel.APPLICATION:
            return 1 + len(self._destination_id) + number_length
        token = (
            len(Writer.encode_varint(len(self._token))) + len(self._token)
            if level is EncryptionLevel.INITIAL
            else 0
        )
        return (
            7
            + len(self._destination_id)
            + len(self._source_id)
            + token
            + 2
            + number_length
        )

    def _header(
        self, level: EncryptionLevel, number_bytes: bytes, remaining_length: int
    ) -> bytes:
        if level is EncryptionLevel.APPLICATION:
            return Header.build_short(
                self._destination_id, number_bytes, self._key_phase
            )
        return Header.build(
            PACKET_TYPE_OF[level],
            self._version,
            self._destination_id,
            self._source_id,
            self._token,
            number_bytes,
            remaining_length,
        )

    @staticmethod
    def _frame_length(frame: Frame) -> int:
        if isinstance(frame, Stream):
            # the common frame is sized without encoding its data twice
            size = len(frame.data)
            return (
                1
                + Writer.varint_length(frame.stream_id)
                + (Writer.varint_length(frame.offset) if frame.offset else 0)
                + Writer.varint_length(size)
                + size
            )
        writer = Writer()
        writer.frame(frame)
        return len(writer)
