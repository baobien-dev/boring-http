import logging
from collections import deque
from dataclasses import dataclass
from enum import IntEnum

from boring_ssl2 import ClientContext, EncryptionLevel, PacketProtection, QuicHandshake, QuicVersion, TLSBuffer
from ssl2.errors import TLSError
from ssl2.registry import NextProtocol
from ssl2.value import Value

from boring_http.errors import ConnectError, ProtocolError
from boring_http.quic.packet import (
    Ack,
    Bit,
    ConnectionClose,
    Crypto,
    DataBlocked,
    Datagram,
    Frame,
    FrameReader,
    FrameWriter,
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
    ResetStream,
    RetireConnectionId,
    StopSending,
    Stream,
    StreamDataBlocked,
    StreamsBlocked,
    TransportError,
    Width,
)
from boring_http.quic.parameters import Parameter, PeerParameters, TransportParameters
from boring_http.quic.recovery import Recovery, SentPacket, Tuning
from boring_http.quic.streams import ReceiveStream, SendStream
from boring_http.quic.wire import Writer
from boring_http.tracing import Event


class Size(IntEnum):
    # RFC 9000 section 14: the datagram every path carries, and what a 1500 byte link carries under IPv6 and UDP
    DATAGRAM = 1200
    PROBED_DATAGRAM = 1452
    CONNECTION_ID = 8
    # RFC 9001 section 5.4.2: packet number and payload together must reach four bytes for the protection sample
    MINIMUM_PROTECTED = 4
    # room kept for the type, offset and length fields when a frame's data is cut to fit
    CRYPTO_FRAME_HEAD = 8
    STREAM_FRAME_HEAD = 12
    CONGESTION_RESERVE = 32
    CRYPTO_WINDOW = 1 << 62
    LONG_HEADER_FIXED = 7


class Limit(IntEnum):
    # datagrams per burst; ACK after every second ack-eliciting packet, RFC 9000 section 13.2.1
    BURST = 10
    ACK_THRESHOLD = 2
    STREAM_STEP = 4
    MILLISECONDS = 1000
    MICROSECONDS = 1_000_000
    TLS_INTERNAL_ERROR = 80


class Pacing:
    # RFC 9002 section 7.7: a little above the window per round trip, so the window is never the limit
    GAIN = 1.25


class StreamIdBit(IntEnum):
    # RFC 9000 section 2.1: the two low bits of a stream id name its initiator and direction
    SERVER_INITIATED = 0x01
    UNIDIRECTIONAL = 0x02
    SEQUENCE_SHIFT = 2


class LevelKeys:
    # the packet protection of one encryption level, one key per direction
    __slots__ = ("receive", "send")

    def __init__(self, receive: PacketProtection | None = None, send: PacketProtection | None = None) -> None:
        self.receive = receive
        self.send = send


@dataclass(frozen=True, slots=True)
class StreamDataReceived(Value):
    stream_id: int
    data: bytes
    end: bool


@dataclass(frozen=True, slots=True)
class StreamReset(Value):
    stream_id: int
    error: int


@dataclass(frozen=True, slots=True)
class StopSendingReceived(Value):
    stream_id: int
    error: int


@dataclass(frozen=True, slots=True)
class HandshakeCompleted(Value):
    pass


@dataclass(frozen=True, slots=True)
class ConnectionTerminated(Value):
    error: int
    reason: str
    application: bool


@dataclass(frozen=True, slots=True)
class VersionNegotiated(Value):
    version: QuicVersion


@dataclass(frozen=True, slots=True)
class EarlyDataAvailable(Value):
    pass


@dataclass(frozen=True, slots=True)
class EarlyDataRejected(Value):
    pass


@dataclass(frozen=True, slots=True)
class DatagramReceived(Value):
    data: bytes


type QuicEvent = (
    StreamDataReceived
    | StreamReset
    | StopSendingReceived
    | HandshakeCompleted
    | ConnectionTerminated
    | VersionNegotiated
    | EarlyDataAvailable
    | EarlyDataRejected
    | DatagramReceived
)


class QuicConnection:
    # RFC 9000 client side without any socket: datagrams in, datagrams and events out, time given by the caller
    logger = logging.getLogger("boring_http")
    # RFC 9000 section 7.4.1: what a client never takes from a remembered set of parameters
    NEVER_REMEMBERED = frozenset(
        {
            Parameter.ACK_DELAY_EXPONENT,
            Parameter.MAX_ACK_DELAY,
            Parameter.INITIAL_SOURCE_CONNECTION_ID,
            Parameter.ORIGINAL_DESTINATION_CONNECTION_ID,
            Parameter.PREFERRED_ADDRESS,
            Parameter.RETRY_SOURCE_CONNECTION_ID,
            Parameter.STATELESS_RESET_TOKEN,
            Parameter.VERSION_INFORMATION,
        }
    )
    # RFC 9000 section 7.4.1: the limits a server that accepts early data may not lower
    EARLY_DATA_LIMITS = (
        Parameter.ACTIVE_CONNECTION_ID_LIMIT,
        Parameter.INITIAL_MAX_DATA,
        Parameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        Parameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        Parameter.INITIAL_MAX_STREAM_DATA_UNI,
        Parameter.INITIAL_MAX_STREAMS_BIDI,
        Parameter.INITIAL_MAX_STREAMS_UNI,
    )
    SEND_ORDER = (
        EncryptionLevel.INITIAL,
        EncryptionLevel.EARLY_DATA,
        EncryptionLevel.HANDSHAKE,
        EncryptionLevel.APPLICATION,
    )

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
        library = context.library
        self._library = library
        self._parameters = parameters
        # RFC 9368: the first flight is always v1; another version is offered in version_information and the server may switch
        self._version = QuicVersion.V1
        self._offered = (version, QuicVersion.V1) if version is not QuicVersion.V1 else (version,)
        self._source_id = PacketProtection.random(library, Size.CONNECTION_ID)
        self._destination_id = PacketProtection.random(library, Size.CONNECTION_ID)
        self._original_destination = self._destination_id
        self._retry_source: bytes | None = None
        self._token = token
        self._handshake = QuicHandshake(
            context,
            server_name,
            parameters.encode(self._source_id, self._version, self._offered, round_trip_time),
            remembered,
        )
        self._recovery = Recovery(Size.DATAGRAM)
        client, server = PacketProtection.initial(library, self._version, self._destination_id)
        self._keys: dict[EncryptionLevel, LevelKeys] = {EncryptionLevel.INITIAL: LevelKeys(server, client)}
        self._next_receive_keys: PacketProtection | None = None
        self._key_phase = False
        self._crypto_send = {level: SendStream(-1, Size.CRYPTO_WINDOW) for level in EncryptionLevel}
        self._crypto_receive = {level: ReceiveStream(-1, Size.CRYPTO_WINDOW) for level in EncryptionLevel}
        self._send_streams: dict[int, SendStream] = {}
        self._receive_streams: dict[int, ReceiveStream] = {}
        # streams holding data the application has not been handed yet, in arrival order
        self._readable: dict[int, ReceiveStream] = {}
        self._next_stream = {True: 0, False: int(StreamIdBit.UNIDIRECTIONAL)}
        self._peer_max_streams = {True: 0, False: 0}
        self._local_max_streams = {True: parameters.initial_max_streams_bidi, False: parameters.initial_max_streams_uni}
        self._peer_opened = {True: 0, False: 0}
        self._peer: PeerParameters | None = None
        self._peer_max_data = 0
        self._data_sent = 0
        self._local_max_data = parameters.initial_max_data
        self._data_received = 0
        # control frames waiting to go out, by packet number space
        self._pending: dict[EncryptionLevel, list[Frame]] = {
            EncryptionLevel.INITIAL: [],
            EncryptionLevel.HANDSHAKE: [],
            EncryptionLevel.APPLICATION: [],
        }
        self._events: deque[QuicEvent] = deque()
        self._handshake_done = False
        self._handshake_confirmed = False
        self._datagram_size: int = Size.DATAGRAM
        self._mtu_probe: int | None = None
        self._closing: ConnectionClose | None = None
        self._close_sent = False
        self._terminated = False
        self._idle_timeout: float | None = parameters.max_idle_timeout / Limit.MILLISECONDS or None
        self._last_activity = now
        self._ack_timer: float | None = None
        self._peer_connection_ids: dict[int, tuple[bytes, bytes]] = {}
        self._probe_levels: deque[EncryptionLevel] = deque()
        self._initial_hello = b""
        self.new_token = b""
        self.alpn: NextProtocol | bytes | None = None
        self.early_data = self._handshake.early_data_offered
        if self.early_data:
            # 0-RTT runs under the limits the server granted last time until the handshake brings the new ones
            granted = PeerParameters(self._handshake.remembered_transport_parameters)
            for parameter in self.NEVER_REMEMBERED:
                granted.forget(parameter)
            self._apply_peer_parameters(granted)
        self._drive_handshake()

    @property
    def handshake_complete(self) -> bool:
        return self._handshake_done

    @property
    def early_data_pending(self) -> bool:
        return self.early_data and not self._handshake_done

    @property
    def early_data_accepted(self) -> bool:
        return self.early_data and self._handshake.early_data_accepted

    @property
    def early_data_rejected(self) -> bool:
        return self._handshake.early_data_rejected

    @property
    def retried(self) -> bool:
        return self._retry_source is not None

    @property
    def peer_transport_parameters(self) -> bytes:
        return self._handshake.peer_transport_parameters if self._handshake_done else b""

    @property
    def round_trip_time(self) -> int:
        # the smoothed estimate in microseconds, the unit initial_round_trip_time is sent in
        return int(self._recovery.smoothed_rtt * Limit.MICROSECONDS)

    @property
    def version(self) -> QuicVersion:
        return self._version

    @property
    def buffer(self) -> TLSBuffer:
        return self._handshake.buffer

    @property
    def peer_chain(self) -> tuple[bytes, ...]:
        return self._handshake.buffer.getpeerchain()

    @property
    def terminated(self) -> bool:
        return self._terminated

    def next_event(self) -> QuicEvent | None:
        if self._events:
            return self._events.popleft()
        if self._readable:
            # one event carries everything a stream received since the last read, not one event per packet
            stream_id, receive = next(iter(self._readable.items()))
            del self._readable[stream_id]
            chunks, receive.chunks = receive.chunks, []
            data = chunks[0] if len(chunks) == 1 else b"".join(chunks)
            return StreamDataReceived(stream_id, data, receive.finished)
        return None

    def can_open_stream(self, *, bidirectional: bool = True) -> bool:
        return (self._next_stream[bidirectional] >> StreamIdBit.SEQUENCE_SHIFT) < self._peer_max_streams[bidirectional]

    def open_stream(self, *, bidirectional: bool = True) -> int:
        if not self.can_open_stream(bidirectional=bidirectional):
            raise ConnectError("the server allows no more streams right now")
        stream_id = self._next_stream[bidirectional]
        self._next_stream[bidirectional] += Limit.STREAM_STEP
        limit = (
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE if bidirectional else Parameter.INITIAL_MAX_STREAM_DATA_UNI
        )
        self._send_streams[stream_id] = SendStream(stream_id, self._peer_parameter(limit))
        if bidirectional:
            self._receive_streams[stream_id] = ReceiveStream(
                stream_id, self._parameters.initial_max_stream_data_bidi_local
            )
        return stream_id

    def send_stream_data(self, stream_id: int, data: bytes, *, end: bool = False) -> None:
        stream = self._send_streams[stream_id]
        stream.write(data)
        if end:
            stream.end()

    def unsent(self, stream_id: int) -> int:
        stream = self._send_streams.get(stream_id)
        return 0 if stream is None else stream.unsent

    def stream_read(self, stream_id: int, size: int) -> bool:
        # the stream window opens as the application takes data, so a reader that stops holds the server at one window;
        # returns whether a MAX_STREAM_DATA now waits to go out
        receive = self._receive_streams.get(stream_id)
        if receive is None or receive.final_size is not None:
            return False
        receive.read += size
        window = (
            self._parameters.initial_max_stream_data_uni
            if stream_id & StreamIdBit.UNIDIRECTIONAL
            else self._parameters.initial_max_stream_data_bidi_local
        )
        if receive.max_data - receive.read >= window // 2:
            return False
        receive.max_data = receive.read + window
        self._pending[EncryptionLevel.APPLICATION].append(MaxStreamData(stream_id, receive.max_data))
        return True

    def reset_stream(self, stream_id: int, error: int) -> None:
        stream = self._send_streams.get(stream_id)
        if stream is not None and stream.reset_error is None:
            stream.reset_error = error
            stream.pending.clear()
            self._pending[EncryptionLevel.APPLICATION].append(ResetStream(stream_id, error, stream.offset))

    def stop_sending(self, stream_id: int, error: int) -> None:
        stream = self._receive_streams.get(stream_id)
        if stream is not None and not stream.stop_sent:
            stream.stop_sent = True
            self._pending[EncryptionLevel.APPLICATION].append(StopSending(stream_id, error))

    def send_datagram(self, data: bytes) -> None:
        self._pending[EncryptionLevel.APPLICATION].append(Datagram(data))

    def close(self, error: int = 0, reason: str = "", *, application: bool = True) -> None:
        if self._closing is None and not self._terminated:
            self._closing = ConnectionClose(error, None, reason.encode(), application)

    def datagram_received(self, data: bytes, now: float) -> None:
        if self._terminated:
            return
        self._last_activity = now
        offset = 0
        while offset < len(data):
            if not data[offset] & Bit.LONG_FORM:
                # a short header packet is the last one in its datagram
                keys = self._keys.get(EncryptionLevel.APPLICATION)
                if keys is not None and keys.receive is not None:
                    number_offset = offset + 1 + len(self._source_id)
                    self._receive_packet(
                        data, offset, number_offset, len(data), EncryptionLevel.APPLICATION, keys.receive, now, b""
                    )
                return
            try:
                header = Header.parse(data, offset, len(self._source_id))
            except ProtocolError:
                return
            match header.packet_type:
                case PacketType.VERSION_NEGOTIATION:
                    self._on_version_negotiation(header)
                    return
                case PacketType.RETRY:
                    self._on_retry(header, data[offset:])
                    return
                case PacketType.INITIAL:
                    level = EncryptionLevel.INITIAL
                case PacketType.ZERO_RTT:
                    level = EncryptionLevel.EARLY_DATA
                case PacketType.HANDSHAKE:
                    level = EncryptionLevel.HANDSHAKE
                case PacketType.ONE_RTT:
                    level = EncryptionLevel.APPLICATION
            if header.version != self._version:
                if header.version not in self._offered or self._handshake_done:
                    return
                self._switch_version(QuicVersion(header.version))
            keys = self._keys.get(level)
            if keys is not None and keys.receive is not None:
                self._receive_packet(
                    data, offset, header.number_offset, header.end, level, keys.receive, now, header.source
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
            self._terminate(
                self._closing.error,
                self._closing.reason.decode("utf-8", "replace"),
                application=self._closing.application,
            )
            return [datagram] if datagram else []
        datagrams: list[bytes] = []
        while len(datagrams) < Limit.BURST:
            datagram = self._build_datagram(now)
            if datagram is None:
                break
            datagrams.append(datagram)
        if datagrams:
            self._last_activity = now
        return datagrams

    def pacing_delay(self, size: int) -> float:
        # RFC 9002 section 7.7: a window is spread over a round trip instead of leaving as one burst
        recovery = self._recovery
        window = max(recovery.window, 2 * Size.DATAGRAM)
        rate = Pacing.GAIN * window / max(recovery.smoothed_rtt, Tuning.GRANULARITY)
        return size / rate

    def datagram_too_long(self) -> None:
        # the kernel refused a datagram for its size, so from here on only the size every path carries goes out
        self._datagram_size = Size.DATAGRAM
        self._mtu_probe = None

    def next_timer(self) -> float | None:
        candidates: list[float] = []
        if self._idle_timeout is not None:
            candidates.append(self._last_activity + self._idle_timeout)
        if self._ack_timer is not None:
            candidates.append(self._ack_timer)
        timer = self._recovery.loss_timer(has_handshake_keys=EncryptionLevel.HANDSHAKE in self._keys)
        if timer is not None:
            candidates.append(timer.when)
        return min(candidates, default=None)

    def handle_timer(self, now: float) -> None:
        if self._terminated:
            return
        if self._idle_timeout is not None and now >= self._last_activity + self._idle_timeout:
            self._terminate(TransportError.NO_ERROR, "idle timeout", application=False)
            return
        if self._ack_timer is not None and now >= self._ack_timer:
            self._ack_timer = None
            self._recovery.space(EncryptionLevel.APPLICATION).ack_pending = True
        timer = self._recovery.loss_timer(has_handshake_keys=EncryptionLevel.HANDSHAKE in self._keys)
        if timer is None or now < timer.when:
            return
        if timer.loss:
            for packet in self._recovery.detect_lost(timer.level, now):
                self._on_lost(timer.level, packet)
            return
        # RFC 9002 section 6.2.4: a probe timeout sends unacknowledged data again, and two probes
        self._recovery.on_pto()
        wanted = timer.level
        if (
            wanted is EncryptionLevel.APPLICATION
            and wanted not in self._keys
            and EncryptionLevel.EARLY_DATA in self._keys
        ):
            wanted = EncryptionLevel.EARLY_DATA
        level = wanted if wanted in self._keys else next(iter(self._keys))
        self._resend_unacknowledged(level)
        self._probe_levels.extend((level, level))

    def _resend_unacknowledged(self, level: EncryptionLevel) -> None:
        # a bare PING tells a server that lost the first flight nothing; the handshake flights are small and go whole,
        # afterwards the oldest packet alone is enough
        space = self._recovery.space(self._space_of(level))
        unacknowledged = [packet for _, packet in sorted(space.sent.items()) if packet.ack_eliciting]
        if level is EncryptionLevel.APPLICATION:
            unacknowledged = unacknowledged[:1]
        for packet in unacknowledged:
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
        # RFC 9001 section 5.4: the header protection comes off first, then the packet number is known
        if end - number_offset < Width.SAMPLE_OFFSET + Width.SAMPLE:
            return
        sample_start = number_offset + Width.SAMPLE_OFFSET
        mask = keys.mask(data[sample_start : sample_start + Width.SAMPLE])
        first = data[offset] ^ (mask[0] & (Bit.LONG_PROTECTED if data[offset] & Bit.LONG_FORM else Bit.SHORT_PROTECTED))
        length = (first & Bit.NUMBER_LENGTH_MASK) + 1
        truncated = int.from_bytes(data[number_offset : number_offset + length]) ^ int.from_bytes(mask[1 : 1 + length])
        number = self._recovery.space(self._space_of(level)).decode_number(truncated, length * Width.BITS_PER_BYTE)
        header = bytes((first,)) + data[offset + 1 : number_offset] + truncated.to_bytes(length)
        ciphertext = data[number_offset + length : end]
        if level is EncryptionLevel.APPLICATION and bool(first & Bit.KEY_PHASE) != self._key_phase:
            # RFC 9001 section 6: the peer started a key update; the next keys open it and both directions move on
            candidate = self._next_receive_keys or keys.update()
            try:
                payload = candidate.open(number, header, ciphertext)
            except ValueError:
                return
            self._next_receive_keys = None
            self._key_phase = not self._key_phase
            current = self._keys[level]
            current.receive = candidate
            if current.send is not None:
                current.send = current.send.update()
        else:
            try:
                payload = keys.open(number, header, ciphertext)
            except ValueError:
                return
        if (
            level is EncryptionLevel.INITIAL
            and not self._handshake_done
            and self._destination_id in (self._original_destination, self._retry_source)
        ):
            # RFC 9000 section 7.2: the server's first Initial names the id the rest of the connection uses
            self._destination_id = source
        self._process_payload(level, number, payload, now)

    def _process_payload(self, level: EncryptionLevel, number: int, payload: bytes, now: float) -> None:
        reader = FrameReader(payload)
        ack_eliciting = False
        while reader.remaining:
            frame = reader.frame()
            if not isinstance(frame, FrameReader.NOT_ACK_ELICITING):
                ack_eliciting = True
            match frame:
                case Stream():
                    self._on_stream(frame)
                case Ack():
                    self._on_ack(level, frame, now)
                case Crypto(offset, data):
                    self._on_crypto(level, offset, data)
                case MaxData(maximum):
                    self._peer_max_data = max(self._peer_max_data, maximum)
                case MaxStreamData(stream_id, maximum):
                    stream = self._send_streams.get(stream_id)
                    if stream is not None:
                        stream.max_data = max(stream.max_data, maximum)
                case MaxStreams(bidirectional, maximum):
                    self._peer_max_streams[bidirectional] = max(self._peer_max_streams[bidirectional], maximum)
                case NewConnectionId(sequence, retire_prior_to, connection_id, reset_token):
                    self._on_new_connection_id(sequence, retire_prior_to, connection_id, reset_token)
                case ResetStream(stream_id, error, _):
                    if self._receive_streams.pop(stream_id, None) is not None:
                        self._readable.pop(stream_id, None)
                        self._events.append(StreamReset(stream_id, error))
                case StopSending(stream_id, error):
                    self.reset_stream(stream_id, error)
                    self._events.append(StopSendingReceived(stream_id, error))
                case NewToken(token):
                    self.new_token = token
                case PathChallenge(challenge):
                    self._pending[EncryptionLevel.APPLICATION].append(PathResponse(challenge))
                case ConnectionClose(error, _, reason, application):
                    self._terminate(error, reason.decode("utf-8", "replace"), application=application)
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
        space = self._recovery.space(self._space_of(level))
        in_order = space.record_received(number, now, ack_eliciting=ack_eliciting)
        if not ack_eliciting:
            return
        # RFC 9000 section 13.2.1: an ACK after every second ack-eliciting packet, at once when one arrives out of order
        if (
            level is not EncryptionLevel.APPLICATION
            or not in_order
            or space.ack_eliciting_received >= Limit.ACK_THRESHOLD
        ):
            space.ack_pending = True
            self._ack_timer = None
        elif self._ack_timer is None:
            self._ack_timer = now + self._parameters.max_ack_delay / Limit.MILLISECONDS

    def _on_crypto(self, level: EncryptionLevel, offset: int, data: bytes) -> None:
        received = self._crypto_receive[level].on_frame(Stream(-1, offset, data, fin=False))
        if not received:
            return
        self._handshake.provide(level, received)
        if self._handshake_done:
            # NewSessionTicket and the other post-handshake messages; this is what fills the session cache
            self._handshake.process_post_handshake()
        else:
            self._drive_handshake()

    def _on_new_connection_id(
        self, sequence: int, retire_prior_to: int, connection_id: bytes, reset_token: bytes
    ) -> None:
        self._peer_connection_ids[sequence] = (connection_id, reset_token)
        for old in [key for key in self._peer_connection_ids if key < retire_prior_to]:
            del self._peer_connection_ids[old]
            self._pending[EncryptionLevel.APPLICATION].append(RetireConnectionId(old))

    def _on_ack(self, level: EncryptionLevel, ack: Ack, now: float) -> None:
        space_level = self._space_of(level)
        exponent = self._peer_parameter(Parameter.ACK_DELAY_EXPONENT)
        acked, lost = self._recovery.on_ack_received(space_level, ack, now, exponent)
        space = self._recovery.space(space_level)
        for packet in acked:
            if packet.probe:
                # the path carried the probe, so every datagram from here on may be that large
                self._datagram_size = packet.size
            for frame in packet.frames:
                match frame:
                    case Ack(largest, _, _, _):
                        space.forget(largest)
                    case Stream(stream_id, _, _, _):
                        self._stream_acked(stream_id)
                    case ResetStream(stream_id, _, _):
                        self._send_streams.pop(stream_id, None)
                    case _:
                        pass
        for packet in lost:
            self._on_lost(space_level, packet)
        # RFC 9001 section 4.1.2: an acknowledged 1-RTT packet confirms the handshake; an acknowledged 0-RTT one does not
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
        self.logger.debug("%s level=%s number=%d size=%d", Event.QUIC_LOST, level.name, packet.number, packet.size)
        for frame in packet.frames:
            match frame:
                case Crypto(offset, data):
                    self._crypto_send[level].requeue(Stream(-1, offset, data, fin=False))
                case Stream():
                    stream = self._send_streams.get(frame.stream_id)
                    if stream is not None and stream.reset_error is None:
                        stream.requeue(frame)
                case Ack() | Ping() | Padding() | PathResponse() | Datagram():
                    pass
                case _:
                    self._pending[level].append(frame)

    def _on_stream(self, frame: Stream) -> None:
        stream_id = frame.stream_id
        server_initiated = bool(stream_id & StreamIdBit.SERVER_INITIATED)
        bidirectional = not stream_id & StreamIdBit.UNIDIRECTIONAL
        if not server_initiated and not bidirectional:
            raise ProtocolError(f"the server sent data on our unidirectional stream {stream_id}")
        receive = self._receive_streams.get(stream_id)
        if receive is None:
            if not server_initiated:
                return
            receive = self._open_peer_stream(stream_id, bidirectional=bidirectional)
        before = receive.next_offset
        data = receive.on_frame(frame)
        self._data_received += receive.next_offset - before
        if data or receive.finished:
            if data:
                receive.chunks.append(data)
            self._readable[stream_id] = receive
            if receive.finished:
                del self._receive_streams[stream_id]
        if self._data_received > self._local_max_data - self._parameters.initial_max_data // 2:
            self._local_max_data = self._data_received + self._parameters.initial_max_data
            self._pending[EncryptionLevel.APPLICATION].append(MaxData(self._local_max_data))

    def _open_peer_stream(self, stream_id: int, *, bidirectional: bool) -> ReceiveStream:
        sequence = stream_id >> StreamIdBit.SEQUENCE_SHIFT
        if sequence >= self._local_max_streams[bidirectional]:
            raise ProtocolError("the server opened more streams than allowed")
        limit = (
            self._parameters.initial_max_stream_data_bidi_remote
            if bidirectional
            else self._parameters.initial_max_stream_data_uni
        )
        receive = self._receive_streams[stream_id] = ReceiveStream(stream_id, limit)
        self._peer_opened[bidirectional] = max(self._peer_opened[bidirectional], sequence + 1)
        if bidirectional:
            self._send_streams[stream_id] = SendStream(
                stream_id, self._peer_parameter(Parameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL)
            )
        if self._peer_opened[bidirectional] * 2 > self._local_max_streams[bidirectional]:
            # the stream limit grows by the initial allowance once half of it is in use
            self._local_max_streams[bidirectional] += (
                self._parameters.initial_max_streams_bidi if bidirectional else self._parameters.initial_max_streams_uni
            )
            self._pending[EncryptionLevel.APPLICATION].append(
                MaxStreams(bidirectional, self._local_max_streams[bidirectional])
            )
        return receive

    def _drive_handshake(self) -> None:
        try:
            done = self._handshake.advance()
        except TLSError as error:
            # the peer gets the TLS alert in a CONNECTION_CLOSE, the caller the reason once it has gone out
            alert = Limit.TLS_INTERNAL_ERROR if self._handshake.alert is None else self._handshake.alert[1]
            self._closing = ConnectionClose(
                TransportError.CRYPTO_ERROR + alert, None, f"TLS handshake failed: {error}".encode(), application=False
            )
            return
        for level, is_write, suite, secret in self._handshake.take_secrets():
            protection = PacketProtection(self._library, suite, secret, self._version)
            keys = self._keys.setdefault(level, LevelKeys())
            if is_write:
                keys.send = protection
            else:
                keys.receive = protection
            if level is EncryptionLevel.EARLY_DATA:
                self.logger.info("%s keys=ready", Event.QUIC_EARLY_DATA)
                self._events.append(EarlyDataAvailable())
        for level in EncryptionLevel:
            data = self._handshake.take_outgoing(level)
            if data:
                self._crypto_send[level].write(data)
                if level is EncryptionLevel.INITIAL:
                    self._initial_hello += data
        if self._handshake.alert is not None:
            _, alert = self._handshake.alert
            self._closing = ConnectionClose(TransportError.CRYPTO_ERROR + alert, None, b"TLS alert", application=False)
        if done and not self._handshake_done:
            self._complete_handshake()

    def _complete_handshake(self) -> None:
        self._handshake_done = True
        peer = PeerParameters(self._handshake.peer_transport_parameters)
        # RFC 9000 section 7.3: the ids the server echoes must be the ones this connection used
        if peer.connection_id(Parameter.ORIGINAL_DESTINATION_CONNECTION_ID) != self._original_destination:
            raise ProtocolError("the server's original_destination_connection_id does not match")
        if peer.connection_id(Parameter.INITIAL_SOURCE_CONNECTION_ID) != self._destination_id:
            raise ProtocolError("the server's initial_source_connection_id does not match")
        if (
            self._retry_source is not None
            and peer.connection_id(Parameter.RETRY_SOURCE_CONNECTION_ID) != self._retry_source
        ):
            raise ProtocolError("the server's retry_source_connection_id does not match")
        information = peer.connection_id(Parameter.VERSION_INFORMATION)
        if information is not None and information[: Width.VERSION] != self._version.to_bytes(Width.VERSION, "big"):
            # RFC 9368 section 4: the server's chosen version must be the one its packets carry
            raise ProtocolError("the server's version_information names another version")
        if self._handshake.early_data_accepted and self._peer is not None:
            # RFC 9000 section 7.4.1: accepted 0-RTT data keeps the limits it was sent under
            for parameter in self.EARLY_DATA_LIMITS:
                if peer.integer(parameter) < self._peer.integer(parameter):
                    raise ProtocolError(f"the server lowered {parameter.name} below what it granted for early data")
        self._apply_peer_parameters(peer)
        self.alpn = self._handshake.buffer.negotiated_protocol()
        if self._handshake.early_data_rejected:
            self._requeue_early_packets()
            self._events.append(EarlyDataRejected())
        if self.early_data:
            self._discard(EncryptionLevel.EARLY_DATA)
        self.logger.info(
            "%s version=%s alpn=%s early_data=%s",
            Event.QUIC_HANDSHAKE_DONE,
            self._version.name,
            self.alpn,
            self.early_data_accepted,
        )
        self._events.append(HandshakeCompleted())

    def _apply_peer_parameters(self, peer: PeerParameters) -> None:
        self._peer = peer
        self._peer_max_data = peer.integer(Parameter.INITIAL_MAX_DATA)
        self._peer_max_streams[True] = peer.integer(Parameter.INITIAL_MAX_STREAMS_BIDI)
        self._peer_max_streams[False] = peer.integer(Parameter.INITIAL_MAX_STREAMS_UNI)
        # RFC 9000 section 10.1: the smaller advertised timeout, where zero means that side sets none
        timeouts = [
            value / Limit.MILLISECONDS
            for value in (peer.integer(Parameter.MAX_IDLE_TIMEOUT), self._parameters.max_idle_timeout)
            if value
        ]
        self._idle_timeout = min(timeouts) if timeouts else None
        self._recovery.max_ack_delay = peer.integer(Parameter.MAX_ACK_DELAY) / Limit.MILLISECONDS

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
        target = min(Size.PROBED_DATAGRAM, self._peer_parameter(Parameter.MAX_UDP_PAYLOAD_SIZE))
        if target > self._datagram_size:
            self._mtu_probe = target

    def _discard(self, level: EncryptionLevel) -> None:
        self._keys.pop(level, None)
        self._recovery.discard_space(level)
        self._crypto_send[level].pending.clear()
        self._pending.get(level, []).clear()

    def _peer_parameter(self, parameter: Parameter) -> int:
        return parameter.absent if self._peer is None else self._peer.integer(parameter)

    def _terminate(self, error: int, reason: str, *, application: bool) -> None:
        self._terminated = True
        self.logger.info("%s error=%#x reason=%s application=%s", Event.QUIC_TERMINATED, error, reason, application)
        self._events.append(ConnectionTerminated(error, reason, application))

    def _switch_version(self, version: QuicVersion) -> None:
        # RFC 9368 section 2.3: the server answered in another version we offered; the Initial keys follow it,
        # derived from the id the first flight went to, not from the id the server has chosen since
        self.logger.info("%s version=%s", Event.QUIC_VERSION_CHANGED, version.name)
        self._version = version
        chosen = self._original_destination if self._retry_source is None else self._retry_source
        client, server = PacketProtection.initial(self._library, version, chosen)
        self._keys[EncryptionLevel.INITIAL] = LevelKeys(server, client)

    def _on_version_negotiation(self, header: Header) -> None:
        # RFC 9000 section 6.2: a server that speaks none of our versions lists its own; one we know restarts the connection
        if self._version in header.supported_versions or self._handshake_done:
            return
        for candidate in QuicVersion:
            if candidate in header.supported_versions and candidate is not self._version:
                self._terminated = True
                self._events.append(VersionNegotiated(candidate))
                return
        self._terminate(TransportError.NO_ERROR, "no common QUIC version", application=False)

    def _on_retry(self, header: Header, packet: bytes) -> None:
        # RFC 9000 section 17.2.5: one Retry per connection, before the server's first Initial, with a valid tag
        if self._retry_source is not None or self._handshake_done or header.destination != self._source_id:
            return
        pseudo = packet[: len(packet) - Width.RETRY_TAG]
        if PacketProtection.retry_tag(self._library, self._version, self._destination_id, pseudo) != header.retry_tag:
            return
        self.logger.info("%s token=%d", Event.QUIC_RETRY, len(header.token))
        self._retry_source = header.source
        self._token = header.token
        self._destination_id = header.source
        client, server = PacketProtection.initial(self._library, self._version, self._destination_id)
        self._keys[EncryptionLevel.INITIAL] = LevelKeys(server, client)
        # RFC 9000 section 17.2.5.3: the packets before the Retry are dropped, but their numbers are not used again
        number = self._recovery.space(EncryptionLevel.INITIAL).next_number
        self._recovery.discard_space(EncryptionLevel.INITIAL)
        self._recovery.space(EncryptionLevel.INITIAL).next_number = number
        self._crypto_send[EncryptionLevel.INITIAL] = SendStream(-1, Size.CRYPTO_WINDOW)
        self._crypto_send[EncryptionLevel.INITIAL].write(self._initial_hello)
        # the server dropped the 0-RTT packets with the Initial; they go again with the new connection id
        self._requeue_early_packets()

    def _build_datagram(self, now: float) -> bytes | None:
        if self._mtu_probe is not None:
            keys = self._keys.get(EncryptionLevel.APPLICATION)
            if keys is not None and keys.send is not None and self._recovery.can_send(self._mtu_probe):
                # RFC 9000 section 14.2.1: a padded PING in a datagram of its own asks the path whether it carries the size
                target, self._mtu_probe = self._mtu_probe, None
                built = self._build_packet(
                    EncryptionLevel.APPLICATION, keys.send, target, now, pad=True, frames=(Ping(),), probe=True
                )
                if built is not None:
                    self._recovery.on_packet_sent(EncryptionLevel.APPLICATION, built[1])
                    return built[0]
        packets: list[tuple[EncryptionLevel, bytes, SentPacket]] = []
        remaining = self._datagram_size
        for level in self.SEND_ORDER:
            keys = self._keys.get(level)
            if keys is None or keys.send is None:
                continue
            if level is EncryptionLevel.INITIAL and self._awaiting_retry_answer():
                continue
            built = self._build_packet(level, keys.send, remaining, now, pad=False)
            if built is not None:
                packets.append((level, built[0], built[1]))
                remaining -= len(built[0])
        if not packets:
            return None
        if packets[0][0] is EncryptionLevel.INITIAL and remaining > 0:
            # RFC 9000 section 14.1: a datagram with an Initial packet is padded to the size every path carries
            level, _, record = packets[0]
            keys = self._keys[level]
            if keys.send is not None:
                self._recovery.space(level).next_number -= 1
                budget = Size.DATAGRAM - sum(len(packet) for _, packet, _ in packets[1:])
                rebuilt = self._build_packet(level, keys.send, budget, now, pad=True, frames=record.frames)
                if rebuilt is not None:
                    packets[0] = (level, rebuilt[0], rebuilt[1])
        for level, _, record in packets:
            self._recovery.on_packet_sent(self._space_of(level), record)
            if level is EncryptionLevel.HANDSHAKE and EncryptionLevel.INITIAL in self._keys:
                # RFC 9001 section 4.9.1: the first Handshake packet sent ends the Initial keys
                self._discard(EncryptionLevel.INITIAL)
        return b"".join(packet for _, packet, _ in packets)

    def _awaiting_retry_answer(self) -> bool:
        # after a Retry one Initial goes out until the server answers with its connection id, so a ClientHello in
        # several packets reaches one server connection instead of one per datagram
        return self._destination_id == self._retry_source and any(
            packet.ack_eliciting for packet in self._recovery.space(EncryptionLevel.INITIAL).sent.values()
        )

    @staticmethod
    def _space_of(level: EncryptionLevel) -> EncryptionLevel:
        # 0-RTT and 1-RTT packets share one packet number space
        return EncryptionLevel.APPLICATION if level is EncryptionLevel.EARLY_DATA else level

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
        overhead = self._header_length(level, len(number_bytes)) + Width.TAG
        if space_left <= overhead + Size.MINIMUM_PROTECTED:
            return None
        capacity = space_left - overhead
        collected = list(frames) if frames is not None else self._collect_frames(level, capacity, now)
        if not collected:
            return None
        if len(collected) == 1 and isinstance(collected[0], Stream) and not pad:
            # a packet of one STREAM frame, the shape of every packet in an upload, needs no writer
            payload = FrameWriter.stream_frame(collected[0])
        else:
            writer = FrameWriter()
            for frame in collected:
                writer.frame(frame)
            if pad and len(writer) < capacity:
                collected.append(Padding(capacity - len(writer)))
                writer.frame(collected[-1])
            if len(writer) + len(number_bytes) < Size.MINIMUM_PROTECTED:
                collected.append(Padding(Size.MINIMUM_PROTECTED - len(writer) - len(number_bytes)))
                writer.frame(collected[-1])
            payload = writer.finish()
        header = self._header(level, number_bytes, len(payload) + Width.TAG)
        sealed = keys.seal(number, header, payload)
        # RFC 9001 section 5.4.2: the sample starts four bytes past the start of the number, which is inside the ciphertext
        length = len(number_bytes)
        sample_start = Width.SAMPLE_OFFSET - length
        mask = keys.mask(sealed[sample_start : sample_start + Width.SAMPLE])
        first = header[0] ^ (mask[0] & (Bit.LONG_PROTECTED if header[0] & Bit.LONG_FORM else Bit.SHORT_PROTECTED))
        masked_number = (int.from_bytes(number_bytes) ^ int.from_bytes(mask[1 : 1 + length])).to_bytes(length)
        packet = bytes((first,)) + header[1:-length] + masked_number + sealed
        space.next_number += 1
        ack_eliciting = in_flight = False
        for frame in collected:
            if not isinstance(frame, FrameReader.NOT_ACK_ELICITING):
                ack_eliciting = in_flight = True
                break
            if isinstance(frame, Padding):
                in_flight = True
        record = SentPacket(
            number,
            now,
            len(packet),
            tuple(collected),
            ack_eliciting,
            in_flight,
            early=level is EncryptionLevel.EARLY_DATA,
            probe=probe,
        )
        return packet, record

    def _collect_frames(self, level: EncryptionLevel, capacity: int, now: float) -> list[Frame]:
        frames: list[Frame] = []
        used = 0
        early = level is EncryptionLevel.EARLY_DATA
        space_level = self._space_of(level)
        space = self._recovery.space(space_level)
        # RFC 9000 section 12.5: a 0-RTT packet never carries an ACK frame
        wants_ack = space.ack_pending or (
            bool(space.received) and level is not EncryptionLevel.APPLICATION and space.ack_eliciting_received > 0
        )
        if not early and wants_ack:
            ack = space.ack_frame(now, self._parameters.ack_delay_exponent)
            if ack is not None:
                frames.append(ack)
                used += FrameWriter.length(ack)
                space.ack_pending = False
                space.ack_eliciting_received = 0
        if self._probe_levels and self._probe_levels[0] is level:
            self._probe_levels.popleft()
            frames.append(Ping())
            used += 1
        pending = self._pending[space_level]
        for frame in list(pending):
            length = FrameWriter.length(frame)
            if used + length > capacity:
                break
            frames.append(frame)
            pending.remove(frame)
            used += length
        crypto = self._crypto_send[level]
        while crypto.active and used + Size.CRYPTO_FRAME_HEAD < capacity:
            piece = crypto.next_frame(capacity - used - Size.CRYPTO_FRAME_HEAD, Size.CRYPTO_WINDOW)
            if piece is None:
                break
            frame = Crypto(piece.offset, piece.data)
            frames.append(frame)
            used += FrameWriter.length(frame)
        if early or (level is EncryptionLevel.APPLICATION and self._handshake_done):
            used = self._collect_stream_frames(frames, used, capacity)
        return frames

    def _collect_stream_frames(self, frames: list[Frame], used: int, capacity: int) -> int:
        for stream in list(self._send_streams.values()):
            if not stream.active or stream.reset_error is not None:
                continue
            if not self._recovery.can_send(used + Size.CONGESTION_RESERVE):
                break
            while stream.active and used + Size.STREAM_FRAME_HEAD < capacity:
                high = stream.sent_offset
                frame = stream.next_frame(
                    capacity - used - Size.STREAM_FRAME_HEAD, self._peer_max_data - self._data_sent
                )
                if frame is None:
                    if stream.blocked:
                        blocked = StreamDataBlocked(stream.stream_id, stream.max_data)
                        frames.append(blocked)
                        used += FrameWriter.length(blocked)
                        stream.blocked = False
                    break
                frames.append(frame)
                # a retransmission was charged to the connection window when it first went out
                self._data_sent += stream.sent_offset - high
                used += FrameWriter.length(frame)
        return used

    def _close_datagram(self, now: float) -> bytes:
        # RFC 9000 section 10.2.3: the close goes out at the highest level that has keys, as a transport close below 1-RTT
        if self._closing is None:
            return b""
        for level in (EncryptionLevel.APPLICATION, EncryptionLevel.HANDSHAKE, EncryptionLevel.INITIAL):
            keys = self._keys.get(level)
            if keys is None or keys.send is None:
                continue
            if level is EncryptionLevel.APPLICATION:
                close = self._closing
            else:
                error = TransportError.APPLICATION_ERROR if self._closing.application else self._closing.error
                close = ConnectionClose(error, None, b"", application=False)
            built = self._build_packet(
                level, keys.send, Size.DATAGRAM, now, pad=level is EncryptionLevel.INITIAL, frames=(close,)
            )
            if built is not None:
                return built[0]
        return b""

    def _header_length(self, level: EncryptionLevel, number_length: int) -> int:
        if level is EncryptionLevel.APPLICATION:
            return 1 + len(self._destination_id) + number_length
        token = Writer.varint_length(len(self._token)) + len(self._token) if level is EncryptionLevel.INITIAL else 0
        return (
            Size.LONG_HEADER_FIXED
            + len(self._destination_id)
            + len(self._source_id)
            + token
            + Width.LENGTH
            + number_length
        )

    def _header(self, level: EncryptionLevel, number_bytes: bytes, remaining_length: int) -> bytes:
        match level:
            case EncryptionLevel.APPLICATION:
                return Header.short_bytes(self._destination_id, number_bytes, key_phase=self._key_phase)
            case EncryptionLevel.INITIAL:
                packet_type = PacketType.INITIAL
            case EncryptionLevel.EARLY_DATA:
                packet_type = PacketType.ZERO_RTT
            case EncryptionLevel.HANDSHAKE:
                packet_type = PacketType.HANDSHAKE
        return Header.long_bytes(
            packet_type,
            self._version,
            self._destination_id,
            self._source_id,
            self._token,
            number_bytes,
            remaining_length,
        )
