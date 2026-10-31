from collections import deque
from dataclasses import dataclass
from enum import IntEnum

from boring_ssl2 import EncryptionLevel
from ssl2.value import Value

from boring_http.quic.packet import Ack, Frame


class Count(IntEnum):
    # RFC 9002 sections 6.1.1 and 7.2: reordering before a loss, windows in datagrams
    PACKET_THRESHOLD = 3
    MINIMUM_WINDOW_DATAGRAMS = 2
    INITIAL_WINDOW_DATAGRAMS = 10
    INITIAL_WINDOW_FLOOR = 14720
    MAXIMUM_WINDOW = 16 << 20
    PERSISTENT_CONGESTION_THRESHOLD = 3
    # how many received ranges an ACK repeats, and how many ACK-only packets stay on record
    RANGES = 32
    ACK_ONLY_TRACKED = 256
    MICROSECONDS = 1_000_000
    NUMBER_LIMIT = 1 << 62
    # a packet number takes one to four bytes; the shortest that leaves the receiver no doubt is used
    NUMBER_BYTES = 4
    BITS_PER_BYTE = 8


class Tuning:
    # RFC 9002 sections 5 and 6, in seconds
    INITIAL_RTT = 0.333
    TIME_THRESHOLD = 9 / 8
    GRANULARITY = 0.001
    LOSS_REDUCTION = 0.5
    MAX_ACK_DELAY = 0.025
    RTT_VARIANCE_WEIGHT = 1 / 4
    RTT_WEIGHT = 1 / 8
    VARIANCE_MULTIPLIER = 4


@dataclass(frozen=True, slots=True)
class SentPacket(Value):
    number: int
    time: float
    size: int
    frames: tuple[Frame, ...]
    ack_eliciting: bool
    in_flight: bool
    # sent under the 0-RTT keys, so a rejection sends its frames again
    early: bool = False
    # a padded PING that asks the path whether it carries this size
    probe: bool = False


@dataclass(frozen=True, slots=True)
class Timer(Value):
    when: float
    level: EncryptionLevel
    # a loss timer fires detection; a probe timer fires a PTO
    loss: bool


class PacketSpace:
    # RFC 9002 section 4: the numbers sent and received at one encryption level
    def __init__(self) -> None:
        self.sent: dict[int, SentPacket] = {}
        self.next_number = 0
        self.largest_acked: int | None = None
        self.loss_time: float | None = None
        self.last_ack_eliciting: float | None = None
        # ascending disjoint (low, high) ranges of what arrived, and the newest arrival
        self.received: list[tuple[int, int]] = []
        self.largest_received: int | None = None
        self.largest_received_time = 0.0
        self.ack_pending = False
        self.ack_eliciting_received = 0
        self._ack_only: deque[int] = deque()

    def record_received(self, number: int, now: float, *, ack_eliciting: bool) -> bool:
        # returns whether the number arrived in order
        in_order = self.largest_received is None or number == self.largest_received + 1
        if self.largest_received is None or number > self.largest_received:
            self.largest_received = number
            self.largest_received_time = now
        if ack_eliciting:
            self.ack_eliciting_received += 1
        self._insert(number)
        if len(self.received) > Count.RANGES:
            # a peer that never acknowledges our ACK-only packets would make this grow without end
            del self.received[: len(self.received) - Count.RANGES]
        return in_order

    def _insert(self, number: int) -> None:
        ranges = self.received
        if ranges and ranges[-1][1] + 1 == number:
            # the usual case: the next number extends the newest range
            ranges[-1] = (ranges[-1][0], number)
            return
        position = 0
        while position < len(ranges) and ranges[position][1] + 1 < number:
            position += 1
        if position < len(ranges) and ranges[position][0] - 1 <= number <= ranges[position][1] + 1:
            low, high = ranges[position]
            ranges[position] = (min(low, number), max(high, number))
        else:
            ranges.insert(position, (number, number))
        # the range that grew may now touch the one after it
        if position + 1 < len(ranges) and ranges[position][1] + 1 >= ranges[position + 1][0]:
            low, _ = ranges[position]
            _, high = ranges[position + 1]
            ranges[position : position + 2] = [(low, max(high, ranges[position][1]))]

    def encode_number(self, number: int) -> bytes:
        # RFC 9000 section 17.1: enough bytes to cover twice the distance to the largest acknowledged number
        span = number + 1 if self.largest_acked is None else number - self.largest_acked
        length = min(
            (max(span.bit_length() + 1, Count.BITS_PER_BYTE) + Count.BITS_PER_BYTE - 1) // Count.BITS_PER_BYTE,
            Count.NUMBER_BYTES,
        )
        return (number & ((1 << (Count.BITS_PER_BYTE * length)) - 1)).to_bytes(length, "big")

    def decode_number(self, truncated: int, bits: int) -> int:
        # RFC 9000 appendix A.3
        if self.largest_received is None:
            return truncated
        expected = self.largest_received + 1
        window = 1 << bits
        half = window // 2
        candidate = (expected & ~(window - 1)) | truncated
        if candidate <= expected - half and candidate < Count.NUMBER_LIMIT - window:
            return candidate + window
        if candidate > expected + half and candidate >= window:
            return candidate - window
        return candidate

    def forget(self, acknowledged: int) -> None:
        # RFC 9000 section 13.2.4: the peer has seen our ACK up to this number, so those ranges need no repeating
        self.received = [(max(low, acknowledged + 1), high) for low, high in self.received if high > acknowledged]

    def ack_frame(self, now: float, ack_delay_exponent: int) -> Ack | None:
        if not self.received or self.largest_received is None:
            return None
        delay = int((now - self.largest_received_time) * Count.MICROSECONDS) >> ack_delay_exponent
        return Ack(self.largest_received, max(delay, 0), tuple(reversed(self.received)))

    def add_sent(self, packet: SentPacket) -> None:
        self.sent[packet.number] = packet
        if packet.in_flight:
            return
        # an ACK-only packet is remembered so that its acknowledgement can prune the received ranges, not forever
        self._ack_only.append(packet.number)
        if len(self._ack_only) > Count.ACK_ONLY_TRACKED:
            self.sent.pop(self._ack_only.popleft(), None)


class Recovery:
    # RFC 9002: round trip estimation, loss detection and NewReno congestion control
    def __init__(self, max_datagram_size: int) -> None:
        self._max_datagram = max_datagram_size
        self.spaces: dict[EncryptionLevel, PacketSpace] = {}
        self.latest_rtt = 0.0
        self.smoothed_rtt = Tuning.INITIAL_RTT
        self.rtt_variance = Tuning.INITIAL_RTT / 2
        self.min_rtt = 0.0
        self.first_rtt_sample: float | None = None
        self.max_ack_delay = Tuning.MAX_ACK_DELAY
        self.pto_count = 0
        self.window = max(Count.INITIAL_WINDOW_DATAGRAMS * max_datagram_size, Count.INITIAL_WINDOW_FLOOR)
        self.slow_start_threshold = float("inf")
        self.bytes_in_flight = 0
        self.recovery_start: float | None = None
        self.handshake_confirmed = False

    def space(self, level: EncryptionLevel) -> PacketSpace:
        space = self.spaces.get(level)
        if space is None:
            space = self.spaces[level] = PacketSpace()
        return space

    def on_packet_sent(self, level: EncryptionLevel, packet: SentPacket) -> None:
        space = self.space(level)
        space.add_sent(packet)
        if packet.in_flight:
            self.bytes_in_flight += packet.size
            if packet.ack_eliciting:
                space.last_ack_eliciting = packet.time

    def on_ack_received(
        self, level: EncryptionLevel, ack: Ack, now: float, ack_delay_exponent: int
    ) -> tuple[list[SentPacket], list[SentPacket]]:
        # returns the packets the frame newly acknowledges and the ones that count as lost because of it
        space = self.space(level)
        acked = [packet for number, packet in space.sent.items() if self._covers(ack, number)]
        if not acked:
            return [], []
        newest = max(acked, key=lambda packet: packet.number)
        space.largest_acked = newest.number if space.largest_acked is None else max(space.largest_acked, newest.number)
        if newest.number == ack.largest and newest.ack_eliciting:
            # RFC 9002 section 5.1: only the largest newly acknowledged packet gives a round trip sample
            delay = (ack.delay << ack_delay_exponent) / Count.MICROSECONDS
            self._update_rtt(
                now - newest.time, delay if self.handshake_confirmed else min(delay, self.max_ack_delay), now
            )
        for packet in acked:
            del space.sent[packet.number]
            if packet.in_flight:
                self.bytes_in_flight -= packet.size
                self._on_packet_acked(packet)
        lost = self.detect_lost(level, now)
        self.pto_count = 0
        return acked, lost

    @staticmethod
    def _covers(ack: Ack, number: int) -> bool:
        return any(low <= number <= high for low, high in ack.ranges)

    def detect_lost(self, level: EncryptionLevel, now: float) -> list[SentPacket]:
        # RFC 9002 section 6.1: a packet is lost once enough later ones or enough time has passed
        space = self.space(level)
        space.loss_time = None
        if space.largest_acked is None:
            return []
        delay = Tuning.TIME_THRESHOLD * max(self.latest_rtt, self.smoothed_rtt, Tuning.GRANULARITY)
        lost: list[SentPacket] = []
        for number, packet in sorted(space.sent.items()):
            if number > space.largest_acked:
                continue
            if packet.time <= now - delay or space.largest_acked >= number + Count.PACKET_THRESHOLD:
                lost.append(packet)
            else:
                due = packet.time + delay
                space.loss_time = due if space.loss_time is None else min(space.loss_time, due)
        congesting: list[SentPacket] = []
        for packet in lost:
            del space.sent[packet.number]
            if packet.in_flight:
                self.bytes_in_flight -= packet.size
                # RFC 9000 section 14.4: a lost size probe says the path is narrow, not that it is congested
                if not packet.probe:
                    congesting.append(packet)
        if congesting:
            self._on_packets_lost(congesting, now)
        return congesting

    def loss_timer(self, *, has_handshake_keys: bool) -> Timer | None:
        earliest: Timer | None = None
        for level, space in self.spaces.items():
            if space.loss_time is not None and (earliest is None or space.loss_time < earliest.when):
                earliest = Timer(space.loss_time, level, loss=True)
        if earliest is not None:
            return earliest
        # RFC 9002 section 6.2.2.1: with nothing in flight the probe timer stays off once the server has validated us
        if self.bytes_in_flight == 0 and (has_handshake_keys or self.handshake_confirmed):
            return None
        interval = self.pto_interval()
        probe: Timer | None = None
        for level, space in self.spaces.items():
            if space.last_ack_eliciting is None:
                continue
            due = space.last_ack_eliciting + interval
            if level is EncryptionLevel.APPLICATION:
                due += self.max_ack_delay * (1 << self.pto_count)
            if probe is None or due < probe.when:
                probe = Timer(due, level, loss=False)
        return probe

    def pto_interval(self) -> float:
        # RFC 9002 section 6.2.1
        return (self.smoothed_rtt + max(Tuning.VARIANCE_MULTIPLIER * self.rtt_variance, Tuning.GRANULARITY)) * (
            1 << self.pto_count
        )

    def on_pto(self) -> None:
        self.pto_count += 1

    def discard_space(self, level: EncryptionLevel) -> None:
        space = self.spaces.pop(level, None)
        if space is not None:
            for packet in space.sent.values():
                if packet.in_flight:
                    self.bytes_in_flight -= packet.size

    def can_send(self, size: int) -> bool:
        return self.bytes_in_flight + size <= self.window

    def _update_rtt(self, sample: float, ack_delay: float, now: float) -> None:
        # RFC 9002 section 5.3
        self.latest_rtt = sample
        if self.first_rtt_sample is None:
            self.min_rtt = sample
            self.smoothed_rtt = sample
            self.rtt_variance = sample / 2
            self.first_rtt_sample = now
            return
        self.min_rtt = min(self.min_rtt, sample)
        adjusted = max(sample - ack_delay, self.min_rtt)
        self.rtt_variance += Tuning.RTT_VARIANCE_WEIGHT * (abs(self.smoothed_rtt - adjusted) - self.rtt_variance)
        self.smoothed_rtt += Tuning.RTT_WEIGHT * (adjusted - self.smoothed_rtt)

    def _on_packet_acked(self, packet: SentPacket) -> None:
        # RFC 9002 section 7.3: slow start doubles per round trip, congestion avoidance adds one datagram per window
        if self.recovery_start is not None and packet.time <= self.recovery_start:
            return
        if self.window >= Count.MAXIMUM_WINDOW:
            return
        if self.window < self.slow_start_threshold:
            self.window += packet.size
        else:
            self.window += self._max_datagram * packet.size // self.window

    def _on_packets_lost(self, lost: list[SentPacket], now: float) -> None:
        # RFC 9002 sections 7.3.2 and 7.6: one reduction per recovery period, a reset on persistent congestion
        newest = max(packet.time for packet in lost)
        if self.recovery_start is not None and newest <= self.recovery_start:
            return
        self.recovery_start = now
        self.window = max(int(self.window * Tuning.LOSS_REDUCTION), Count.MINIMUM_WINDOW_DATAGRAMS * self._max_datagram)
        self.slow_start_threshold = self.window
        if self.first_rtt_sample is None:
            return
        oldest = min(packet.time for packet in lost)
        period = (
            self.smoothed_rtt
            + max(Tuning.VARIANCE_MULTIPLIER * self.rtt_variance, Tuning.GRANULARITY)
            + self.max_ack_delay
        ) * Count.PERSISTENT_CONGESTION_THRESHOLD
        if newest - oldest > period and oldest > self.first_rtt_sample:
            self.window = Count.MINIMUM_WINDOW_DATAGRAMS * self._max_datagram
