from collections import deque
from dataclasses import dataclass, field

from boring_http.quic.packet import Ack, Frame

INITIAL_RTT = 0.333
PACKET_THRESHOLD = 3
TIME_THRESHOLD = 9 / 8
GRANULARITY = 0.001
MINIMUM_WINDOW_PACKETS = 2
INITIAL_WINDOW_PACKETS = 10
LOSS_REDUCTION = 0.5
PERSISTENT_CONGESTION_THRESHOLD = 3
MAXIMUM_WINDOW = 16 << 20
MAX_RANGES = 32
TRACKED_ACK_ONLY = 256


@dataclass(slots=True)
class SentPacket:
    number: int
    time: float
    ack_eliciting: bool
    in_flight: bool
    size: int
    frames: tuple[Frame, ...]
    early: bool = False
    mtu_probe: bool = False


@dataclass(slots=True)
class PacketSpace:
    sent: dict[int, SentPacket] = field(default_factory=dict[int, SentPacket])
    largest_acked: int | None = None
    loss_time: float | None = None
    last_ack_eliciting: float | None = None
    next_number: int = 0
    received: list[tuple[int, int]] = field(default_factory=list[tuple[int, int]])
    ack_only: deque[int] = field(default_factory=deque[int])
    largest_received: int | None = None
    largest_received_time: float = 0.0
    ack_pending: bool = False
    ack_eliciting_received: int = 0

    def record_received(self, number: int, now: float, ack_eliciting: bool) -> bool:
        in_order = self.largest_received is None or number == self.largest_received + 1
        if self.largest_received is None or number > self.largest_received:
            self.largest_received = number
            self.largest_received_time = now
        if ack_eliciting:
            self.ack_eliciting_received += 1
        received = self.received
        if in_order and received:
            # the usual case: the next number extends the newest range, nothing to merge or sort
            received[-1] = (received[-1][0], number)
            return True
        for index, (low, high) in enumerate(received):
            if low <= number <= high:
                break
            if number == high + 1:
                self.received[index] = (low, number)
                self._merge()
                break
            if number == low - 1:
                self.received[index] = (number, high)
                self._merge()
                break
        else:
            self.received.append((number, number))
            self.received.sort(key=lambda span: span[0])
        # a peer that never acknowledges our ACK-only packets would otherwise make this list grow without end
        if len(self.received) > MAX_RANGES:
            del self.received[: len(self.received) - MAX_RANGES]
        return in_order

    def encode_number(self, number: int) -> bytes:
        span = number + 1 if self.largest_acked is None else number - self.largest_acked
        length = min((max(span.bit_length() + 1, 8) + 7) // 8, 4)
        return (number & ((1 << (8 * length)) - 1)).to_bytes(length, "big")

    def decode_number(self, truncated: int, bits: int) -> int:
        if self.largest_received is None:
            return truncated
        expected = self.largest_received + 1
        window = 1 << bits
        half = window // 2
        candidate = (expected & ~(window - 1)) | truncated
        if candidate <= expected - half and candidate < (1 << 62) - window:
            return candidate + window
        if candidate > expected + half and candidate >= window:
            return candidate - window
        return candidate

    def forget(self, acknowledged: int) -> None:
        # RFC 9000 section 13.2.4: once the peer has acknowledged our ACK up to this number, those ranges need no repeating
        self.received = [
            (max(low, acknowledged + 1), high)
            for low, high in self.received
            if high > acknowledged
        ]

    def ack_frame(self, now: float, ack_delay_exponent: int) -> Ack | None:
        if not self.received or self.largest_received is None:
            return None
        delay = (
            int((now - self.largest_received_time) * 1_000_000) >> ack_delay_exponent
        )
        return Ack(self.largest_received, max(delay, 0), tuple(reversed(self.received)))

    def _merge(self) -> None:
        merged: list[tuple[int, int]] = []
        for low, high in sorted(self.received, key=lambda span: span[0]):
            if merged and low <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(high, merged[-1][1]))
            else:
                merged.append((low, high))
        self.received = merged


class Recovery:
    def __init__(self, max_datagram_size: int) -> None:
        self._max_datagram = max_datagram_size
        self.spaces: dict[int, PacketSpace] = {}
        self.latest_rtt = 0.0
        self.smoothed_rtt = INITIAL_RTT
        self.rttvar = INITIAL_RTT / 2
        self.min_rtt = 0.0
        self.first_rtt_sample: float | None = None
        self.max_ack_delay = 0.025
        self.pto_count = 0
        self.window = max(INITIAL_WINDOW_PACKETS * max_datagram_size, 14720)
        self.ssthresh = float("inf")
        self.bytes_in_flight = 0
        self.recovery_start: float | None = None
        self.handshake_confirmed = False

    def space(self, level: int) -> PacketSpace:
        space = self.spaces.get(level)
        if space is None:
            space = self.spaces[level] = PacketSpace()
        return space

    def on_packet_sent(self, level: int, packet: SentPacket) -> None:
        space = self.space(level)
        space.sent[packet.number] = packet
        if packet.in_flight:
            self.bytes_in_flight += packet.size
            if packet.ack_eliciting:
                space.last_ack_eliciting = packet.time
            return
        space.ack_only.append(packet.number)
        if len(space.ack_only) > TRACKED_ACK_ONLY:
            space.sent.pop(space.ack_only.popleft(), None)

    def on_ack_received(
        self, level: int, ack: Ack, now: float, ack_delay_exponent: int
    ) -> tuple[list[SentPacket], list[SentPacket]]:
        space = self.space(level)
        acked: list[SentPacket] = []
        for number, packet in space.sent.items():
            for low, high in ack.ranges:
                if low <= number <= high:
                    acked.append(packet)
                    break
        if not acked:
            return [], []
        largest = max(packet.number for packet in acked)
        space.largest_acked = (
            largest
            if space.largest_acked is None
            else max(space.largest_acked, largest)
        )
        newest = max(acked, key=lambda packet: packet.number)
        if newest.number == ack.largest and newest.ack_eliciting:
            delay = (ack.delay << ack_delay_exponent) / 1_000_000
            self._update_rtt(
                now - newest.time,
                delay if self.handshake_confirmed else min(delay, self.max_ack_delay),
                now,
            )
        for packet in acked:
            del space.sent[packet.number]
            if packet.in_flight:
                self.bytes_in_flight -= packet.size
                self._on_packet_acked(packet)
        lost = self.detect_lost(level, now)
        self.pto_count = 0
        return acked, lost

    def detect_lost(self, level: int, now: float) -> list[SentPacket]:
        space = self.space(level)
        space.loss_time = None
        if space.largest_acked is None:
            return []
        delay = TIME_THRESHOLD * max(self.latest_rtt, self.smoothed_rtt, GRANULARITY)
        lost: list[SentPacket] = []
        for number, packet in sorted(space.sent.items()):
            if number > space.largest_acked:
                continue
            if (
                packet.time <= now - delay
                or space.largest_acked >= number + PACKET_THRESHOLD
            ):
                lost.append(packet)
            else:
                space.loss_time = (
                    packet.time + delay
                    if space.loss_time is None
                    else min(space.loss_time, packet.time + delay)
                )
        in_flight: list[SentPacket] = []
        for packet in lost:
            del space.sent[packet.number]
            if packet.in_flight:
                self.bytes_in_flight -= packet.size
                # RFC 9000 section 14.4: a lost PMTU probe says the path is narrow, not that it is congested
                if not packet.mtu_probe:
                    in_flight.append(packet)
        if in_flight:
            self._on_packets_lost(in_flight, now)
        return in_flight

    def loss_timer(self, has_handshake_keys: bool) -> tuple[float, int, bool] | None:
        earliest: tuple[float, int] | None = None
        for level, space in self.spaces.items():
            if space.loss_time is not None and (
                earliest is None or space.loss_time < earliest[0]
            ):
                earliest = (space.loss_time, level)
        if earliest is not None:
            return earliest[0], earliest[1], True
        # RFC 9002 section 6.2.2.1: with nothing in flight the PTO timer stays off once the peer has validated our address
        if self.bytes_in_flight == 0 and (
            has_handshake_keys or self.handshake_confirmed
        ):
            return None
        pto = self.pto_interval()
        candidate: tuple[float, int] | None = None
        for level, space in self.spaces.items():
            if space.last_ack_eliciting is None:
                continue
            due = (
                space.last_ack_eliciting
                + pto
                + (self.max_ack_delay * (1 << self.pto_count) if level == 3 else 0)
            )
            if candidate is None or due < candidate[0]:
                candidate = (due, level)
        return None if candidate is None else (candidate[0], candidate[1], False)

    def pto_interval(self) -> float:
        return (self.smoothed_rtt + max(4 * self.rttvar, GRANULARITY)) * (
            1 << self.pto_count
        )

    def on_pto(self) -> None:
        self.pto_count += 1

    def discard_space(self, level: int) -> None:
        space = self.spaces.pop(level, None)
        if space is not None:
            for packet in space.sent.values():
                if packet.in_flight:
                    self.bytes_in_flight -= packet.size

    def can_send(self, size: int) -> bool:
        return self.bytes_in_flight + size <= self.window

    def _update_rtt(self, sample: float, ack_delay: float, now: float) -> None:
        self.latest_rtt = sample
        if self.first_rtt_sample is None:
            self.min_rtt = sample
            self.smoothed_rtt = sample
            self.rttvar = sample / 2
            self.first_rtt_sample = now
            return
        self.min_rtt = min(self.min_rtt, sample)
        adjusted = max(sample - ack_delay, self.min_rtt)
        self.rttvar = 3 / 4 * self.rttvar + 1 / 4 * abs(self.smoothed_rtt - adjusted)
        self.smoothed_rtt = 7 / 8 * self.smoothed_rtt + 1 / 8 * adjusted

    def _on_packet_acked(self, packet: SentPacket) -> None:
        if self.recovery_start is not None and packet.time <= self.recovery_start:
            return
        if self.window >= MAXIMUM_WINDOW:
            return
        if self.window < self.ssthresh:
            self.window += packet.size
        else:
            self.window += self._max_datagram * packet.size // self.window

    def _on_packets_lost(self, lost: list[SentPacket], now: float) -> None:
        newest = max(packet.time for packet in lost)
        if self.recovery_start is not None and newest <= self.recovery_start:
            return
        self.recovery_start = now
        self.window = max(
            int(self.window * LOSS_REDUCTION),
            MINIMUM_WINDOW_PACKETS * self._max_datagram,
        )
        self.ssthresh = self.window
        if self.first_rtt_sample is not None:
            oldest = min(packet.time for packet in lost)
            duration = (
                self.smoothed_rtt
                + max(4 * self.rttvar, GRANULARITY)
                + self.max_ack_delay
            ) * PERSISTENT_CONGESTION_THRESHOLD
            if newest - oldest > duration and oldest > self.first_rtt_sample:
                self.window = MINIMUM_WINDOW_PACKETS * self._max_datagram
