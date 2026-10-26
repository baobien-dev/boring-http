from typing import final

from boring_http.errors import ProtocolError
from boring_http.quic.packet import Stream


@final
class SendStream:
    def __init__(self, stream_id: int, max_data: int) -> None:
        self.stream_id = stream_id
        self.max_data = max_data
        self.pending: list[tuple[int, bytes]] = []
        # how much of pending[0] has gone out already; slicing the remainder off a large chunk per frame would be quadratic
        self.position = 0
        self.offset = 0
        self.ended = False
        self.fin_sent = False
        self.fin_offset: int | None = None
        self.reset_error: int | None = None
        self.reset_sent = False
        self.blocked = False
        self.blocked_reported = -1
        self.unacked = 0
        self.sent_offset = 0

    @property
    def active(self) -> bool:
        return bool(self.pending) or (self.ended and not self.fin_sent)

    def write(self, data: bytes) -> None:
        if self.ended:
            raise ProtocolError(f"stream {self.stream_id} already ended")
        if data:
            self.pending.append((self.offset, data))
            self.offset += len(data)

    def end(self) -> None:
        self.ended = True
        self.fin_offset = self.offset

    def requeue(self, frame: Stream) -> None:
        self.unacked -= 1
        if frame.data:
            if self.position:
                offset, data = self.pending[0]
                self.pending[0] = (offset + self.position, data[self.position :])
                self.position = 0
            self.pending.append((frame.offset, frame.data))
            self.pending.sort(key=lambda item: item[0])
        if frame.fin:
            self.fin_sent = False

    def next_frame(self, limit: int, connection_credit: int) -> Stream | None:
        if self.pending:
            start, data = self.pending[0]
            offset = start + self.position
            # bytes below the high-water mark went out before and are charged to the connection window already
            credit = min(
                limit,
                self.max_data - offset,
                max(self.sent_offset - offset, 0) + connection_credit,
                len(data) - self.position,
            )
            if credit <= 0:
                # STREAM_DATA_BLOCKED goes out once per limit, not once per attempt to send
                self.blocked = (
                    offset >= self.max_data and self.max_data != self.blocked_reported
                )
                if self.blocked:
                    self.blocked_reported = self.max_data
                return None
            piece = data[self.position : self.position + credit]
            if self.position + credit < len(data):
                self.position += credit
            else:
                del self.pending[0]
                self.position = 0
            fin = self.ended and not self.pending and offset + credit == self.fin_offset
            if fin:
                self.fin_sent = True
            self.sent_offset = max(self.sent_offset, offset + credit)
            self.unacked += 1
            return Stream(self.stream_id, offset, piece, fin)
        if self.ended and not self.fin_sent:
            self.fin_sent = True
            self.unacked += 1
            return Stream(self.stream_id, self.offset, b"", True)
        return None


@final
class ReceiveStream:
    def __init__(self, stream_id: int, max_data: int) -> None:
        self.stream_id = stream_id
        self.max_data = max_data
        self.consumed = 0
        self.ready = bytearray()
        self.fragments: dict[int, bytes] = {}
        self.next_offset = 0
        self.final_size: int | None = None
        self.reset_error: int | None = None
        self.stop_sent = False

    @property
    def finished(self) -> bool:
        return (
            self.final_size is not None
            and self.next_offset == self.final_size
            and not self.ready
        )

    @property
    def readable(self) -> bool:
        return (
            bool(self.ready)
            or self.final_size == self.next_offset
            or self.reset_error is not None
        )

    def on_frame(self, frame: Stream) -> int:
        end = frame.offset + len(frame.data)
        if frame.fin:
            if self.final_size is not None and self.final_size != end:
                raise ProtocolError(f"stream {self.stream_id} changed its final size")
            self.final_size = end
        if self.final_size is not None and end > self.final_size:
            raise ProtocolError(f"stream {self.stream_id} data beyond its final size")
        if end > self.max_data:
            raise ProtocolError(
                f"stream {self.stream_id} exceeded its flow control limit"
            )
        if end <= self.next_offset:
            return 0
        if frame.offset > self.next_offset:
            self.fragments[frame.offset] = frame.data
            return 0
        self.ready += frame.data[self.next_offset - frame.offset :]
        self.next_offset = end
        while (fragment := self.fragments.pop(self.next_offset, None)) is not None:
            self.ready += fragment
            self.next_offset += len(fragment)
        for offset in sorted(self.fragments):
            if offset < self.next_offset:
                fragment = self.fragments.pop(offset)
                if offset + len(fragment) > self.next_offset:
                    self.ready += fragment[self.next_offset - offset :]
                    self.next_offset = offset + len(fragment)
        return self.next_offset

    def read(self) -> bytes:
        data = bytes(self.ready)
        self.ready = bytearray()
        self.consumed += len(data)
        return data
