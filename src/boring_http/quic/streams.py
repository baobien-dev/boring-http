from boring_http.errors import ProtocolError
from boring_http.quic.packet import Stream


class SendStream:
    # RFC 9000 section 3.1: the sending half of one stream, from the application's writes to STREAM frames
    def __init__(self, stream_id: int, max_data: int) -> None:
        self.stream_id = stream_id
        self.max_data = max_data
        # (offset, data) chunks not yet sent, in offset order; the first may be partly sent up to position
        self.pending: list[tuple[int, bytes]] = []
        self.position = 0
        # the stream's write offset, the highest offset ever sent, and how far the FIN lies
        self.offset = 0
        self.sent_offset = 0
        self.fin_offset: int | None = None
        self.fin_sent = False
        self.reset_error: int | None = None
        self.unacked = 0
        # a STREAM_DATA_BLOCKED goes out once per limit, not once per attempt
        self.blocked = False
        self.blocked_reported: int | None = None

    @property
    def ended(self) -> bool:
        return self.fin_offset is not None

    @property
    def active(self) -> bool:
        return bool(self.pending) or (self.ended and not self.fin_sent)

    @property
    def unsent(self) -> int:
        return sum(len(data) for _, data in self.pending) - self.position

    def write(self, data: bytes) -> None:
        if self.ended:
            raise ProtocolError(f"stream {self.stream_id} already ended")
        if data:
            self.pending.append((self.offset, data))
            self.offset += len(data)

    def end(self) -> None:
        self.fin_offset = self.offset

    def requeue(self, frame: Stream) -> None:
        # a lost frame's bytes go out again at their offset; the FIN too when it was in the frame
        self.unacked -= 1
        if frame.data:
            if self.position:
                offset, data = self.pending[0]
                self.pending[0] = (offset + self.position, data[self.position :])
                self.position = 0
            self.pending.append((frame.offset, frame.data))
            self.pending.sort(key=lambda chunk: chunk[0])
        if frame.fin:
            self.fin_sent = False

    def next_frame(self, limit: int, connection_credit: int) -> Stream | None:
        if not self.pending:
            if self.ended and not self.fin_sent:
                self.fin_sent = True
                self.unacked += 1
                return Stream(self.stream_id, self.offset, b"", fin=True)
            return None
        start, data = self.pending[0]
        offset = start + self.position
        # bytes below the high-water mark went out before and were charged to the connection window then
        allowance = min(
            limit,
            self.max_data - offset,
            max(self.sent_offset - offset, 0) + connection_credit,
            len(data) - self.position,
        )
        if allowance <= 0:
            self.blocked = offset >= self.max_data and self.max_data != self.blocked_reported
            if self.blocked:
                self.blocked_reported = self.max_data
            return None
        piece = data[self.position : self.position + allowance]
        if self.position + allowance < len(data):
            self.position += allowance
        else:
            del self.pending[0]
            self.position = 0
        end = offset + allowance
        fin = self.ended and not self.pending and end == self.fin_offset
        if fin:
            self.fin_sent = True
        self.sent_offset = max(self.sent_offset, end)
        self.unacked += 1
        return Stream(self.stream_id, offset, piece, fin=fin)


class ReceiveStream:
    # RFC 9000 section 3.2: the receiving half of one stream, from STREAM frames to bytes in order
    def __init__(self, stream_id: int, max_data: int) -> None:
        self.stream_id = stream_id
        self.max_data = max_data
        # what the application took, which is what moves max_data
        self.read = 0
        # in-order data the application has not been handed yet, and out-of-order data by offset
        self.chunks: list[bytes] = []
        self.fragments: dict[int, bytes] = {}
        self.next_offset = 0
        self.final_size: int | None = None
        self.stop_sent = False

    @property
    def finished(self) -> bool:
        return self.final_size is not None and self.next_offset == self.final_size

    def on_frame(self, frame: Stream) -> bytes:
        # returns what the frame makes readable in order; a frame that arrives in order hands its bytes on as they are
        end = frame.offset + len(frame.data)
        if frame.fin:
            if self.final_size is not None and self.final_size != end:
                raise ProtocolError(f"stream {self.stream_id} changed its final size")
            self.final_size = end
        if self.final_size is not None and end > self.final_size:
            raise ProtocolError(f"stream {self.stream_id} carries data beyond its final size")
        if end > self.max_data:
            raise ProtocolError(f"stream {self.stream_id} exceeded its flow control limit")
        if end <= self.next_offset:
            return b""
        if frame.offset > self.next_offset:
            self.fragments[frame.offset] = frame.data
            return b""
        data = frame.data if frame.offset == self.next_offset else frame.data[self.next_offset - frame.offset :]
        self.next_offset = end
        if not self.fragments:
            return data
        pieces = [data]
        for offset in sorted(self.fragments):
            if offset > self.next_offset:
                break
            fragment = self.fragments.pop(offset)
            fragment_end = offset + len(fragment)
            if fragment_end > self.next_offset:
                pieces.append(fragment[self.next_offset - offset :])
                self.next_offset = fragment_end
        return b"".join(pieces)
