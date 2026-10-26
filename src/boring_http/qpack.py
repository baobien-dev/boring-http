import asyncio
from collections.abc import Iterable

from boring_http.errors import ProtocolError
from boring_http.hpack import BlockReader, BlockWriter
from boring_http.qpack_tables import STATIC_TABLE

STATIC_PAIRS = {pair: index for index, pair in enumerate(STATIC_TABLE)}
STATIC_NAMES = {
    name: index for index, (name, _) in reversed(list(enumerate(STATIC_TABLE)))
}
ENTRY_OVERHEAD = 32
ENCODER_STREAM_LIMIT = 1 << 20


class Qpack:
    def __init__(self, maximum_capacity: int) -> None:
        self._maximum = maximum_capacity
        self._capacity = 0
        self._entries: list[tuple[bytes, bytes]] = []
        self._dropped = 0
        self._size = 0
        self._insert_count = 0
        self._pending = bytearray()
        self._instructions = BlockWriter()
        self._waiters: list[asyncio.Future[None]] = []

    def encode(self, headers: Iterable[tuple[bytes, bytes]]) -> bytes:
        writer = BlockWriter()
        writer.integer(0, 8, 0x00)
        writer.integer(0, 7, 0x00)
        for name, value in headers:
            index = STATIC_PAIRS.get((name, value))
            if index is not None:
                writer.integer(index, 6, 0xC0)
                continue
            name_index = STATIC_NAMES.get(name)
            if name_index is not None:
                writer.integer(name_index, 4, 0x50)
            else:
                writer.string(name, 3, 0x20)
            writer.string(value)
        return writer.finish()

    def decode(self, block: bytes, stream_id: int) -> list[tuple[bytes, bytes]] | None:
        reader = BlockReader(block)
        required = self._required_insert_count(reader.integer(8))
        if required > self._insert_count:
            return None
        sign = bool(reader.peek() & 0x80)
        delta = reader.integer(7)
        base = required - delta - 1 if sign else required + delta
        headers: list[tuple[bytes, bytes]] = []
        while reader.remaining:
            first = reader.peek()
            if first & 0x80:
                index = reader.integer(6)
                headers.append(
                    self._static(index)
                    if first & 0x40
                    else self._dynamic(base - 1 - index)
                )
            elif first & 0x40:
                index = reader.integer(4)
                name = (
                    self._static(index)
                    if first & 0x10
                    else self._dynamic(base - 1 - index)
                )[0]
                headers.append((name, reader.string()))
            elif first & 0x20:
                name = reader.string(3)
                headers.append((name, reader.string()))
            elif first & 0x10:
                headers.append(self._dynamic(base + reader.integer(4)))
            else:
                name = self._dynamic(base + reader.integer(3))[0]
                headers.append((name, reader.string()))
        if required:
            self._instructions.integer(stream_id, 7, 0x80)
        return headers

    def feed_encoder(self, data: bytes) -> None:
        self._pending += data
        if len(self._pending) > ENCODER_STREAM_LIMIT:
            raise ProtocolError("QPACK encoder instruction exceeds 1 MiB")
        before = self._insert_count
        while self._pending:
            consumed = self._instruction(bytes(self._pending))
            if consumed == 0:
                break
            del self._pending[:consumed]
        if self._insert_count > before:
            self._instructions.integer(self._insert_count - before, 6, 0x00)
            for waiter in self._waiters:
                if not waiter.done():
                    waiter.set_result(None)
            self._waiters.clear()

    def cancel(self, stream_id: int) -> None:
        self._instructions.integer(stream_id, 6, 0x40)

    def take_instructions(self) -> bytes:
        data = self._instructions.finish()
        self._instructions = BlockWriter()
        return data

    async def wait(self) -> None:
        waiter = asyncio.get_running_loop().create_future()
        self._waiters.append(waiter)
        await waiter

    def _instruction(self, data: bytes) -> int:
        first = data[0]
        if first & 0x80:
            parsed = self._integer(data, 0, 6)
            if parsed is None:
                return 0
            index, position = parsed
            value = self._string(data, position)
            if value is None:
                return 0
            name = (
                self._static(index)
                if first & 0x40
                else self._dynamic(self._insert_count - 1 - index)
            )[0]
            self._insert(name, value[0])
            return value[1]
        if first & 0x40:
            name = self._string(data, 0, 5)
            if name is None:
                return 0
            value = self._string(data, name[1])
            if value is None:
                return 0
            self._insert(name[0], value[0])
            return value[1]
        parsed = self._integer(data, 0, 5)
        if parsed is None:
            return 0
        if first & 0x20:
            self._set_capacity(parsed[0])
        else:
            name, value = self._dynamic(self._insert_count - 1 - parsed[0])
            self._insert(name, value)
        return parsed[1]

    def _insert(self, name: bytes, value: bytes) -> None:
        size = len(name) + len(value) + ENTRY_OVERHEAD
        if size > self._capacity:
            raise ProtocolError("QPACK entry larger than the dynamic table")
        while self._size + size > self._capacity:
            self._evict()
        self._entries.append((name, value))
        self._size += size
        self._insert_count += 1

    def _set_capacity(self, capacity: int) -> None:
        if capacity > self._maximum:
            raise ProtocolError(
                f"QPACK capacity {capacity} above the advertised {self._maximum}"
            )
        self._capacity = capacity
        while self._size > capacity:
            self._evict()

    def _evict(self) -> None:
        name, value = self._entries.pop(0)
        self._size -= len(name) + len(value) + ENTRY_OVERHEAD
        self._dropped += 1

    def _dynamic(self, absolute: int) -> tuple[bytes, bytes]:
        position = absolute - self._dropped
        if not 0 <= position < len(self._entries):
            raise ProtocolError(
                f"QPACK dynamic table index {absolute} is not available"
            )
        return self._entries[position]

    def _required_insert_count(self, encoded: int) -> int:
        # RFC 9204 section 4.5.1.1
        if encoded == 0:
            return 0
        full_range = 2 * (self._maximum // ENTRY_OVERHEAD)
        if encoded > full_range:
            raise ProtocolError("QPACK required insert count outside its range")
        maximum = self._insert_count + self._maximum // ENTRY_OVERHEAD
        wrap = maximum // full_range * full_range
        required = wrap + encoded - 1
        if required > maximum:
            if required <= full_range:
                raise ProtocolError("QPACK required insert count outside its range")
            required -= full_range
        if required == 0:
            raise ProtocolError("QPACK required insert count outside its range")
        return required

    @staticmethod
    def _static(index: int) -> tuple[bytes, bytes]:
        if index >= len(STATIC_TABLE):
            raise ProtocolError(f"QPACK static index {index} out of range")
        return STATIC_TABLE[index]

    @staticmethod
    def _integer(
        data: bytes, position: int, prefix_bits: int
    ) -> tuple[int, int] | None:
        if position >= len(data):
            return None
        limit = (1 << prefix_bits) - 1
        value = data[position] & limit
        position += 1
        if value < limit:
            return value, position
        shift = 0
        while True:
            if position >= len(data):
                return None
            byte = data[position]
            position += 1
            value += (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value, position
            if shift > 62:
                raise ProtocolError("QPACK integer too large")

    @classmethod
    def _string(
        cls, data: bytes, position: int, prefix_bits: int = 7
    ) -> tuple[bytes, int] | None:
        if position >= len(data):
            return None
        compressed = bool(data[position] & (1 << prefix_bits))
        parsed = cls._integer(data, position, prefix_bits)
        if parsed is None:
            return None
        length, position = parsed
        if position + length > len(data):
            return None
        value = data[position : position + length]
        return (BlockReader.huffman(value) if compressed else value), position + length
