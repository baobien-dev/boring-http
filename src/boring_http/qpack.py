import asyncio
from collections.abc import Iterable
from enum import IntEnum
from typing import override

from boring_http.errors import ProtocolError
from boring_http.hpack import BlockReader, BlockWriter
from boring_http.qpack_tables import QpackTables


class Pattern(IntEnum):
    # RFC 9204 sections 4.3 to 4.5: the first byte patterns of field lines and instructions
    INDEXED = 0x80
    INDEXED_STATIC = 0x40
    POST_BASE_INDEXED = 0x10
    NAME_REFERENCE = 0x40
    NAME_REFERENCE_STATIC = 0x10
    LITERAL_NAME = 0x20
    NEGATIVE_BASE = 0x80
    INSERT_NAME_REFERENCE = 0x80
    INSERT_STATIC_NAME = 0x40
    INSERT_LITERAL_NAME = 0x40
    SET_CAPACITY = 0x20
    SECTION_ACKNOWLEDGMENT = 0x80
    STREAM_CANCELLATION = 0x40
    INSERT_COUNT_INCREMENT = 0x00


class Bits(IntEnum):
    # RFC 9204 sections 4.3 to 4.5: how many bits of the first byte hold the integer
    REQUIRED_INSERT_COUNT = 8
    DELTA_BASE = 7
    INDEXED = 6
    POST_BASE_INDEXED = 4
    NAME_REFERENCE = 4
    POST_BASE_NAME_REFERENCE = 3
    LITERAL_NAME = 3
    VALUE = 7
    CAPACITY = 5
    INSERT_NAME_REFERENCE = 6
    INSERT_LITERAL_NAME = 5
    DUPLICATE = 5
    SECTION_ACKNOWLEDGMENT = 7
    STREAM_CANCELLATION = 6
    INSERT_COUNT_INCREMENT = 6


class Size(IntEnum):
    # RFC 9204 section 3.2.1: an entry costs its name, its value and 32 bytes
    ENTRY_OVERHEAD = 32
    ENCODER_STREAM_LIMIT = 1 << 20


class IncompleteError(Exception):
    # an instruction whose end has not arrived yet; the rest comes with the next piece of the encoder stream
    pass


class InstructionReader(BlockReader):
    # reads encoder instructions and tells a cut-off instruction apart from a malformed one
    @override
    def peek(self) -> int:
        if self.remaining <= 0:
            raise IncompleteError
        return super().peek()

    @override
    def _byte(self) -> int:
        if self.remaining <= 0:
            raise IncompleteError
        return super()._byte()

    @override
    def string(self, prefix_bits: int = Bits.VALUE) -> bytes:
        compressed = bool(self.peek() & (1 << prefix_bits))
        length = self.integer(prefix_bits)
        if length > self.remaining:
            raise IncompleteError
        value = self._data[self._position : self._position + length]
        self._position += length
        return self.huffman(value) if compressed else value


class StaticTable:
    _pairs: dict[tuple[bytes, bytes], int] | None = None
    _names: dict[bytes, int] | None = None

    @classmethod
    def pair_index(cls, name: bytes, value: bytes) -> int | None:
        if cls._pairs is None:
            cls._pairs = {pair: index for index, pair in enumerate(QpackTables.STATIC)}
        return cls._pairs.get((name, value))

    @classmethod
    def name_index(cls, name: bytes) -> int | None:
        if cls._names is None:
            # the first entry of a name wins, so the dict is filled from the end
            cls._names = {entry[0]: index for index, entry in reversed(list(enumerate(QpackTables.STATIC)))}
        return cls._names.get(name)

    @staticmethod
    def entry(index: int) -> tuple[bytes, bytes]:
        if index >= len(QpackTables.STATIC):
            raise ProtocolError(f"QPACK static index {index} is out of range")
        return QpackTables.STATIC[index]


class Qpack:
    # RFC 9204 for one HTTP/3 connection: an encoder that uses the static table only, so no block it writes can
    # ever wait on the peer, and a decoder that follows the peer's dynamic table through the encoder stream
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
        writer.integer(0, Bits.REQUIRED_INSERT_COUNT, 0)
        writer.integer(0, Bits.DELTA_BASE, 0)
        for name, value in headers:
            index = StaticTable.pair_index(name, value)
            if index is not None:
                writer.integer(index, Bits.INDEXED, Pattern.INDEXED | Pattern.INDEXED_STATIC)
                continue
            name_index = StaticTable.name_index(name)
            if name_index is not None:
                writer.integer(name_index, Bits.NAME_REFERENCE, Pattern.NAME_REFERENCE | Pattern.NAME_REFERENCE_STATIC)
            else:
                writer.string(name, Bits.LITERAL_NAME, Pattern.LITERAL_NAME)
            writer.string(value)
        return writer.finish()

    def decode(self, block: bytes, stream_id: int) -> list[tuple[bytes, bytes]] | None:
        # None while the block refers to table entries the encoder stream has not delivered yet
        reader = BlockReader(block)
        required = self._required_insert_count(reader.integer(Bits.REQUIRED_INSERT_COUNT))
        if required > self._insert_count:
            return None
        negative = bool(reader.peek() & Pattern.NEGATIVE_BASE)
        delta = reader.integer(Bits.DELTA_BASE)
        base = required - delta - 1 if negative else required + delta
        headers: list[tuple[bytes, bytes]] = []
        while reader.remaining:
            first = reader.peek()
            if first & Pattern.INDEXED:
                index = reader.integer(Bits.INDEXED)
                headers.append(
                    StaticTable.entry(index) if first & Pattern.INDEXED_STATIC else self._dynamic(base - 1 - index)
                )
            elif first & Pattern.NAME_REFERENCE:
                index = reader.integer(Bits.NAME_REFERENCE)
                entry = (
                    StaticTable.entry(index)
                    if first & Pattern.NAME_REFERENCE_STATIC
                    else self._dynamic(base - 1 - index)
                )
                headers.append((entry[0], reader.string()))
            elif first & Pattern.LITERAL_NAME:
                name = reader.string(Bits.LITERAL_NAME)
                headers.append((name, reader.string()))
            elif first & Pattern.POST_BASE_INDEXED:
                headers.append(self._dynamic(base + reader.integer(Bits.POST_BASE_INDEXED)))
            else:
                entry = self._dynamic(base + reader.integer(Bits.POST_BASE_NAME_REFERENCE))
                headers.append((entry[0], reader.string()))
        if required:
            # RFC 9204 section 4.4.1: a block that used the dynamic table is acknowledged
            self._instructions.integer(stream_id, Bits.SECTION_ACKNOWLEDGMENT, Pattern.SECTION_ACKNOWLEDGMENT)
        return headers

    def feed_encoder(self, data: bytes) -> None:
        self._pending += data
        if len(self._pending) > Size.ENCODER_STREAM_LIMIT:
            raise ProtocolError("a QPACK encoder instruction longer than 1 MiB")
        before = self._insert_count
        while self._pending:
            reader = InstructionReader(bytes(self._pending))
            try:
                self._instruction(reader)
            except IncompleteError:
                break
            del self._pending[: reader.position]
        if self._insert_count > before:
            self._instructions.integer(
                self._insert_count - before, Bits.INSERT_COUNT_INCREMENT, Pattern.INSERT_COUNT_INCREMENT
            )
            for waiter in self._waiters:
                if not waiter.done():
                    waiter.set_result(None)
            self._waiters.clear()

    def cancel(self, stream_id: int) -> None:
        self._instructions.integer(stream_id, Bits.STREAM_CANCELLATION, Pattern.STREAM_CANCELLATION)

    def take_instructions(self) -> bytes:
        data = self._instructions.finish()
        self._instructions = BlockWriter()
        return data

    async def wait(self) -> None:
        waiter = asyncio.get_running_loop().create_future()
        self._waiters.append(waiter)
        await waiter

    def _instruction(self, reader: InstructionReader) -> None:
        # RFC 9204 section 4.3: one encoder instruction, by its first byte
        first = reader.peek()
        if first & Pattern.INSERT_NAME_REFERENCE:
            index = reader.integer(Bits.INSERT_NAME_REFERENCE)
            value = reader.string()
            source = (
                StaticTable.entry(index)
                if first & Pattern.INSERT_STATIC_NAME
                else self._dynamic(self._insert_count - 1 - index)
            )
            self._insert(source[0], value)
        elif first & Pattern.INSERT_LITERAL_NAME:
            name = reader.string(Bits.INSERT_LITERAL_NAME)
            self._insert(name, reader.string())
        elif first & Pattern.SET_CAPACITY:
            self._set_capacity(reader.integer(Bits.CAPACITY))
        else:
            name, value = self._dynamic(self._insert_count - 1 - reader.integer(Bits.DUPLICATE))
            self._insert(name, value)

    def _insert(self, name: bytes, value: bytes) -> None:
        size = len(name) + len(value) + Size.ENTRY_OVERHEAD
        if size > self._capacity:
            raise ProtocolError("a QPACK entry larger than the dynamic table")
        while self._size + size > self._capacity:
            self._evict()
        self._entries.append((name, value))
        self._size += size
        self._insert_count += 1

    def _set_capacity(self, capacity: int) -> None:
        if capacity > self._maximum:
            raise ProtocolError(f"QPACK capacity {capacity} above the advertised {self._maximum}")
        self._capacity = capacity
        while self._size > capacity:
            self._evict()

    def _evict(self) -> None:
        name, value = self._entries.pop(0)
        self._size -= len(name) + len(value) + Size.ENTRY_OVERHEAD
        self._dropped += 1

    def _dynamic(self, absolute: int) -> tuple[bytes, bytes]:
        position = absolute - self._dropped
        if not 0 <= position < len(self._entries):
            raise ProtocolError(f"QPACK dynamic table index {absolute} is not available")
        return self._entries[position]

    def _required_insert_count(self, encoded: int) -> int:
        # RFC 9204 section 4.5.1.1
        if encoded == 0:
            return 0
        max_entries = self._maximum // Size.ENTRY_OVERHEAD
        full_range = 2 * max_entries
        if encoded > full_range:
            raise ProtocolError("a QPACK required insert count outside its range")
        max_value = self._insert_count + max_entries
        wrapped = max_value // full_range * full_range
        required = wrapped + encoded - 1
        if required > max_value:
            if required <= full_range:
                raise ProtocolError("a QPACK required insert count outside its range")
            required -= full_range
        if required == 0:
            raise ProtocolError("a QPACK required insert count outside its range")
        return required
