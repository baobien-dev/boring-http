from collections.abc import Iterable

from boring_http.errors import ProtocolError
from boring_http.hpack_tables import HUFFMAN_CODES, STATIC_TABLE

NEVER_INDEXED = frozenset({b"authorization", b"proxy-authorization"})
ENTRY_OVERHEAD = 32
DEFAULT_CAPACITY = 4096
EOS = 256
DECODE_TABLE = {
    (length, code): symbol for symbol, (code, length) in enumerate(HUFFMAN_CODES)
}
STATIC_PAIRS = {pair: index for index, pair in enumerate(STATIC_TABLE, 1)}
STATIC_NAMES = {
    name: index for index, (name, _) in reversed(list(enumerate(STATIC_TABLE, 1)))
}


class BlockWriter:
    def __init__(self) -> None:
        self._data = bytearray()

    def integer(self, value: int, prefix_bits: int, first_byte: int) -> None:
        limit = (1 << prefix_bits) - 1
        if value < limit:
            self._data.append(first_byte | value)
            return
        self._data.append(first_byte | limit)
        value -= limit
        while value >= 128:
            self._data.append(value % 128 + 128)
            value //= 128
        self._data.append(value)

    def string(self, value: bytes, prefix_bits: int = 7, pattern: int = 0x00) -> None:
        encoded = self.huffman(value)
        if len(encoded) < len(value):
            self.integer(len(encoded), prefix_bits, pattern | (1 << prefix_bits))
            self._data += encoded
        else:
            self.integer(len(value), prefix_bits, pattern)
            self._data += value

    def finish(self) -> bytes:
        return bytes(self._data)

    @staticmethod
    def huffman(data: bytes) -> bytes:
        out = bytearray()
        bits, count = 0, 0
        for byte in data:
            code, length = HUFFMAN_CODES[byte]
            bits = (bits << length) | code
            count += length
            while count >= 8:
                count -= 8
                out.append((bits >> count) & 0xFF)
            bits &= (1 << count) - 1
        if count:
            out.append(((bits << (8 - count)) | ((1 << (8 - count)) - 1)) & 0xFF)
        return bytes(out)


class BlockReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._position

    def peek(self) -> int:
        if self._position >= len(self._data):
            raise ProtocolError("HPACK block ended inside a field")
        return self._data[self._position]

    def integer(self, prefix_bits: int) -> int:
        limit = (1 << prefix_bits) - 1
        value = self._byte() & limit
        if value < limit:
            return value
        shift = 0
        while True:
            byte = self._byte()
            value += (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value
            if shift > 62:
                raise ProtocolError("HPACK integer too large")

    def string(self, prefix_bits: int = 7) -> bytes:
        compressed = bool(self.peek() & (1 << prefix_bits))
        length = self.integer(prefix_bits)
        if length > self.remaining:
            raise ProtocolError("HPACK string runs past the block")
        value = self._data[self._position : self._position + length]
        self._position += length
        return self.huffman(value) if compressed else value

    def _byte(self) -> int:
        if self._position >= len(self._data):
            raise ProtocolError("HPACK block ended inside a field")
        value = self._data[self._position]
        self._position += 1
        return value

    @staticmethod
    def huffman(data: bytes) -> bytes:
        out = bytearray()
        code, length = 0, 0
        for byte in data:
            for bit in range(7, -1, -1):
                code = (code << 1) | ((byte >> bit) & 1)
                length += 1
                symbol = DECODE_TABLE.get((length, code))
                if symbol is not None:
                    if symbol == EOS:
                        raise ProtocolError("EOS inside HPACK huffman data")
                    out.append(symbol)
                    code, length = 0, 0
        if length > 7 or code != (1 << length) - 1:
            raise ProtocolError("invalid HPACK huffman padding")
        return bytes(out)


class Encoder:
    def __init__(self) -> None:
        self._table: list[tuple[bytes, bytes]] = []
        self._size = 0
        self._capacity = DEFAULT_CAPACITY
        self._announce: int | None = None

    def set_capacity(self, capacity: int) -> None:
        capacity = min(capacity, DEFAULT_CAPACITY)
        if capacity != self._capacity:
            self._capacity = capacity
            self._announce = capacity
            self._evict()

    def encode(self, headers: Iterable[tuple[bytes, bytes]]) -> bytes:
        writer = BlockWriter()
        if self._announce is not None:
            writer.integer(self._announce, 5, 0x20)
            self._announce = None
        for name, value in headers:
            pair_index, name_index = self._find(name, value)
            if pair_index is not None:
                writer.integer(pair_index, 7, 0x80)
                continue
            if name in NEVER_INDEXED:
                writer.integer(name_index or 0, 4, 0x10)
            else:
                writer.integer(name_index or 0, 6, 0x40)
            if name_index is None:
                writer.string(name)
            writer.string(value)
            if name not in NEVER_INDEXED:
                self._add(name, value)
        return writer.finish()

    def _find(self, name: bytes, value: bytes) -> tuple[int | None, int | None]:
        pair_index = STATIC_PAIRS.get((name, value))
        if pair_index is not None:
            return pair_index, pair_index
        name_index = STATIC_NAMES.get(name)
        for position, entry in enumerate(self._table):
            if entry == (name, value):
                return len(STATIC_TABLE) + 1 + position, None
            if name_index is None and entry[0] == name:
                name_index = len(STATIC_TABLE) + 1 + position
        return None, name_index

    def _add(self, name: bytes, value: bytes) -> None:
        self._table.insert(0, (name, value))
        self._size += len(name) + len(value) + ENTRY_OVERHEAD
        self._evict()

    def _evict(self) -> None:
        while self._size > self._capacity:
            name, value = self._table.pop()
            self._size -= len(name) + len(value) + ENTRY_OVERHEAD


class Decoder:
    def __init__(self, capacity: int, max_header_list_size: int) -> None:
        self._table: list[tuple[bytes, bytes]] = []
        self._size = 0
        self._capacity = capacity
        self._limit = capacity
        self._max_list = max_header_list_size

    def decode(self, block: bytes) -> list[tuple[bytes, bytes]]:
        reader = BlockReader(block)
        headers: list[tuple[bytes, bytes]] = []
        total = 0
        while reader.remaining:
            first = reader.peek()
            if first & 0x80:
                name, value = self._lookup(reader.integer(7))
            elif first & 0x40:
                index = reader.integer(6)
                name = self._lookup(index)[0] if index else reader.string()
                value = reader.string()
                self._add(name, value)
            elif first & 0x20:
                size = reader.integer(5)
                if size > self._limit:
                    raise ProtocolError(
                        f"HPACK table size update {size} exceeds the advertised {self._limit}"
                    )
                self._capacity = size
                self._evict()
                continue
            else:
                index = reader.integer(4)
                name = self._lookup(index)[0] if index else reader.string()
                value = reader.string()
            headers.append((name, value))
            total += len(name) + len(value) + ENTRY_OVERHEAD
            if total > self._max_list:
                raise ProtocolError(f"header list exceeds {self._max_list} bytes")
        return headers

    def _lookup(self, index: int) -> tuple[bytes, bytes]:
        if 1 <= index <= len(STATIC_TABLE):
            return STATIC_TABLE[index - 1]
        position = index - len(STATIC_TABLE) - 1
        if 0 <= position < len(self._table):
            return self._table[position]
        raise ProtocolError(f"HPACK index {index} is not in the table")

    def _add(self, name: bytes, value: bytes) -> None:
        self._table.insert(0, (name, value))
        self._size += len(name) + len(value) + ENTRY_OVERHEAD
        self._evict()

    def _evict(self) -> None:
        while self._size > self._capacity:
            name, value = self._table.pop()
            self._size -= len(name) + len(value) + ENTRY_OVERHEAD
