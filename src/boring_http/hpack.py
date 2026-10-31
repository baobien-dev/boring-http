from collections.abc import Iterable
from enum import IntEnum

from boring_http.errors import ProtocolError
from boring_http.hpack_tables import HpackTables


class Prefix(IntEnum):
    # RFC 7541 section 6: the first byte's pattern says which representation follows
    INDEXED = 0x80
    LITERAL_INDEXED = 0x40
    TABLE_SIZE_UPDATE = 0x20
    LITERAL_NEVER_INDEXED = 0x10
    LITERAL_NOT_INDEXED = 0x00
    HUFFMAN = 0x80


class Bits(IntEnum):
    # RFC 7541 sections 5.1 and 6: how many bits of the first byte hold the integer
    INDEXED = 7
    LITERAL_INDEXED = 6
    TABLE_SIZE_UPDATE = 5
    LITERAL_NOT_INDEXED = 4
    STRING_LENGTH = 7
    CONTINUATION_PAYLOAD = 0x7F
    CONTINUATION_FLAG = 0x80
    CONTINUATION_SHIFT = 7
    CONTINUATION_LIMIT = 62
    BYTE = 8
    BYTE_MASK = 0xFF
    EOS = 256


class Size(IntEnum):
    # RFC 7541 section 4.1: an entry costs its name, its value and 32 bytes
    ENTRY_OVERHEAD = 32
    DEFAULT_TABLE = 4096


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
        while value >= Bits.CONTINUATION_FLAG:
            self._data.append(value % Bits.CONTINUATION_FLAG + Bits.CONTINUATION_FLAG)
            value //= Bits.CONTINUATION_FLAG
        self._data.append(value)

    def string(self, value: bytes, prefix_bits: int = Bits.STRING_LENGTH, pattern: int = 0) -> None:
        # Huffman coded when that is shorter, plain otherwise
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
            code, length = HpackTables.HUFFMAN[byte]
            bits = (bits << length) | code
            count += length
            while count >= Bits.BYTE:
                count -= Bits.BYTE
                out.append((bits >> count) & Bits.BYTE_MASK)
            bits &= (1 << count) - 1
        if count:
            # RFC 7541 section 5.2: the last byte is filled with the most significant bits of EOS, all ones
            padding = Bits.BYTE - count
            out.append(((bits << padding) | ((1 << padding) - 1)) & Bits.BYTE_MASK)
        return bytes(out)


class BlockReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0
        self._decode_table = HuffmanTable.decoding()

    @property
    def remaining(self) -> int:
        return len(self._data) - self._position

    @property
    def position(self) -> int:
        return self._position

    def peek(self) -> int:
        if self._position >= len(self._data):
            raise ProtocolError("the HPACK block ends inside a field")
        return self._data[self._position]

    def integer(self, prefix_bits: int) -> int:
        limit = (1 << prefix_bits) - 1
        value = self._byte() & limit
        if value < limit:
            return value
        shift = 0
        while True:
            byte = self._byte()
            value += (byte & Bits.CONTINUATION_PAYLOAD) << shift
            shift += Bits.CONTINUATION_SHIFT
            if not byte & Bits.CONTINUATION_FLAG:
                return value
            if shift > Bits.CONTINUATION_LIMIT:
                raise ProtocolError("an HPACK integer runs past 62 bits")

    def string(self, prefix_bits: int = Bits.STRING_LENGTH) -> bytes:
        compressed = bool(self.peek() & (1 << prefix_bits))
        length = self.integer(prefix_bits)
        if length > self.remaining:
            raise ProtocolError("an HPACK string runs past the block")
        value = self._data[self._position : self._position + length]
        self._position += length
        return self.huffman(value) if compressed else value

    def _byte(self) -> int:
        if self._position >= len(self._data):
            raise ProtocolError("the HPACK block ends inside a field")
        value = self._data[self._position]
        self._position += 1
        return value

    def huffman(self, data: bytes) -> bytes:
        out = bytearray()
        code, length = 0, 0
        table = self._decode_table
        for byte in data:
            for bit in range(Bits.BYTE - 1, -1, -1):
                code = (code << 1) | ((byte >> bit) & 1)
                length += 1
                symbol = table.get((length, code))
                if symbol is not None:
                    if symbol == Bits.EOS:
                        raise ProtocolError("EOS inside HPACK Huffman data")
                    out.append(symbol)
                    code, length = 0, 0
        # RFC 7541 section 5.2: at most seven bits of padding, all ones
        if length >= Bits.BYTE or code != (1 << length) - 1:
            raise ProtocolError("invalid HPACK Huffman padding")
        return bytes(out)


class HuffmanTable:
    # (bit length, code) to symbol, built once from the code table
    _decoding: dict[tuple[int, int], int] | None = None

    @classmethod
    def decoding(cls) -> dict[tuple[int, int], int]:
        if cls._decoding is None:
            cls._decoding = {(length, code): symbol for symbol, (code, length) in enumerate(HpackTables.HUFFMAN)}
        return cls._decoding


class StaticTable:
    _pairs: dict[tuple[bytes, bytes], int] | None = None
    _names: dict[bytes, int] | None = None

    @classmethod
    def pair_index(cls, name: bytes, value: bytes) -> int | None:
        if cls._pairs is None:
            cls._pairs = {pair: index for index, pair in enumerate(HpackTables.STATIC, 1)}
        return cls._pairs.get((name, value))

    @classmethod
    def name_index(cls, name: bytes) -> int | None:
        if cls._names is None:
            # the first entry of a name wins, so the dict is filled from the end
            cls._names = {entry[0]: index for index, entry in reversed(list(enumerate(HpackTables.STATIC, 1)))}
        return cls._names.get(name)

    @staticmethod
    def entry(index: int) -> tuple[bytes, bytes] | None:
        return HpackTables.STATIC[index - 1] if 1 <= index <= len(HpackTables.STATIC) else None


class Encoder:
    # RFC 7541 section 6.2: credentials are never indexed, everything else goes into the dynamic table
    NEVER_INDEXED = frozenset({b"authorization", b"proxy-authorization"})

    def __init__(self) -> None:
        self._table: list[tuple[bytes, bytes]] = []
        self._size = 0
        self._capacity = int(Size.DEFAULT_TABLE)
        self._announce: int | None = None

    def set_capacity(self, capacity: int) -> None:
        # the peer's SETTINGS_HEADER_TABLE_SIZE bounds the table; the next block announces the change
        capacity = min(capacity, Size.DEFAULT_TABLE)
        if capacity != self._capacity:
            self._capacity = capacity
            self._announce = capacity
            self._evict()

    def encode(self, headers: Iterable[tuple[bytes, bytes]]) -> bytes:
        writer = BlockWriter()
        if self._announce is not None:
            writer.integer(self._announce, Bits.TABLE_SIZE_UPDATE, Prefix.TABLE_SIZE_UPDATE)
            self._announce = None
        for name, value in headers:
            pair_index, name_index = self._find(name, value)
            if pair_index is not None:
                writer.integer(pair_index, Bits.INDEXED, Prefix.INDEXED)
                continue
            if name in self.NEVER_INDEXED:
                writer.integer(name_index or 0, Bits.LITERAL_NOT_INDEXED, Prefix.LITERAL_NEVER_INDEXED)
            else:
                writer.integer(name_index or 0, Bits.LITERAL_INDEXED, Prefix.LITERAL_INDEXED)
            if name_index is None:
                writer.string(name)
            writer.string(value)
            if name not in self.NEVER_INDEXED:
                self._add(name, value)
        return writer.finish()

    def _find(self, name: bytes, value: bytes) -> tuple[int | None, int | None]:
        pair_index = StaticTable.pair_index(name, value)
        if pair_index is not None:
            return pair_index, pair_index
        name_index = StaticTable.name_index(name)
        for position, entry in enumerate(self._table):
            if entry == (name, value):
                return len(HpackTables.STATIC) + 1 + position, None
            if name_index is None and entry[0] == name:
                name_index = len(HpackTables.STATIC) + 1 + position
        return None, name_index

    def _add(self, name: bytes, value: bytes) -> None:
        self._table.insert(0, (name, value))
        self._size += len(name) + len(value) + Size.ENTRY_OVERHEAD
        self._evict()

    def _evict(self) -> None:
        while self._size > self._capacity:
            name, value = self._table.pop()
            self._size -= len(name) + len(value) + Size.ENTRY_OVERHEAD


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
            if first & Prefix.INDEXED:
                name, value = self._lookup(reader.integer(Bits.INDEXED))
            elif first & Prefix.LITERAL_INDEXED:
                index = reader.integer(Bits.LITERAL_INDEXED)
                name = self._lookup(index)[0] if index else reader.string()
                value = reader.string()
                self._add(name, value)
            elif first & Prefix.TABLE_SIZE_UPDATE:
                size = reader.integer(Bits.TABLE_SIZE_UPDATE)
                if size > self._limit:
                    raise ProtocolError(f"HPACK table size update {size} exceeds the advertised {self._limit}")
                self._capacity = size
                self._evict()
                continue
            else:
                index = reader.integer(Bits.LITERAL_NOT_INDEXED)
                name = self._lookup(index)[0] if index else reader.string()
                value = reader.string()
            headers.append((name, value))
            total += len(name) + len(value) + Size.ENTRY_OVERHEAD
            if total > self._max_list:
                raise ProtocolError(f"the header list exceeds {self._max_list} bytes")
        return headers

    def _lookup(self, index: int) -> tuple[bytes, bytes]:
        entry = StaticTable.entry(index)
        if entry is not None:
            return entry
        position = index - len(HpackTables.STATIC) - 1
        if 0 <= position < len(self._table):
            return self._table[position]
        raise ProtocolError(f"HPACK index {index} is not in the table")

    def _add(self, name: bytes, value: bytes) -> None:
        self._table.insert(0, (name, value))
        self._size += len(name) + len(value) + Size.ENTRY_OVERHEAD
        self._evict()

    def _evict(self) -> None:
        while self._size > self._capacity:
            name, value = self._table.pop()
            self._size -= len(name) + len(value) + Size.ENTRY_OVERHEAD
