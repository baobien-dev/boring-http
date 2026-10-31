from enum import IntEnum

from boring_http.errors import ProtocolError


class Varint(IntEnum):
    # RFC 9000 section 16: the two high bits of the first byte give the length, the rest the value
    LENGTH_SHIFT = 6
    LENGTH_BITS = 2
    BITS_PER_BYTE = 8
    ONE_BYTE_MAXIMUM = 0x3F
    TWO_BYTE_MAXIMUM = 0x3FFF
    FOUR_BYTE_MAXIMUM = 0x3FFFFFFF
    EIGHT_BYTE_MAXIMUM = 0x3FFFFFFFFFFFFFFF
    TWO_BYTE_PREFIX = 0x4000
    FOUR_BYTE_PREFIX = 0x80000000
    EIGHT_BYTE_PREFIX = 0xC000000000000000


class Reader:
    def __init__(self, data: bytes, position: int = 0) -> None:
        self._data = data
        self._end = len(data)
        self.position = position

    @property
    def remaining(self) -> int:
        return self._end - self.position

    def peek(self) -> int:
        if self.position >= self._end:
            raise ProtocolError("the packet ends inside a field")
        return self._data[self.position]

    def byte(self) -> int:
        if self.position >= self._end:
            raise ProtocolError("the packet ends inside a field")
        value = self._data[self.position]
        self.position += 1
        return value

    def take(self, length: int) -> bytes:
        position = self.position
        if position + length > self._end:
            raise ProtocolError("the packet ends inside a field")
        self.position = position + length
        return self._data[position : position + length]

    def rest(self) -> bytes:
        return self.take(self.remaining)

    def varint(self) -> int:
        position = self.position
        if position >= self._end:
            raise ProtocolError("the packet ends inside a field")
        first = self._data[position]
        length = 1 << (first >> Varint.LENGTH_SHIFT)
        if length == 1:
            self.position = position + 1
            return first & Varint.ONE_BYTE_MAXIMUM
        end = position + length
        if end > self._end:
            raise ProtocolError("the packet ends inside a field")
        self.position = end
        mask = (1 << (Varint.BITS_PER_BYTE * length - Varint.LENGTH_BITS)) - 1
        return int.from_bytes(self._data[position:end], "big") & mask


class Writer:
    def __init__(self) -> None:
        self._data = bytearray()

    def __len__(self) -> int:
        return len(self._data)

    def byte(self, value: int) -> None:
        self._data.append(value)

    def put(self, data: bytes) -> None:
        self._data += data

    def varint(self, value: int) -> None:
        if value <= Varint.ONE_BYTE_MAXIMUM:
            self._data.append(value)
        elif value <= Varint.TWO_BYTE_MAXIMUM:
            self._data += (value | Varint.TWO_BYTE_PREFIX).to_bytes(2, "big")
        else:
            self._data += self.encode_varint(value)

    def finish(self) -> bytes:
        return bytes(self._data)

    @staticmethod
    def varint_length(value: int) -> int:
        if value <= Varint.ONE_BYTE_MAXIMUM:
            return 1
        if value <= Varint.TWO_BYTE_MAXIMUM:
            return 2
        return 4 if value <= Varint.FOUR_BYTE_MAXIMUM else 8

    @staticmethod
    def encode_varint(value: int) -> bytes:
        if value <= Varint.ONE_BYTE_MAXIMUM:
            return bytes((value,))
        if value <= Varint.TWO_BYTE_MAXIMUM:
            return (value | Varint.TWO_BYTE_PREFIX).to_bytes(2, "big")
        if value <= Varint.FOUR_BYTE_MAXIMUM:
            return (value | Varint.FOUR_BYTE_PREFIX).to_bytes(4, "big")
        if value <= Varint.EIGHT_BYTE_MAXIMUM:
            return (value | Varint.EIGHT_BYTE_PREFIX).to_bytes(8, "big")
        raise ValueError(f"{value} does not fit a QUIC varint")
