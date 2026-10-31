import base64
import hashlib
import logging
import secrets
import struct
from enum import IntEnum, StrEnum
from typing import Self

from ssl2.asynchronous import AsyncTransport

from boring_http.errors import ProtocolError, WebSocketClosedError
from boring_http.headers import Headers
from boring_http.timing import Deadline, Phase
from boring_http.tracing import Event


class Opcode(IntEnum):
    # RFC 6455 section 5.2
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA


class CloseCode(IntEnum):
    # RFC 6455 section 7.4.1
    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    NO_STATUS = 1005
    ABNORMAL = 1006
    INVALID_PAYLOAD = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    INTERNAL_ERROR = 1011


class Bit(IntEnum):
    # RFC 6455 section 5.2: the two bytes every frame starts with
    FIN = 0x80
    RESERVED = 0x70
    OPCODE = 0x0F
    MASK = 0x80
    LENGTH = 0x7F


class Length(IntEnum):
    # RFC 6455 section 5.2: a length under 126 fits the first byte, 126 announces two more bytes, 127 eight
    SHORT_LIMIT = 126
    TWO_BYTES = 126
    EIGHT_BYTES = 127
    TWO_BYTE_LIMIT = 1 << 16
    CONTROL_LIMIT = 125
    HEAD = 2
    MASK_KEY = 4
    KEY_RANDOM = 16
    CLOSE_CODE = 2
    READ = 65536


class Handshake(StrEnum):
    # RFC 6455 section 4.1
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    VERSION = "13"
    UPGRADE = "websocket"
    CONNECTION = "Upgrade"


class WebSocket:
    # RFC 6455 client side over any transport: the HTTP/1.1 connection after its upgrade, or an Extended CONNECT stream
    logger = logging.getLogger("boring_http")

    def __init__(
        self,
        transport: AsyncTransport,
        leftover: bytes,
        deadline: Deadline,
        *,
        subprotocol: str | None,
        max_message_size: int,
    ) -> None:
        self._transport = transport
        self._buffer = bytearray(leftover)
        # the total covered the handshake; from here each read and write keeps only its own limit
        deadline.drop_total()
        self._deadline = deadline
        self._limit = max_message_size
        self._fragments: list[bytes] = []
        self._opcode = Opcode.CONTINUATION
        self._close_sent = False
        self.subprotocol = subprotocol
        self.close_code: int | None = None
        self.close_reason = ""
        self.logger.info("%s subprotocol=%s", Event.WEBSOCKET_OPENED, subprotocol)

    @staticmethod
    def handshake(headers: Headers, subprotocols: tuple[str, ...]) -> tuple[Headers, str]:
        # the upgrade request's headers and the key the server must answer
        key = base64.b64encode(secrets.token_bytes(Length.KEY_RANDOM)).decode("ascii")
        result = headers.copy()
        result.set("Upgrade", Handshake.UPGRADE)
        result.set("Connection", Handshake.CONNECTION)
        result.set("Sec-WebSocket-Version", Handshake.VERSION)
        result.set("Sec-WebSocket-Key", key)
        if subprotocols:
            result.set("Sec-WebSocket-Protocol", ", ".join(subprotocols))
        return result, key

    @staticmethod
    def accept(key: str) -> str:
        # RFC 6455 section 4.2.2: what Sec-WebSocket-Accept must hold for the key
        return base64.b64encode(hashlib.sha1((key + Handshake.GUID).encode("ascii")).digest()).decode("ascii")

    @property
    def closed(self) -> bool:
        return self.close_code is not None

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> str | bytes:
        try:
            return await self.receive()
        except WebSocketClosedError:
            raise StopAsyncIteration from None

    async def send(self, message: str | bytes) -> None:
        if isinstance(message, str):
            await self._write(Opcode.TEXT, message.encode())
        else:
            await self._write(Opcode.BINARY, message)

    async def ping(self, payload: bytes = b"") -> None:
        await self._write(Opcode.PING, payload)

    async def receive(self) -> str | bytes:
        # the next complete message; pings are answered and a close frame ends the socket
        while True:
            if self.close_code is not None:
                raise WebSocketClosedError(self.close_code, self.close_reason)
            final, opcode, payload = await self._read_frame()
            match opcode:
                case Opcode.PING:
                    await self._write(Opcode.PONG, payload)
                case Opcode.PONG:
                    pass
                case Opcode.CLOSE:
                    code, reason = self._close_payload(payload)
                    await self._finish(code, reason)
                case Opcode.TEXT | Opcode.BINARY | Opcode.CONTINUATION:
                    message = await self._assemble(opcode, payload, final=final)
                    if message is not None:
                        return message

    async def _assemble(self, opcode: Opcode, payload: bytes, *, final: bool) -> str | bytes | None:
        # RFC 6455 section 5.4: fragments of one message arrive in order with nothing but control frames between
        if opcode is Opcode.CONTINUATION:
            if not self._fragments:
                raise ProtocolError("a continuation frame without a message")
        elif self._fragments:
            raise ProtocolError("a new message inside a fragmented message")
        else:
            self._opcode = opcode
        self._fragments.append(payload)
        if sum(len(fragment) for fragment in self._fragments) > self._limit:
            await self.close(CloseCode.MESSAGE_TOO_BIG, "message too big")
            raise ProtocolError(f"a message exceeds {self._limit} bytes")
        if not final:
            return None
        message = b"".join(self._fragments)
        self._fragments.clear()
        if self._opcode is Opcode.BINARY:
            return message
        try:
            return message.decode()
        except UnicodeDecodeError:
            await self.close(CloseCode.INVALID_PAYLOAD, "invalid UTF-8")
            raise ProtocolError("a text message that is not valid UTF-8") from None

    async def close(self, code: int = CloseCode.NORMAL, reason: str = "") -> None:
        # RFC 6455 section 7.1.2: the close is sent, then the server's close frame is waited for
        if not self._close_sent:
            self._close_sent = True
            await self._write(Opcode.CLOSE, struct.pack("!H", code) + reason.encode())
        if self.close_code is None:
            try:
                while True:
                    _, opcode, payload = await self._read_frame()
                    if opcode is Opcode.CLOSE:
                        peer_code, peer_reason = self._close_payload(payload)
                        await self._finish(peer_code, peer_reason)
            except WebSocketClosedError, ProtocolError, ConnectionError:
                pass
        await self._transport.close()

    @staticmethod
    def _close_payload(payload: bytes) -> tuple[int, str]:
        if len(payload) < Length.CLOSE_CODE:
            return CloseCode.NO_STATUS, ""
        code = struct.unpack("!H", payload[: Length.CLOSE_CODE])[0]
        return code, payload[Length.CLOSE_CODE :].decode("utf-8", "replace")

    async def _finish(self, code: int, reason: str) -> None:
        self.close_code, self.close_reason = code, reason
        self.logger.info("%s code=%d reason=%s", Event.WEBSOCKET_CLOSED, code, reason)
        if not self._close_sent:
            self._close_sent = True
            await self._write(Opcode.CLOSE, struct.pack("!H", code))
        await self._transport.close()
        raise WebSocketClosedError(code, reason)

    async def _write(self, opcode: Opcode, payload: bytes) -> None:
        # RFC 6455 section 5.3: every frame a client sends is masked with a fresh key
        head = bytes((Bit.FIN | opcode,))
        length = len(payload)
        if length < Length.SHORT_LIMIT:
            head += bytes((Bit.MASK | length,))
        elif length < Length.TWO_BYTE_LIMIT:
            head += bytes((Bit.MASK | Length.TWO_BYTES,)) + struct.pack("!H", length)
        else:
            head += bytes((Bit.MASK | Length.EIGHT_BYTES,)) + struct.pack("!Q", length)
        mask = secrets.token_bytes(Length.MASK_KEY)
        async with self._deadline.phase(Phase.WRITE):
            await self._transport.write(head + mask + self._masked(payload, mask))

    @staticmethod
    def _masked(payload: bytes, mask: bytes) -> bytes:
        if not payload:
            return payload
        # one XOR over the whole message, instead of one per byte in Python
        repeated = (mask * (len(payload) // Length.MASK_KEY + 1))[: len(payload)]
        return (int.from_bytes(payload, "big") ^ int.from_bytes(repeated, "big")).to_bytes(len(payload), "big")

    async def _read_frame(self) -> tuple[bool, Opcode, bytes]:
        first, second = await self._read_exactly(Length.HEAD)
        if second & Bit.MASK:
            raise ProtocolError("the server sent a masked frame")
        if first & Bit.RESERVED:
            raise ProtocolError("reserved bits set without a negotiated extension")
        length = second & Bit.LENGTH
        if length == Length.TWO_BYTES:
            length = struct.unpack("!H", await self._read_exactly(2))[0]
        elif length == Length.EIGHT_BYTES:
            length = struct.unpack("!Q", await self._read_exactly(8))[0]
        try:
            opcode = Opcode(first & Bit.OPCODE)
        except ValueError:
            raise ProtocolError(f"unknown websocket opcode {first & Bit.OPCODE:#x}") from None
        final = bool(first & Bit.FIN)
        if opcode >= Opcode.CLOSE and (length > Length.CONTROL_LIMIT or not final):
            raise ProtocolError("a control frame too long or fragmented")
        if length > self._limit:
            raise ProtocolError(f"a frame exceeds {self._limit} bytes")
        return final, opcode, await self._read_exactly(length)

    async def _read_exactly(self, length: int) -> bytes:
        while len(self._buffer) < length:
            async with self._deadline.phase(Phase.READ):
                piece = await self._transport.read(Length.READ)
            if not piece:
                if self.close_code is None:
                    self.close_code, self.close_reason = CloseCode.ABNORMAL, "connection closed without a close frame"
                raise WebSocketClosedError(self.close_code, self.close_reason)
            self._buffer += piece
        data = bytes(self._buffer[:length])
        del self._buffer[:length]
        return data
