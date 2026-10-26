import base64
import hashlib
import os
import secrets
import struct
from enum import IntEnum
from typing import Self

from ssl2 import AsyncTransport

from boring_http.errors import ProtocolError, WebSocketClosed
from boring_http.message import Headers
from boring_http.timing import Deadline

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
VERSION = "13"


class Opcode(IntEnum):
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA


class WebSocket:
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
        # the total covered the handshake; from here each read and write keeps only its phase limit
        deadline.drop_total()
        self._deadline = deadline
        self._limit = max_message_size
        self._fragments: list[bytes] = []
        self._opcode = Opcode.CONTINUATION
        self._close_sent = False
        self.subprotocol = subprotocol
        self.close_code: int | None = None
        self.close_reason = ""

    @staticmethod
    def handshake(
        headers: Headers, subprotocols: tuple[str, ...]
    ) -> tuple[Headers, str]:
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        required = [
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Version", VERSION),
            ("Sec-WebSocket-Key", key),
        ]
        if subprotocols:
            required.append(("Sec-WebSocket-Protocol", ", ".join(subprotocols)))
        result = headers.copy()
        for name, value in required:
            result.set(name, value)
        return result, key

    @staticmethod
    def accept(key: str) -> str:
        return base64.b64encode(
            hashlib.sha1((key + GUID).encode("ascii")).digest()
        ).decode("ascii")

    @property
    def closed(self) -> bool:
        return self.close_code is not None

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> str | bytes:
        try:
            return await self.receive()
        except WebSocketClosed:
            raise StopAsyncIteration from None

    async def send(self, message: str | bytes) -> None:
        if isinstance(message, str):
            await self._write(Opcode.TEXT, message.encode())
        else:
            await self._write(Opcode.BINARY, message)

    async def ping(self, payload: bytes = b"") -> None:
        await self._write(Opcode.PING, payload)

    async def receive(self) -> str | bytes:
        while True:
            if self.close_code is not None:
                raise WebSocketClosed(self.close_code, self.close_reason)
            final, opcode, payload = await self._read_frame()
            match opcode:
                case Opcode.PING:
                    await self._write(Opcode.PONG, payload)
                case Opcode.PONG:
                    pass
                case Opcode.CLOSE:
                    code = (
                        struct.unpack("!H", payload[:2])[0]
                        if len(payload) >= 2
                        else 1005
                    )
                    await self._finish(code, payload[2:].decode("utf-8", "replace"))
                case Opcode.TEXT | Opcode.BINARY | Opcode.CONTINUATION:
                    if opcode is Opcode.CONTINUATION:
                        if not self._fragments:
                            raise ProtocolError("continuation frame without a message")
                    elif self._fragments:
                        raise ProtocolError("new message inside a fragmented message")
                    else:
                        self._opcode = opcode
                    self._fragments.append(payload)
                    if sum(len(fragment) for fragment in self._fragments) > self._limit:
                        await self.close(1009, "message too big")
                        raise ProtocolError(f"message exceeds {self._limit} bytes")
                    if final:
                        message = b"".join(self._fragments)
                        self._fragments.clear()
                        if self._opcode is Opcode.BINARY:
                            return message
                        try:
                            return message.decode()
                        except UnicodeDecodeError:
                            await self.close(1007, "invalid UTF-8")
                            raise ProtocolError(
                                "text message is not valid UTF-8"
                            ) from None

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if not self._close_sent:
            self._close_sent = True
            await self._write(Opcode.CLOSE, struct.pack("!H", code) + reason.encode())
        if self.close_code is None:
            try:
                while True:
                    _, opcode, payload = await self._read_frame()
                    if opcode is Opcode.CLOSE:
                        peer_code = (
                            struct.unpack("!H", payload[:2])[0]
                            if len(payload) >= 2
                            else 1005
                        )
                        await self._finish(
                            peer_code, payload[2:].decode("utf-8", "replace")
                        )
            except WebSocketClosed, ProtocolError, ConnectionError:
                pass
        await self._transport.close()

    async def _finish(self, code: int, reason: str) -> None:
        self.close_code, self.close_reason = code, reason
        if not self._close_sent:
            self._close_sent = True
            await self._write(Opcode.CLOSE, struct.pack("!H", code))
        await self._transport.close()
        raise WebSocketClosed(code, reason)

    async def _write(self, opcode: Opcode, payload: bytes) -> None:
        head = bytes((0x80 | opcode,))
        length = len(payload)
        if length < 126:
            head += bytes((0x80 | length,))
        elif length < 65536:
            head += b"\xfe" + struct.pack("!H", length)
        else:
            head += b"\xff" + struct.pack("!Q", length)
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        async with self._deadline.phase("write"):
            await self._transport.write(head + mask + masked)

    async def _read_frame(self) -> tuple[bool, Opcode, bytes]:
        first, second = await self._read_exactly(2)
        if second & 0x80:
            raise ProtocolError("the server sent a masked frame")
        if first & 0x70:
            raise ProtocolError("reserved bits set without a negotiated extension")
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", await self._read_exactly(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", await self._read_exactly(8))[0]
        try:
            opcode = Opcode(first & 0x0F)
        except ValueError:
            raise ProtocolError(f"unknown websocket opcode {first & 0x0F:#x}") from None
        if opcode >= Opcode.CLOSE and (length > 125 or not first & 0x80):
            raise ProtocolError("control frame too long or fragmented")
        if length > self._limit:
            raise ProtocolError(f"frame exceeds {self._limit} bytes")
        return bool(first & 0x80), opcode, await self._read_exactly(length)

    async def _read_exactly(self, length: int) -> bytes:
        while len(self._buffer) < length:
            async with self._deadline.phase("read"):
                piece = await self._transport.read(65536)
            if not piece:
                if self.close_code is None:
                    self.close_code, self.close_reason = (
                        1006,
                        "connection closed without a close frame",
                    )
                raise WebSocketClosed(self.close_code, self.close_reason)
            self._buffer += piece
        data = bytes(self._buffer[:length])
        del self._buffer[:length]
        return data
