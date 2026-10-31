import zlib
from collections.abc import Sequence
from compression import zstd
from enum import IntEnum, StrEnum
from typing import Protocol

from boring_ssl2 import BrotliDecoder, Library

from boring_http.errors import ProtocolError


class ContentCoding(StrEnum):
    GZIP = "gzip"
    X_GZIP = "x-gzip"
    DEFLATE = "deflate"
    BROTLI = "br"
    ZSTD = "zstd"
    IDENTITY = "identity"

    @classmethod
    def accepted(cls) -> str:
        # what Accept-Encoding offers when the client decodes bodies
        return f"{cls.GZIP}, {cls.DEFLATE}, {cls.BROTLI}, {cls.ZSTD}"


class Window(IntEnum):
    # zlib's window bits, plus the flag that selects the gzip wrapper
    MAXIMUM = zlib.MAX_WBITS
    GZIP_WRAPPER = 16


class ZlibHeader(IntEnum):
    # RFC 1950 section 2.2: the first byte of a zlib stream names the method 8 and a window of at most 7
    METHOD_MASK = 0x0F
    DEFLATE_METHOD = 8
    INFO_SHIFT = 4
    INFO_MAXIMUM = 7


class Stream(Protocol):
    # one coding undone chunk by chunk; finish says whether the stream came to its end
    def decode(self, data: bytes) -> bytes: ...

    def finish(self) -> bytes: ...


class ZlibStream:
    # gzip or deflate; a gzip body may be several members in a row, and a deflate body may come without its wrapper
    def __init__(self, window: int) -> None:
        self._window = window
        self._decoder = zlib.decompressobj(window)
        self._started = False

    def decode(self, data: bytes) -> bytes:
        if not data:
            return b""
        if not self._started:
            self._started = True
            if self._window == Window.MAXIMUM and not self._zlib_wrapped(data[0]):
                self._decoder = zlib.decompressobj(-Window.MAXIMUM)
        pieces: list[bytes] = []
        while data:
            pieces.append(self._decoder.decompress(data))
            data = b""
            if self._decoder.eof and self._decoder.unused_data:
                # RFC 1952 section 2.2: the next member starts where this one ended
                data = self._decoder.unused_data
                self._decoder = zlib.decompressobj(self._window)
        return b"".join(pieces)

    def finish(self) -> bytes:
        if not self._started:
            return b""
        tail = self._decoder.flush()
        if not self._decoder.eof:
            raise ProtocolError("the compressed body ended before the end of its stream")
        return tail

    @staticmethod
    def _zlib_wrapped(first: int) -> bool:
        return (first & ZlibHeader.METHOD_MASK) == ZlibHeader.DEFLATE_METHOD and (
            first >> ZlibHeader.INFO_SHIFT
        ) <= ZlibHeader.INFO_MAXIMUM


class ZstdStream:
    # RFC 8878 section 3.1.1: a zstd body may be several frames in a row
    def __init__(self) -> None:
        self._decoder = zstd.ZstdDecompressor()
        self._started = False

    def decode(self, data: bytes) -> bytes:
        if not data:
            return b""
        self._started = True
        pieces: list[bytes] = []
        while data:
            pieces.append(self._decoder.decompress(data))
            data = self._decoder.unused_data if self._decoder.eof else b""
            if data:
                self._decoder = zstd.ZstdDecompressor()
        return b"".join(pieces)

    def finish(self) -> bytes:
        if self._started and not self._decoder.eof:
            raise ProtocolError("the compressed body ended before the end of its stream")
        return b""


class BrotliStream:
    def __init__(self, library: Library) -> None:
        self._decoder = BrotliDecoder(library)
        self._started = False

    def decode(self, data: bytes) -> bytes:
        if not data:
            return b""
        self._started = True
        return self._decoder.decode(data)

    def finish(self) -> bytes:
        if self._started and not self._decoder.finished:
            raise ProtocolError("the compressed body ended before the end of its stream")
        return b""


class IdentityStream:
    def decode(self, data: bytes) -> bytes:
        return data

    def finish(self) -> bytes:
        return b""


class ContentDecoder:
    # undoes a Content-Encoding chain, last coding first, one chunk at a time
    def __init__(self, codings: Sequence[str], library: Library) -> None:
        self._codings = tuple(reversed(codings))
        self._streams = [self._stream(coding, library) for coding in self._codings]

    def decode(self, data: bytes) -> bytes:
        for coding, stream in zip(self._codings, self._streams, strict=True):
            try:
                data = stream.decode(data)
            except (zlib.error, ValueError, zstd.ZstdError) as error:
                raise ProtocolError(f"the {coding} body is corrupt: {error}") from error
        return data

    def finish(self) -> bytes:
        # the end of the body: what the streams still hold, and the check that each came to its end
        data = b""
        for coding, stream in zip(self._codings, self._streams, strict=True):
            try:
                data = (stream.decode(data) if data else b"") + stream.finish()
            except (zlib.error, ValueError, zstd.ZstdError) as error:
                raise ProtocolError(f"the {coding} body is corrupt: {error}") from error
        return data

    @staticmethod
    def _stream(coding: str, library: Library) -> Stream:
        try:
            known = ContentCoding(coding)
        except ValueError:
            raise ProtocolError(f"unsupported content coding {coding!r}") from None
        match known:
            case ContentCoding.GZIP | ContentCoding.X_GZIP:
                return ZlibStream(Window.GZIP_WRAPPER + Window.MAXIMUM)
            case ContentCoding.DEFLATE:
                return ZlibStream(Window.MAXIMUM)
            case ContentCoding.BROTLI:
                return BrotliStream(library)
            case ContentCoding.ZSTD:
                return ZstdStream()
            case ContentCoding.IDENTITY:
                return IdentityStream()
