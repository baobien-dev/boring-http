import zlib
from collections.abc import Callable, Sequence
from compression import zstd
from enum import IntEnum, StrEnum

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


class ContentDecoder:
    # undoes a Content-Encoding chain, last coding first, one chunk at a time
    def __init__(self, codings: Sequence[str], library: Library) -> None:
        self._codings = tuple(reversed(codings))
        self._decoders = [self._decoder(coding, library) for coding in self._codings]

    def decode(self, data: bytes) -> bytes:
        for coding, decoder in zip(self._codings, self._decoders, strict=True):
            try:
                data = decoder(data)
            except (zlib.error, ValueError, zstd.ZstdError) as error:
                raise ProtocolError(f"the {coding} body is corrupt: {error}") from error
        return data

    @staticmethod
    def _decoder(coding: str, library: Library) -> Callable[[bytes], bytes]:
        try:
            known = ContentCoding(coding)
        except ValueError:
            raise ProtocolError(f"unsupported content coding {coding!r}") from None
        match known:
            case ContentCoding.GZIP | ContentCoding.X_GZIP:
                return zlib.decompressobj(Window.GZIP_WRAPPER + Window.MAXIMUM).decompress
            case ContentCoding.DEFLATE:
                return zlib.decompressobj().decompress
            case ContentCoding.BROTLI:
                return BrotliDecoder(library).decode
            case ContentCoding.ZSTD:
                return zstd.ZstdDecompressor().decompress
            case ContentCoding.IDENTITY:
                return bytes
