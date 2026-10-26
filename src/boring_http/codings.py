import zlib
from collections.abc import Callable, Sequence
from compression import zstd

from boring_ssl2 import BrotliDecoder

from boring_http.errors import ProtocolError


class ContentDecoder:
    def __init__(self, codings: Sequence[str]) -> None:
        self._codings = tuple(reversed(codings))
        self._decoders = [self._decoder(coding) for coding in self._codings]

    def decode(self, data: bytes) -> bytes:
        for coding, decoder in zip(self._codings, self._decoders, strict=True):
            try:
                data = decoder(data)
            except (zlib.error, ValueError, zstd.ZstdError) as error:
                raise ProtocolError(f"the {coding} body is corrupt: {error}") from error
        return data

    @staticmethod
    def _decoder(coding: str) -> Callable[[bytes], bytes]:
        match coding:
            case "gzip" | "x-gzip":
                return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress
            case "deflate":
                return zlib.decompressobj().decompress
            case "br":
                return BrotliDecoder().decode
            case "zstd":
                return zstd.ZstdDecompressor().decompress
            case "identity":
                return bytes
            case _:
                raise ProtocolError(f"unsupported content coding {coding!r}")
