from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import override

from boring_ssl2 import QuicVersion
from ssl2.client_hello import ClientHello
from ssl2.errors import ConfigurationError
from ssl2.fingerprint import AkamaiFingerprint, Http2Priority, PseudoHeader
from ssl2.registry import Http2SettingIdentifier, NextProtocol
from ssl2.value import Value

from boring_http.quic.parameters import Parameter, TransportParameters


class HTTPVersion(StrEnum):
    HTTP_1 = "http/1.1"
    HTTP_2 = "h2"
    HTTP_3 = "h3"

    @classmethod
    @override
    def _missing_(cls, value: object) -> HTTPVersion | None:
        # the short spellings people type: h1, 1.1, 1, 2, 3, HTTP/2
        spelled = str(value).lower().removeprefix("http/")
        match spelled:
            case "h1" | "1.1" | "1":
                return cls.HTTP_1
            case "2":
                return cls.HTTP_2
            case "3":
                return cls.HTTP_3
            case _:
                return None

    @property
    def alpn(self) -> NextProtocol:
        # the protocol name offered in the TLS handshake for this version
        match self:
            case HTTPVersion.HTTP_1:
                return NextProtocol.HTTP1
            case HTTPVersion.HTTP_2:
                return NextProtocol.H2
            case HTTPVersion.HTTP_3:
                return NextProtocol.H3


class Size(IntEnum):
    READ = 65536
    HEAD = 65536
    LINE = 8192


@dataclass(frozen=True, slots=True)
class Http1Profile(Value):
    # Host leads the request when host_first, otherwise it stands where the caller's headers put it
    host_first: bool = True
    read_size: int = int(Size.READ)
    head_limit: int = int(Size.HEAD)
    line_limit: int = int(Size.LINE)


@dataclass(frozen=True, slots=True)
class Http2Profile(Value):
    # the SETTINGS, WINDOW_UPDATE, priorities and pseudo-header order of the connection preface, as an Akamai fingerprint
    fingerprint: AkamaiFingerprint
    headers_priority: Http2Priority | None = None

    def setting(self, identifier: Http2SettingIdentifier, default: int) -> int:
        return next(
            (setting.value for setting in self.fingerprint.settings if setting.identifier is identifier), default
        )


class Http3Setting(IntEnum):
    # RFC 9114 section 7.2.4.1, RFC 9204 section 5, RFC 9220 and RFC 9297
    QPACK_MAX_TABLE_CAPACITY = 0x01
    MAX_FIELD_SECTION_SIZE = 0x06
    QPACK_BLOCKED_STREAMS = 0x07
    ENABLE_CONNECT_PROTOCOL = 0x08
    H3_DATAGRAM = 0x33


@dataclass(frozen=True, slots=True)
class Http3Profile(Value):
    settings: tuple[tuple[Http3Setting | int, int], ...]
    pseudo_header_order: tuple[PseudoHeader, ...]
    transport: TransportParameters
    quic_version: QuicVersion = QuicVersion.V1
    # the ClientHello sent over QUIC; None takes the client's TLS settings with h3 as the protocol
    tls: ClientHello | None = None
    # a GREASE setting and a GREASE frame on the control stream, RFC 9114 sections 7.2.4.1 and 7.2.8
    grease: bool = False

    def __post_init__(self) -> None:
        # RFC 9368 section 2.1: the first packet is v1 and another version is offered only in version_information
        if self.quic_version is not QuicVersion.V1 and Parameter.VERSION_INFORMATION not in self.transport.order:
            raise ConfigurationError(
                f"quic_version {self.quic_version.name} needs VERSION_INFORMATION in transport.order"
            )

    def setting(self, identifier: Http3Setting, default: int) -> int:
        return next((value for key, value in self.settings if key == identifier), default)
