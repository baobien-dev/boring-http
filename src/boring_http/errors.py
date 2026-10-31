import builtins
from enum import IntEnum, StrEnum


class HTTPError(Exception):
    pass


class ConnectError(HTTPError):
    pass


class RevocationError(ConnectError):
    pass


class RemoteDisconnectedError(ConnectError):
    pass


class StreamRefusedError(RemoteDisconnectedError):
    # the server never processed the request, so sending it again is safe
    pass


class StreamResetError(RemoteDisconnectedError):
    def __init__(self, stream_id: int, code: IntEnum | int) -> None:
        name = code.name if isinstance(code, IntEnum) else f"{code:#x}"
        super().__init__(f"stream {stream_id} reset by the server with {name}")
        self.stream_id = stream_id
        self.code = int(code)


class RequestTimeoutError(HTTPError, builtins.TimeoutError):
    def __init__(self, phase: StrEnum, seconds: float) -> None:
        super().__init__(f"{phase} timed out after {seconds:g} seconds")
        self.phase = phase
        self.seconds = seconds


class ProtocolError(HTTPError):
    pass


class TooManyRedirectsError(HTTPError):
    pass


class WebSocketClosedError(HTTPError):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(f"websocket closed with code {code}{': ' + reason if reason else ''}")
        self.code = code
        self.reason = reason
