import builtins


class HTTPError(Exception):
    pass


class ConnectError(HTTPError):
    pass


class RevocationError(ConnectError):
    pass


class RemoteDisconnected(ConnectError):
    pass


class StreamRefused(RemoteDisconnected):
    # the server never processed the request, so sending it again is safe
    pass


class StreamResetError(RemoteDisconnected):
    def __init__(self, stream_id: int, code: int) -> None:
        super().__init__(f"stream {stream_id} reset by the server with error {code:#x}")
        self.stream_id: int = stream_id
        self.code: int = code


class TimeoutError(HTTPError, builtins.TimeoutError):
    def __init__(self, phase: str, seconds: float) -> None:
        super().__init__(f"{phase} timed out after {seconds:g} seconds")
        self.phase: str = phase
        self.seconds: float = seconds


class ProtocolError(HTTPError):
    pass


class TooManyRedirects(HTTPError):
    pass


class WebSocketClosed(HTTPError):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(
            f"websocket closed with code {code}{': ' + reason if reason else ''}"
        )
        self.code: int = code
        self.reason: str = reason
