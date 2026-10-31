from enum import StrEnum


class Event(StrEnum):
    # what the boring_http logger reports; a filter matches on these names
    CONNECTION_OPENED = "connection.opened"
    CONNECTION_REUSED = "connection.reused"
    CONNECTION_CLOSED = "connection.closed"
    CONNECTION_FAILED = "connection.failed"
    REQUEST_SENT = "request.sent"
    RESPONSE_HEADERS = "response.headers"
    RESPONSE_DONE = "response.done"
    REDIRECT = "redirect"
    RETRY = "retry"
    ALT_SVC_LEARNED = "alt_svc.learned"
    ALT_SVC_DROPPED = "alt_svc.dropped"
    QUIC_HANDSHAKE_DONE = "quic.handshake.done"
    QUIC_EARLY_DATA = "quic.early_data"
    QUIC_VERSION_CHANGED = "quic.version.changed"
    QUIC_RETRY = "quic.retry"
    QUIC_LOST = "quic.lost"
    QUIC_TERMINATED = "quic.terminated"
    WEBSOCKET_OPENED = "websocket.opened"
    WEBSOCKET_CLOSED = "websocket.closed"


class Step(StrEnum):
    # the timed spans of one request, after the connect, proxy and handshake spans ssl2 records
    POOL = "pool"
    SEND = "send"
    HEADERS = "headers"
    BODY = "body"
