# Changelog

All notable changes to boring-http. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

The client was written again from the ground up. What a program sees:

### Changed

- `URL` is `Url`, `Headers` holds `Header`s, `Http2Settings` and `Http3Settings` are `Http2Profile` and `Http3Profile`, `Setting` is `Http3Setting`, and HTTP/1.1 gets an `Http1Profile` for the Host position and the read limits. Every one prints as `Name(field=...)` and `dict()` takes it apart.
- The errors end in Error: `RemoteDisconnectedError`, `StreamRefusedError`, `RequestTimeoutError` (still a `TimeoutError`), `TooManyRedirectsError`, `WebSocketClosedError`. A mistaken argument raises `ConfigurationError` from `ssl2`; a URL that does not parse raises `ParseError`, a `ValueError` too.
- `client.cookies.header(host, path, secure=...)` takes the flag as a keyword.
- A server's malformed header is a `ProtocolError` on every version.
- Only a peer's close is logged as a connection failure.

### Added

- `trace=True` on `Client`: every response carries a `Trace` with the connect, proxy, handshake, pool, send, headers and body spans, and `print(response.trace)` shows them.
- `library=` on `Client`: a BoringSSL build of your own, through `boring_ssl2.Library(path)`.
- The `boring_http` logger reports connections, requests, responses, redirects, retries, Alt-Svc, QUIC handshakes, losses and closes, and WebSockets.
- On Windows' default event loop, which signals no socket readiness, QUIC runs on an asyncio datagram endpoint.
- `Method`, `Scheme`, `Proxy`, `ProxyCredentials` and `ProxyScheme` are exported.

## [2.5.1] - 2026-10-27

- After a Retry, the rest of a multi-packet ClientHello waits for the server's connection id.

## [2.5.0] - 2026-10-27

- `write` limits each chunk of a body, `connect_time` on `response.connection`, Initial packet numbers go on after a Retry.

## [2.4.0] - 2026-10-27

- `response.connection` tells the addresses, TLS version, cipher, peer chain and reuse of the connection.

## [2.3.0] - 2026-10-27

- `key_log=` writes the TLS and QUIC secrets for Wireshark, `resolve=` pins a host to an address.

## [2.2.1] - 2026-10-27

- A WebSocket over HTTP/2 or HTTP/3 closes the connection it opened.

## [2.2.0] - 2026-10-27

- `certificate_chain=` and `check_peer=` on `Client`, idle pooled connections expire after `max_idle_time`.

## [2.1.0] - 2026-10-27

- HTTP/2 and HTTP/3 grant stream window as the body is read, HTTP/3 uploads wait for the stream to drain.

## [2.0.3] - 2026-10-27

- Cookies refuse a public suffix as Domain, from the bundled Public Suffix List.

## [2.0.2] - 2026-10-27

- The connect timeout covers the handshake, a WebSocket outlives the handshake's total.

## [2.0.1] - 2026-10-27

- Only http/1.1 to https proxies and on HTTP/1.1 fallbacks, `max_idle_timeout=0` means none, transport values the peer would not see are refused.

## [2.0.0] - 2026-10-27

- No Chrome presets; `Http2Settings`, `Http3Settings` and `TransportParameters` come from the caller.

## [1.2.0] - 2026-10-26

- Revocation checks, Chrome 155 trust anchors, path MTU probing, twice the HTTP/3 throughput.

## [1.1.0] - 2026-10-26

- The ClientHello and HTTP/3 Chrome 155 sends over QUIC.

## [1.0.1] - 2026-10-26

- Requires Python 3.14, not the 3.14.8 patch release.

## [1.0.0] - 2026-10-26

- Asyncio HTTP client on BoringSSL.
