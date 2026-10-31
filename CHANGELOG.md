# Changelog

All notable changes to boring-http. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.1.0] - 2026-10-31

### Added

- `resolver=` on `Client` chooses who turns a name into addresses. `DnsResolver(("1.1.1.1", "8.8.8.8"))` asks those servers over UDP, asks again over TCP when an answer came back truncated, asks A and AAAA at once and keeps the answers for their TTL; `timeout=` bounds each attempt and `attempts=` their number. `DohResolver("https://cloudflare-dns.com/dns-query", client=...)` asks over HTTPS with the `Client` given, so on HTTP/2 or HTTP/3. `SystemResolver()` asks the operating system and is the default. A `resolve=` pin wins over any resolver.
- A connection tries every address the name resolved to, IPv6 first, and moves to the next when one fails at the socket or in QUIC. `response.trace` starts with a `resolve` span and the logger reports a `resolved` line per connection.
- `ResolveError`, a `ConnectError`, names a name that did not resolve.
- `boring_http.dns` has the DNS message as typed values: `Message`, `Header`, `Question`, `Record`, `RecordType`, `ResponseCode` and `Flag`, read and written by structure with name compression followed on read.

## [3.0.2] - 2026-10-31

### Changed

- The HPACK and QPACK Huffman decoder walks the code tree four bits at a time from a table built once, instead of one bit at a time: a 91 byte string decodes in 9 µs, and sequential HTTP/3 requests on loopback go from 3933 to 4446 per second.

## [3.0.1] - 2026-10-31

### Fixed

- A response closed before its body was read left its HTTP/1.1 connection neither idle nor closed, so the pool never gave the slot back, and on HTTP/2 and HTTP/3 left the stream open. The body now runs to its first step before the response is handed out, so closing it reaches the cleanup.
- HTTP/2: a header block for a stream this side had already reset is still decoded, so the HPACK table stays in step with the server (RFC 9113 section 4.3); padding counts against flow control (section 6.9.1); a write waiting for window leaves no task behind when it is cancelled; a SETTINGS that takes a stream's window below zero no longer spins the event loop; END_STREAM on a HEADERS frame whose block continues in a CONTINUATION ends the stream.
- Content decoding: a gzip body of several members and a zstd body of several frames decode whole, a deflate body without the zlib wrapper decodes, and a compressed body cut short raises `ProtocolError` instead of passing as complete.

### Changed

- The pool takes an idle connection without its lock, and a connection reads its addresses and handshake once instead of on every request.

## [3.0.0] - 2026-10-31

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
