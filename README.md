# boring-http

An asyncio HTTP client on BoringSSL, through `ssl2` and `boring-ssl2`. HTTP/1.1, HTTP/2 and HTTP/3 over QUIC v1 and v2, WebSocket on all three, HTTP and SOCKS proxies, 0-RTT, headers on the wire in the order you give them, cookies, redirects, timeouts per phase, gzip, deflate, brotli and zstd. Runs on asyncio and on uvloop. Python 3.14.

```text
uv add boring-http
```

## Requests

```python
import asyncio

from boring_http import Client, Http2Profile
from ssl2 import AkamaiFingerprint

http2 = Http2Profile(AkamaiFingerprint.parse("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"))


async def main() -> None:
    async with Client(http2=http2, headers=[("User-Agent", "boring-http/3"), ("Accept", "application/json")]) as client:
        response = await client.get("https://pingly.us.kg/api/all", params={"page": 2})
        print(response.status, response.version, response.content_type)  # 200 h2 application/json
        report = response.json()
        print(report["http_version"], report["user_agent"], report["method"])  # HTTP/2.0 boring-http/3 GET

        response = await client.post("https://httpbingo.org/post", json={"name": "boring"}, headers=[("X-Trace", "abc")])
        echoed = response.json()
        print(echoed["json"], echoed["headers"]["X-Trace"])  # {'name': 'boring'} ['abc']


asyncio.run(main())
```

`get`, `post`, `put`, `patch`, `delete`, `head`, `options` and `request` take `params`, `headers`, `json`, `data`, `content`, `files`, `auth`, `cookies`, `timeout`, `allow_redirects` and `proxy`. Headers go out in the order given, the client's first and then the request's own; `Host` leads an HTTP/1.1 request, HTTP/2 and HTTP/3 lowercase the names and leave out the connection-specific ones. Nothing else is added or moved.

Certificates are checked against the system trust store, or against `trust_store=TrustStore.from_file(...)` from `ssl2`; `verify=False` turns the check off for a test server. The certificate's CRL is fetched over HTTP, checked against the issuer in the chain and kept until its next update; a listed certificate is refused with `RevocationError`. The default `revocation=Revocation.SOFT` lets a connection through when no valid CRL can be had, as browsers do, `Revocation.STRICT` refuses it and `Revocation.NONE` skips the check. `certificate_chain=SigningChain(...)` presents a client certificate, over TCP and QUIC. `check_peer=` is awaited with the peer's chain in DER, leaf first, and its authority; raising from it refuses the connection, which is where a key pin goes. `key_log="keys.txt"` appends every TLS and QUIC secret in the NSS key log format, for Wireshark. `resolve={("example.com", 443): ("203.0.113.7", 443)}` sends a direct connection to that address while SNI and verification keep the name.

Connections are pooled per origin and proxy, under `max_connections` and `max_connections_per_host`. One idle for `max_idle_time` seconds, 90 by default, is closed instead of reused; `None` keeps it until the server closes it. A request that a reused connection or a refused stream fails before any response is sent once more.

## Responses

```python
import asyncio

from boring_http import Client, Http2Profile
from ssl2 import AkamaiFingerprint

http2 = Http2Profile(AkamaiFingerprint.parse("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"))


async def main() -> None:
    async with Client(http2=http2) as client:
        response = await client.get("https://httpbingo.org/redirect/2")
        print(response.status, response.url.path, [step.status for step in response.history])  # 200 /get [302, 302]

        response = await client.get("https://httpbingo.org/redirect/1", allow_redirects=False)
        print(response.status, response.is_redirect, response.location.path)  # 302 True /get

        response = await client.get("https://httpbingo.org/cookies/set?flavor=plain", allow_redirects=False)
        print([cookie.name for cookie in response.cookies], client.cookies.header("httpbingo.org", "/", secure=True))  # ['flavor'] flavor=plain

        info = response.connection
        print(info.tls_version, info.reused, sorted(dict(info)))  # TLSVersion.TLSv1_3 True ['cipher', 'connect_time', 'local_address', 'peer_chain', 'remote_address', 'reused', 'tls_version']


asyncio.run(main())
```

`response.cookies` holds what this response set; `client.cookies` is the jar that follows every request, and refuses a `Domain` that is a public suffix such as `co.uk`. `location`, `content_type`, `charset`, `content_length`, `content_encoding`, `retry_after`, `etag`, `last_modified` and `date` are parsed, `response.headers` keeps the raw fields in order, `raise_for_status()` raises `HTTPStatusError`. `response.connection` is a `ConnectionInfo`: the addresses, the TLS version, cipher and peer chain, whether the connection was reused and how long opening it took. `response.elapsed` is the seconds from sending the request to its last body byte. Every such object prints as `Name(field=...)` and `dict()` takes it apart.

## Streaming, timeouts and tracing

```python
import asyncio

from boring_http import Client, Http2Profile, RequestTimeoutError, Timeout
from ssl2 import AkamaiFingerprint

http2 = Http2Profile(AkamaiFingerprint.parse("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"))


async def main() -> None:
    async with Client(http2=http2, timeout=Timeout(connect=5, read=10, write=10, total=30), trace=True) as client:
        async with client.stream("GET", "https://httpbingo.org/stream-bytes/100000") as response:
            size = sum([len(chunk) async for chunk in response.aiter_bytes()])
        print(response.status, size)  # 200 100000
        print(response.trace)  # connect 29.7 ms, handshake 34.5 ms, pool 65.1 ms, send 0.0 ms, headers 39.0 ms, body 12.3 ms

        try:
            await client.get("https://httpbingo.org/delay/3", timeout=0.5)
        except RequestTimeoutError as error:
            print(error.phase, error)  # total total timed out after 0.5 seconds


asyncio.run(main())
```

One number limits every phase and the whole request. A `Timeout` keeps them apart: `connect` covers opening the connection with its proxy and handshake, `read` is the longest wait for the next bytes, `write` the longest wait for the connection to take the next chunk of a body, `total` caps the exchange with its redirects. The error names the phase that ran out.

With `trace=True` every response carries a `Trace` with the timed steps of its request: the connect, proxy and handshake spans from `ssl2`, then the wait for a pooled connection, the send, the response head and the body. The `boring_http` logger reports one line per connection and request at INFO, such as `response.headers status=200 version=h2 stream=1 seconds=0.039`; DEBUG adds the requests sent and the packets QUIC lost.

A body is held to what is read: over HTTP/2 and HTTP/3 the stream window opens again as chunks are taken, so a response nobody reads stops at one window while the connection window keeps the other streams going. An upload keeps at most 1 MiB unsent in a QUIC stream before the next chunk is taken from the body.

## HTTP/3

```python
import asyncio
from dataclasses import replace

from boring_http import Client, Http2Profile, Http3Profile, Http3Setting, Parameter, QuicVersion, TransportParameters
from ssl2 import AkamaiFingerprint, PseudoHeader

http2 = Http2Profile(AkamaiFingerprint.parse("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"))
http3 = Http3Profile(
    settings=((Http3Setting.QPACK_MAX_TABLE_CAPACITY, 65536), (Http3Setting.MAX_FIELD_SECTION_SIZE, 262144), (Http3Setting.QPACK_BLOCKED_STREAMS, 100)),
    pseudo_header_order=(PseudoHeader.METHOD, PseudoHeader.AUTHORITY, PseudoHeader.SCHEME, PseudoHeader.PATH),
    transport=TransportParameters(
        max_idle_timeout=30000,
        max_udp_payload_size=1472,
        initial_max_data=15728640,
        initial_max_stream_data_bidi_local=6291456,
        initial_max_stream_data_bidi_remote=6291456,
        initial_max_stream_data_uni=6291456,
        initial_max_streams_bidi=100,
        initial_max_streams_uni=100,
        order=(
            Parameter.MAX_IDLE_TIMEOUT,
            Parameter.MAX_UDP_PAYLOAD_SIZE,
            Parameter.INITIAL_MAX_DATA,
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            Parameter.INITIAL_MAX_STREAM_DATA_UNI,
            Parameter.INITIAL_MAX_STREAMS_BIDI,
            Parameter.INITIAL_MAX_STREAMS_UNI,
            Parameter.INITIAL_SOURCE_CONNECTION_ID,
            Parameter.VERSION_INFORMATION,
        ),
    ),
)


async def main() -> None:
    async with Client(versions=("h3", "h2", "h1"), http2=http2, http3=http3) as client:
        first = await client.get("https://pingly.us.kg/api/all")
        second = await client.get("https://pingly.us.kg/api/all")
        print(first.version, second.version)  # h2 h3, the Alt-Svc header said this origin speaks HTTP/3

    async with Client(versions=("h3",), http3=replace(http3, quic_version=QuicVersion.V2)) as client:
        response = await client.get("https://pingly.us.kg/api/all")
        print(response.version, response.json()["http_version"])  # h3 HTTP/3.0


asyncio.run(main())
```

The default is `versions=("h2", "h1")`. With `"h3"` in the list an origin moves to QUIC after an `Alt-Svc: h3` header and comes back to TCP when the QUIC route stops answering; `versions=("h3",)` goes straight to QUIC. The first packet is always v1; `quic_version=QuicVersion.V2` offers v2 in `version_information`, so a server that speaks it switches and every other one stays on v1. That needs `Parameter.VERSION_INFORMATION` in `order`.

`TransportParameters` sends the parameters in `order`, in that order, and refuses a value the peer would never see. `max_idle_timeout=0` sets no idle timeout, `grease=True` adds a GREASE parameter, `grease_version=True` a GREASE version, `shuffle=True` a fresh order on every connection, and `Parameter.INITIAL_ROUND_TRIP_TIME` sends `initial_round_trip_time` or, without one, the round trip measured on the last connection to that origin. The control stream carries the SETTINGS of the profile, a GREASE setting and a GREASE frame with `grease=True`, and a PRIORITY_UPDATE for a request with a `priority` header.

A second connection to an origin resumes the TLS session and sends GET, HEAD and OPTIONS requests before the handshake has finished, under the limits and SETTINGS the server gave last time. Other methods wait for the handshake, a 425 is sent again after it, and a server that declines the early data gets it again under the 1-RTT keys. Retry, version negotiation, loss recovery, pacing, flow control, the server's key updates and path MTU probing from 1200 to 1452 bytes are handled; connection migration is not. On Linux the socket moves many datagrams per call through UDP segmentation and receive offload.

## Proxies

```python
import asyncio

from boring_http import Client, Http2Profile, Http3Profile, Http3Setting, Parameter, TransportParameters
from ssl2 import AkamaiFingerprint, ProxyError, PseudoHeader

http2 = Http2Profile(AkamaiFingerprint.parse("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"))
http3 = Http3Profile(
    settings=((Http3Setting.QPACK_MAX_TABLE_CAPACITY, 65536), (Http3Setting.MAX_FIELD_SECTION_SIZE, 262144), (Http3Setting.QPACK_BLOCKED_STREAMS, 100)),
    pseudo_header_order=(PseudoHeader.METHOD, PseudoHeader.AUTHORITY, PseudoHeader.SCHEME, PseudoHeader.PATH),
    transport=TransportParameters(
        max_idle_timeout=30000,
        max_udp_payload_size=1472,
        initial_max_data=15728640,
        initial_max_stream_data_bidi_local=6291456,
        initial_max_stream_data_bidi_remote=6291456,
        initial_max_stream_data_uni=6291456,
        initial_max_streams_bidi=100,
        initial_max_streams_uni=100,
        order=(
            Parameter.MAX_IDLE_TIMEOUT,
            Parameter.MAX_UDP_PAYLOAD_SIZE,
            Parameter.INITIAL_MAX_DATA,
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            Parameter.INITIAL_MAX_STREAM_DATA_UNI,
            Parameter.INITIAL_MAX_STREAMS_BIDI,
            Parameter.INITIAL_MAX_STREAMS_UNI,
            Parameter.INITIAL_SOURCE_CONNECTION_ID,
            Parameter.VERSION_INFORMATION,
        ),
    ),
)


async def main() -> None:
    async with Client(http2=http2, proxy="socks5h://alice:secret@127.0.0.1:1080") as client:
        response = await client.get("https://pingly.us.kg/api/all")  # SOCKS5 CONNECT, HTTP/2 inside
        print(response.version, response.json()["http_version"])  # h2 HTTP/2.0
        response = await client.get("https://pingly.us.kg/api/all", proxy="http://alice:secret@127.0.0.1:3128")  # this request only
        print(response.version)  # h2

    async with Client(versions=("h3",), http3=http3, proxy="socks5h://alice:secret@127.0.0.1:1080") as client:
        response = await client.get("https://pingly.us.kg/api/all")  # SOCKS5 UDP ASSOCIATE, QUIC datagrams through the relay
        print(response.version, response.json()["http_version"])  # h3 HTTP/3.0

    try:
        async with Client(http2=http2, proxy="socks5h://alice:wrong@127.0.0.1:1080") as client:
            await client.get("https://pingly.us.kg/api/all")
    except ProxyError as refusal:
        print(refusal)  # the SOCKS5 proxy rejected the username and password


asyncio.run(main())
```

`http://`, `https://`, `socks4://`, `socks4a://`, `socks5://` and `socks5h://`, with credentials in the URL or as a `Proxy` from `ssl2`. HTTP and SOCKS proxies carry HTTP/1.1 and HTTP/2; SOCKS5 also carries HTTP/3. `proxy=None` on a request goes direct.

## Fingerprints

```python
import asyncio

from boring_http import Client, Http2Profile
from ssl2 import (
    JA4,
    AkamaiFingerprint,
    CertificateCompressionAlgorithm,
    CipherSuite,
    ClientHelloBuilder,
    ECPointFormat,
    ExtensionType,
    Http2Priority,
    NamedGroup,
    NextProtocol,
    ProtocolVersion,
    PskKeyExchangeMode,
    SignatureScheme,
)

hello = (
    ClientHelloBuilder()
    .supported_versions(ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2)
    .cipher_suites(
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    )
    .extensions(
        ExtensionType.server_name,
        ExtensionType.extended_main_secret,
        ExtensionType.renegotiation_info,
        ExtensionType.supported_groups,
        ExtensionType.ec_point_formats,
        ExtensionType.session_ticket,
        ExtensionType.application_layer_protocol_negotiation,
        ExtensionType.status_request,
        ExtensionType.signature_algorithms,
        ExtensionType.signed_certificate_timestamp,
        ExtensionType.key_share,
        ExtensionType.psk_key_exchange_modes,
        ExtensionType.supported_versions,
        ExtensionType.compress_certificate,
        ExtensionType.application_settings,
        ExtensionType.encrypted_client_hello,
    )
    .supported_groups(NamedGroup.X25519MLKEM768, NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1)
    .key_shares(NamedGroup.X25519MLKEM768, NamedGroup.x25519)
    .ec_point_formats(ECPointFormat.uncompressed)
    .signature_algorithms(
        SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.rsa_pss_rsae_sha256,
        SignatureScheme.rsa_pkcs1_sha256,
        SignatureScheme.ecdsa_secp384r1_sha384,
        SignatureScheme.rsa_pss_rsae_sha384,
        SignatureScheme.rsa_pkcs1_sha384,
        SignatureScheme.rsa_pss_rsae_sha512,
        SignatureScheme.rsa_pkcs1_sha512,
    )
    .application_protocols(NextProtocol.H2, NextProtocol.HTTP1)
    .application_settings(NextProtocol.H2)
    .certificate_compression(CertificateCompressionAlgorithm.brotli)
    .psk_key_exchange_modes(PskKeyExchangeMode.psk_dhe_ke)
    .build()
)
http2 = Http2Profile(
    AkamaiFingerprint.parse("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"),
    headers_priority=Http2Priority(stream_id=0, exclusive=True, dependency=0, weight=256),
)


async def main() -> None:
    async with Client(tls=hello, http2=http2) as client:
        report = (await client.get("https://pingly.us.kg/api/all")).json()
        print(report["tls"]["ja4"] == JA4.of(hello).text, report["tls"]["ja4"])  # True t13d1516h2_8daaf6152771_d8a2da3f94cd
        print(report["http2"]["akamai_fingerprint"] == http2.fingerprint.text, report["http2"]["akamai_fingerprint"])  # True 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p


asyncio.run(main())
```

`tls` is a `ClientHello` from `ssl2`; BoringSSL sends it as described or the client refuses it with the reason. `http2` holds the SETTINGS, WINDOW_UPDATE, priorities and pseudo-header order of the connection preface; `http3` the HTTP/3 SETTINGS, pseudo-header order, transport parameters and QUIC version. Neither has a default: `h2` in the offered ALPN, the ClientHello's when `tls` is given and that of `versions` otherwise, needs `http2`, and `h3` in `versions` needs `http3`. A connection that has to be HTTP/1.1, such as the hop to an `https` proxy, offers only `http/1.1` and leaves the ALPS extension out.

Over QUIC the same holds, here with the ClientHello Chrome 155 sends: TLS 1.3 only, the `trust_anchors` extension with the identifiers of Chrome's root store, and `pre_shared_key` once a session exists.

```python
import asyncio

from boring_http import Client, Http3Profile, Http3Setting, Parameter, TransportParameters
from ssl2 import (
    JA4,
    CertificateCompressionAlgorithm,
    CipherSuite,
    ClientHelloBuilder,
    ExtensionType,
    JA4Transport,
    NamedGroup,
    NextProtocol,
    ProtocolVersion,
    PseudoHeader,
    PskKeyExchangeMode,
    SignatureScheme,
)

quic_hello = (
    ClientHelloBuilder()
    .supported_versions(ProtocolVersion.TLS_1_3)
    .cipher_suites(CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_CHACHA20_POLY1305_SHA256)
    .extensions(
        ExtensionType.signature_algorithms,
        ExtensionType.application_settings,
        ExtensionType.application_layer_protocol_negotiation,
        ExtensionType.compress_certificate,
        ExtensionType.trust_anchors,
        ExtensionType.server_name,
        ExtensionType.psk_key_exchange_modes,
        ExtensionType.key_share,
        ExtensionType.quic_transport_parameters,
        ExtensionType.supported_versions,
        ExtensionType.supported_groups,
        ExtensionType.encrypted_client_hello,
        ExtensionType.pre_shared_key,
    )
    .supported_groups(NamedGroup.X25519MLKEM768, NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1)
    .key_shares(NamedGroup.X25519MLKEM768, NamedGroup.x25519)
    .signature_algorithms(
        SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.rsa_pss_rsae_sha256,
        SignatureScheme.rsa_pkcs1_sha256,
        SignatureScheme.ecdsa_secp384r1_sha384,
        SignatureScheme.rsa_pss_rsae_sha384,
        SignatureScheme.rsa_pkcs1_sha384,
        SignatureScheme.rsa_pss_rsae_sha512,
        SignatureScheme.rsa_pkcs1_sha512,
        SignatureScheme.rsa_pkcs1_sha1,
    )
    .application_protocols(NextProtocol.H3)
    .application_settings(NextProtocol.H3)
    .certificate_compression(CertificateCompressionAlgorithm.brotli)
    .psk_key_exchange_modes(PskKeyExchangeMode.psk_dhe_ke)
    .trust_anchor_ids(
        "44947.2.1", "44947.2.6", "44947.2.13", "44947.2.14", "44947.2.15", "44947.2.18", "44947.2.19", "44947.2.20",
        "52580.200109.1.7", "52580.200109.1.8", "52580.200109.1.9", "52580.200109.1.10", "52580.200109.1.11", "52580.200109.1.12", "52580.200109.1.13", "52580.200109.1.18", "52580.200109.1.19",
        "11129.9.1", "11129.9.4", "11129.9.5", "11129.9.6", "11129.9.7", "11129.9.8", "11129.9.10", "11129.9.11", "11129.9.12", "11129.9.13", "11129.9.15",
    )
    .grease()
    .permute_extensions()
    .build()
)
http3 = Http3Profile(
    settings=((Http3Setting.QPACK_MAX_TABLE_CAPACITY, 65536), (Http3Setting.MAX_FIELD_SECTION_SIZE, 262144), (Http3Setting.QPACK_BLOCKED_STREAMS, 100), (Http3Setting.H3_DATAGRAM, 1)),
    pseudo_header_order=(PseudoHeader.METHOD, PseudoHeader.AUTHORITY, PseudoHeader.SCHEME, PseudoHeader.PATH),
    transport=TransportParameters(
        max_idle_timeout=30000,
        max_udp_payload_size=1472,
        initial_max_data=15728640,
        initial_max_stream_data_bidi_local=6291456,
        initial_max_stream_data_bidi_remote=6291456,
        initial_max_stream_data_uni=6291456,
        initial_max_streams_bidi=100,
        initial_max_streams_uni=103,
        order=(
            Parameter.MAX_IDLE_TIMEOUT,
            Parameter.MAX_UDP_PAYLOAD_SIZE,
            Parameter.INITIAL_MAX_DATA,
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            Parameter.INITIAL_MAX_STREAM_DATA_UNI,
            Parameter.INITIAL_MAX_STREAMS_BIDI,
            Parameter.INITIAL_MAX_STREAMS_UNI,
            Parameter.INITIAL_SOURCE_CONNECTION_ID,
            Parameter.VERSION_INFORMATION,
            Parameter.MAX_DATAGRAM_FRAME_SIZE,
            Parameter.GOOGLE_CONNECTION_OPTIONS,
            Parameter.INITIAL_ROUND_TRIP_TIME,
        ),
        max_datagram_frame_size=65536,
        google_connection_options=(b"ORIG",),
        grease=True,
        grease_version=True,
        shuffle=True,
    ),
    tls=quic_hello,
    grease=True,
)


async def main() -> None:
    async with Client(versions=("h3",), http3=http3, headers=[("priority", "u=0, i")]) as client:
        _ = await client.get("https://pingly.us.kg/api/all")
        await client.close()  # the next request opens a new connection, which resumes the session
        report = (await client.get("https://pingly.us.kg/api/all")).json()
        print(report["tls"]["ja4"] == JA4.of(quic_hello, JA4Transport.QUIC).text, report["tls"]["ja4"])  # True q13d0313h3_55b375c5d22e_b0954bf1abdf
        print(report["http3"]["h3_text"])  # 1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p


asyncio.run(main())
```

## WebSocket

```python
import asyncio

from boring_http import Client, Http2Profile
from ssl2 import AkamaiFingerprint

http2 = Http2Profile(AkamaiFingerprint.parse("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"))


async def main() -> None:
    async with Client(http2=http2) as client:
        websocket = await client.websocket("wss://echo.websocket.org/")
        print((await websocket.receive())[:17])  # Request served by
        await websocket.send("hello")
        print(await websocket.receive())  # hello
        await websocket.send(b"\x00\x01")
        print(await websocket.receive())  # b'\x00\x01'
        await websocket.close()
        print(websocket.close_code)  # 1000


asyncio.run(main())
```

Over HTTP/1.1 this is the Upgrade handshake. Over HTTP/2 and HTTP/3 it is Extended CONNECT when the server announces `SETTINGS_ENABLE_CONNECT_PROTOCOL`, otherwise an HTTP/1.1 connection is opened for it. Each WebSocket has a connection of its own, which `close()` ends after the closing handshake. `subprotocols=[...]` offers subprotocols and `websocket.subprotocol` is the one chosen. The `total` of the timeout covers the handshake only; `read` and `write` still limit each wait afterwards, so `Timeout(read=None)` lets `receive()` wait through any silence. `async for message in websocket` reads until the close.

## Your own BoringSSL

```python
from boring_ssl2 import Library

from boring_http import Client

library = Library.default()  # the build that ships with boring-ssl2; Library("/opt/boringssl/libboring_ssl2.so") loads another
print(len(library.source_revision))  # 40
client = Client(versions=("h1",), library=library)
```

Every connection of the client uses that build: the TLS contexts, the QUIC packet protection, the certificate parsing and the brotli decoder. A build that predates a feature the client needs refuses with a `ConfigurationError` naming the missing function.

## uvloop

```python
import uvloop

from boring_http import Client, Http3Profile, Http3Setting, Parameter, TransportParameters
from ssl2 import PseudoHeader

http3 = Http3Profile(
    settings=((Http3Setting.QPACK_MAX_TABLE_CAPACITY, 65536), (Http3Setting.MAX_FIELD_SECTION_SIZE, 262144), (Http3Setting.QPACK_BLOCKED_STREAMS, 100)),
    pseudo_header_order=(PseudoHeader.METHOD, PseudoHeader.AUTHORITY, PseudoHeader.SCHEME, PseudoHeader.PATH),
    transport=TransportParameters(
        max_idle_timeout=30000,
        max_udp_payload_size=1472,
        initial_max_data=15728640,
        initial_max_stream_data_bidi_local=6291456,
        initial_max_stream_data_bidi_remote=6291456,
        initial_max_stream_data_uni=6291456,
        initial_max_streams_bidi=100,
        initial_max_streams_uni=100,
        order=(
            Parameter.MAX_IDLE_TIMEOUT,
            Parameter.MAX_UDP_PAYLOAD_SIZE,
            Parameter.INITIAL_MAX_DATA,
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            Parameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            Parameter.INITIAL_MAX_STREAM_DATA_UNI,
            Parameter.INITIAL_MAX_STREAMS_BIDI,
            Parameter.INITIAL_MAX_STREAMS_UNI,
            Parameter.INITIAL_SOURCE_CONNECTION_ID,
            Parameter.VERSION_INFORMATION,
        ),
    ),
)


async def main() -> None:
    async with Client(versions=("h3",), http3=http3) as client:
        print((await client.get("https://pingly.us.kg/api/all")).version)  # h3


uvloop.run(main())
```

Every path runs unchanged on uvloop, QUIC included. On Windows' default event loop, which signals no socket readiness, QUIC runs on a datagram endpoint instead of the raw socket.

## Load

Against a Go server on loopback, Python 3.14.8 on Linux, one client with 256 requests in flight and 64 connections to the host:

| version | 20000 small requests | 32 parallel 20 MB downloads | 16 parallel 10 MB uploads |
| --- | ---: | ---: | ---: |
| HTTP/1.1 | 8752 req/s | 982 MB/s | 2350 MB/s |
| HTTP/2 | 9553 req/s | 347 MB/s | 1183 MB/s |
| HTTP/3 | 4904 req/s | 174 MB/s | 95 MB/s |

HTTP/1.1 and HTTP/2 are Python framing over BoringSSL records. HTTP/3 is a QUIC stack in Python with BoringSSL doing the cryptography, which is where its gap comes from. The same code holds a thousand open clients per version and keeps going through 5% datagram loss on the QUIC path.
