# boring-http

An asyncio HTTP client on BoringSSL through `ssl2` and `boring-ssl2`. HTTP/1.1, HTTP/2 and HTTP/3 over QUIC v1 and v2, WebSocket on all three, HTTP and SOCKS proxies, headers sent in the order you give them, cookies, redirects, phased timeouts, gzip, deflate, brotli and zstd decoding. Runs on asyncio and on uvloop. Requires Python 3.14.

```text
uv add boring-http
```

## Requests

```python
import asyncio

from boring_http import Client


async def main() -> None:
    async with Client(headers=[("User-Agent", "boring-http/0.1"), ("Accept", "application/json")]) as client:
        response = await client.get("https://pingly.us.kg/api/all", params={"page": 2})
        print(response.status, response.version, response.content_type)  # 200 h2 application/json
        report = response.json()
        print(report["http_version"], report["user_agent"], report["method"])  # HTTP/2.0 boring-http/0.1 GET

        response = await client.post("https://httpbingo.org/post", json={"name": "boring"}, headers=[("X-Trace", "abc")])
        echoed = response.json()
        print(echoed["json"], echoed["headers"]["X-Trace"])  # {'name': 'boring'} ['abc']


asyncio.run(main())
```

Certificates are checked against the system trust store, or against `trust_store=TrustStore.from_file(...)` from `ssl2`; `verify=False` turns the check off for a test server. Headers go on the wire in the order given, client headers first and then the request's own. `Host` leads an HTTP/1.1 request; HTTP/2 and HTTP/3 lowercase the names and drop the connection-specific ones, nothing else changes. `params`, `json`, `data`, `content`, `files`, `auth` and `cookies` are accepted by `get`, `post`, `put`, `patch`, `delete`, `head`, `options` and `request`.

## Responses

```python
import asyncio

from boring_http import Client


async def main() -> None:
    async with Client() as client:
        response = await client.get("https://httpbingo.org/redirect/2")
        print(response.status, response.url.path, [step.status for step in response.history])  # 200 /get [302, 302]

        response = await client.get("https://httpbingo.org/redirect/1", allow_redirects=False)
        print(response.status, response.is_redirect, response.location.path)  # 302 True /get

        response = await client.get("https://httpbingo.org/cookies/set?flavor=plain", allow_redirects=False)
        print([cookie.name for cookie in response.cookies], client.cookies.header("httpbingo.org", "/", True))  # ['flavor'] flavor=plain


asyncio.run(main())
```

`response.cookies` holds only the cookies this response set; `client.cookies` is the jar that follows every request. `location`, `content_type`, `charset`, `content_length`, `content_encoding`, `retry_after`, `etag`, `last_modified` and `date` are parsed, `response.headers` keeps the raw fields in order, `raise_for_status()` raises `HTTPStatusError`.

## Streaming and timeouts

```python
import asyncio

from boring_http import Client, Timeout, TimeoutError


async def main() -> None:
    async with Client(timeout=Timeout(connect=5, read=10, write=10, total=30)) as client:
        async with client.stream("GET", "https://httpbingo.org/stream-bytes/100000") as response:
            size = sum([len(chunk) async for chunk in response.aiter_bytes()])
        print(response.status, size)  # 200 100000

        try:
            await client.get("https://httpbingo.org/delay/3", timeout=0.5)
        except TimeoutError as error:
            print(error.phase, error)  # total total timed out after 0.5 seconds


asyncio.run(main())
```

A single number sets every phase and the total, so the request gives up after that many seconds whatever it was doing. With a `Timeout` the phases are separate: `read` is the longest wait for the next bytes, `total` caps the whole exchange including redirects, and the error names whichever ran out.

## HTTP/3

```python
import asyncio

from boring_http import QUIC_V2, Client, Http3Profile


async def main() -> None:
    async with Client(versions=("h3", "h2", "h1")) as client:
        first = await client.get("https://pingly.us.kg/api/all")
        second = await client.get("https://pingly.us.kg/api/all")
        print(first.version, second.version)  # h2 h3, the Alt-Svc header taught the client that this origin speaks HTTP/3

    async with Client(versions=("h3",), http3=Http3Profile(quic_version=QUIC_V2)) as client:
        response = await client.get("https://pingly.us.kg/api/all")
        print(response.version, response.json()["http_version"])  # h3 HTTP/3.0


asyncio.run(main())
```

The default is `versions=("h2", "h1")`. With `"h3"` in the list the client switches an origin to QUIC after an `Alt-Svc: h3` header and falls back to TCP when the QUIC route stops answering; `versions=("h3",)` goes straight to QUIC. Retry packets, version negotiation, loss recovery, pacing, flow control, key updates, QPACK with a 64 KiB dynamic table on the decoding side and 0-RTT are handled; connection migration is not. A second connection to an origin resumes the TLS session and sends GET, HEAD and OPTIONS requests before the handshake has finished, under the limits and SETTINGS the server gave last time; other methods wait for the handshake, a 425 answer is retried after it, and a server that declines the early data gets it again under the 1-RTT keys. The transport parameters are Chrome 155's set, in a fresh random order with a GREASE entry, a GREASE version, Chrome's connection options and, on a resumed connection, the round trip time measured last time; `TransportParameters` on the `Http3Profile` changes any of it. The control stream carries SETTINGS with a GREASE entry, a GREASE frame, and a PRIORITY_UPDATE for every request that has a `priority` header, as Chrome sends them.

## Proxies

```python
import asyncio

from boring_http import Client
from ssl2 import ProxyError


async def main() -> None:
    async with Client(proxy="socks5h://alice:secret@127.0.0.1:1080") as client:
        response = await client.get("https://pingly.us.kg/api/all")  # SOCKS5 CONNECT, HTTP/2 inside
        print(response.version, response.json()["http_version"])  # h2 HTTP/2.0
        response = await client.get("https://pingly.us.kg/api/all", proxy="http://alice:secret@127.0.0.1:3128")  # per request
        print(response.version)  # h2

    async with Client(versions=("h3",), proxy="socks5h://alice:secret@127.0.0.1:1080") as client:
        response = await client.get("https://pingly.us.kg/api/all")  # SOCKS5 UDP ASSOCIATE, QUIC datagrams through the relay
        print(response.version, response.json()["http_version"])  # h3 HTTP/3.0

    try:
        async with Client(proxy="socks5h://alice:wrong@127.0.0.1:1080") as client:
            await client.get("https://pingly.us.kg/api/all")
    except ProxyError as refusal:
        print(refusal)  # the SOCKS5 proxy rejected the username and password


asyncio.run(main())
```

`http://`, `https://`, `socks4://`, `socks4a://`, `socks5://` and `socks5h://` proxies, with credentials in the URL. HTTP and SOCKS proxies carry HTTP/1.1 and HTTP/2; SOCKS5 also carries HTTP/3. `proxy=None` on a request bypasses the client's proxy.

## Fingerprints

```python
import asyncio

from boring_http import CHROME, Client
from ssl2 import (
    JA4,
    CertificateCompressionAlgorithm,
    CipherSuite,
    ClientHelloBuilder,
    ECPointFormat,
    ExtensionType,
    NamedGroup,
    NextProtocol,
    ProtocolVersion,
    PskKeyExchangeMode,
    SignatureScheme,
)

profile = (
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


async def main() -> None:
    async with Client(tls=profile, http2=CHROME) as client:
        report = (await client.get("https://pingly.us.kg/api/all")).json()
        print(report["tls"]["ja4"] == JA4.of(profile).text, report["tls"]["ja4"])  # True t13d1516h2_8daaf6152771_d8a2da3f94cd
        print(report["http2"]["akamai_fingerprint"] == CHROME.fingerprint.text, report["http2"]["akamai_fingerprint"])  # True 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p


asyncio.run(main())
```

Over HTTP/3 the same holds, with the ClientHello Chrome 155 sends on QUIC: TLS 1.3 only, the `trust_anchors` extension with the 28 identifiers of Chrome's root store, and `pre_shared_key` once a session exists.

```python
import asyncio

from boring_http import Client, Http3Profile
from ssl2 import (
    CHROME_TRUST_ANCHOR_IDS,
    JA4,
    CertificateCompressionAlgorithm,
    CipherSuite,
    ClientHelloBuilder,
    ExtensionType,
    JA4Transport,
    NamedGroup,
    NextProtocol,
    ProtocolVersion,
    PskKeyExchangeMode,
    SignatureScheme,
)

quic_profile = (
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
    .trust_anchor_ids(*CHROME_TRUST_ANCHOR_IDS)
    .grease()
    .permute_extensions()
    .build()
)


async def main() -> None:
    async with Client(versions=("h3",), http3=Http3Profile(tls=quic_profile), headers=[("priority", "u=0, i")]) as client:
        _ = await client.get("https://pingly.us.kg/api/all")
        await client.close()  # the next request opens a new connection, which resumes the session
        report = (await client.get("https://pingly.us.kg/api/all")).json()
        print(report["tls"]["ja4"] == JA4.of(quic_profile, JA4Transport.QUIC).text, report["tls"]["ja4"])  # True q13d0313h3_55b375c5d22e_b0954bf1abdf
        print(report["http3"]["h3_text"])  # 1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p


asyncio.run(main())
```

`tls` is a `ssl2.ClientHello`; BoringSSL sends it byte for byte or the client refuses it with the reason. `http2` is an `Http2Profile` with the SETTINGS, WINDOW_UPDATE, priorities and pseudo-header order; `CHROME` is the default. `http3` is an `Http3Profile` with the HTTP/3 SETTINGS, QUIC transport parameters and QUIC version.

## WebSocket

```python
import asyncio

from boring_http import Client


async def main() -> None:
    async with Client() as client:
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

Over HTTP/1.1 this is the Upgrade handshake. Over HTTP/2 and HTTP/3 it is Extended CONNECT when the server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`, otherwise the client opens an HTTP/1.1 connection for it. `subprotocols=[...]` offers subprotocols; `websocket.subprotocol` is the one chosen.

## uvloop

```python
import uvloop

from boring_http import Client


async def main() -> None:
    async with Client(versions=("h3",)) as client:
        print((await client.get("https://pingly.us.kg/api/all")).version)  # h3


uvloop.run(main())
```

Every path, QUIC included, runs unchanged on uvloop.

## Performance

Against a Go server (net/http and quic-go) on loopback, so the server is never the limit: 1000 requests for an 86-byte JSON body, sequentially on one connection and with 32 in flight, then one 50 MB download and one 20 MB upload per protocol. The first six rows are requests per second, the rest MB/s, `-` means the client does not speak that protocol. Python 3.14.8 on Linux, one process per measurement.

| scenario    | boring-http | boring-http+uvloop |  wreq | curl_cffi | pycurl | httpx | aiohttp | requests |
| ----------- | ----------: | -----------------: | ----: | --------: | -----: | ----: | ------: | -------: |
| h1-seq      |        9079 |              13405 | 17190 |      6116 |  28775 |  2171 |   11796 |     3287 |
| h2-seq      |        5744 |               5931 | 12384 |      4767 |  15384 |  1808 |       - |        - |
| h3-seq      |        4021 |               4537 |     - |      4595 |  12410 |     - |       - |        - |
| h1-conc     |        8956 |              12148 | 53500 |      7324 |  31170 |   934 |   23259 |     2361 |
| h2-conc     |       14846 |              15584 | 48788 |     10683 |  28764 |  2066 |       - |        - |
| h3-conc     |        6855 |               6901 |     - |     11079 |  29305 |     - |       - |        - |
| h1-download |         658 |                645 |   689 |       793 |   1019 |   264 |    1117 |      658 |
| h2-download |         472 |                497 |   426 |       468 |    479 |   123 |       - |        - |
| h3-download |         105 |                107 |     - |       517 |    492 |     - |       - |        - |
| h1-upload   |         633 |                687 |  3687 |      2002 |   2124 |   675 |     749 |     2296 |
| h2-upload   |         447 |                480 |  2309 |      1375 |   1440 |   197 |       - |        - |
| h3-upload   |          63 |                 67 |     - |       906 |    411 |     - |       - |        - |

HTTP/1.1 and HTTP/2 are Python framing over BoringSSL records; HTTP/3 is a QUIC stack written in Python with BoringSSL doing the cryptography, which is where the gap to libcurl's HTTP/3 comes from. The same code holds 1000 open clients per protocol, 20000 requests with 256 in flight, parallel multi-megabyte transfers and 5% datagram loss on the QUIC path.
