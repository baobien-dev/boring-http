import base64
import os
from collections.abc import (
    AsyncGenerator,
    AsyncIterable,
    Awaitable,
    Callable,
    Mapping,
    Sequence,
)
from contextlib import asynccontextmanager
from dataclasses import replace
from time import monotonic
from typing import Self, TypedDict, Unpack

from boring_ssl2 import ClientContext
from ssl2 import (
    AsyncTransport,
    ClientHello,
    ConfigurationError,
    ExtensionType,
    NextProtocol,
    Proxy,
    ProxyError,
    ProxyScheme,
    SessionCache,
    SigningChain,
    SocketTransport,
    TLSClientConfiguration,
    TLSError,
    TLSStream,
    TrustStore,
)

from boring_http.cookies import CookieJar
from boring_http.errors import (
    ConnectError,
    HTTPError,
    ProtocolError,
    RemoteDisconnected,
    RevocationError,
    StreamRefused,
    TimeoutError,
    TooManyRedirects,
)
from boring_http.http1 import Http1Connection
from boring_http.http2 import Http2Connection, Http2Settings
from boring_http.http3 import Http3Connection, Http3Settings
from boring_http.message import (
    URL,
    Body,
    FileField,
    FormFields,
    HeaderItems,
    Headers,
    HTTPVersion,
    Params,
    Request,
    Response,
)
from boring_http.pool import Connection, Pool
from boring_http.quic.protocol import OriginMemory, QuicClient
from boring_http.revocation import Revocation, Revocations
from boring_http.timing import Deadline, Timeout
from boring_http.websocket import WebSocket

IMPLEMENTED = (HTTPVersion.HTTP_3, HTTPVersion.HTTP_2, HTTPVersion.HTTP_1)
ALPN = {
    HTTPVersion.HTTP_2: NextProtocol.H2,
    HTTPVersion.HTTP_1: NextProtocol.HTTP1,
}
ACCEPTED_ENCODINGS = "gzip, deflate, br, zstd"
USER_AGENT = "boring-http"
DEFAULT_TIMEOUT = Timeout()


class Unset:
    pass


UNSET = Unset()


class RequestOptions(TypedDict, total=False):
    params: Params | None
    headers: HeaderItems | None
    json: object
    data: FormFields | bytes | AsyncIterable[bytes] | None
    content: bytes | str | AsyncIterable[bytes] | None
    files: Mapping[str, FileField] | None
    auth: tuple[str, str] | None
    cookies: Mapping[str, str] | None
    timeout: float | Timeout | None | Unset
    allow_redirects: bool
    proxy: Proxy | str | None | Unset


class Client:
    def __init__(
        self,
        *,
        headers: HeaderItems | None = None,
        timeout: float | Timeout | None = DEFAULT_TIMEOUT,
        proxy: Proxy | str | None = None,
        tls: ClientHello | None = None,
        http2: Http2Settings | None = None,
        http3: Http3Settings | None = None,
        versions: Sequence[HTTPVersion | str] = (
            HTTPVersion.HTTP_2,
            HTTPVersion.HTTP_1,
        ),
        trust_store: TrustStore | None = None,
        verify: bool = True,
        revocation: Revocation = Revocation.SOFT,
        certificate_chain: SigningChain | None = None,
        check_peer: Callable[[tuple[bytes, ...], str], Awaitable[None]] | None = None,
        key_log: str | os.PathLike[str] | None = None,
        resolve: Mapping[tuple[str, int], tuple[str, int]] | None = None,
        cookies: CookieJar | None = None,
        base_url: str | None = None,
        max_connections: int = 100,
        max_connections_per_host: int = 10,
        max_idle_time: float | None = 90.0,
        max_redirects: int = 20,
        max_message_size: int = 16 * 1024 * 1024,
        decode: bool = True,
    ) -> None:
        self._headers = Headers(headers)
        self._timeout = Timeout.of(timeout)
        self._proxy = Proxy.parse(proxy) if isinstance(proxy, str) else proxy
        self._tls = tls
        self._http2 = http2
        self._http3 = http3
        self._alt_svc: dict[tuple[str, int], float] = {}
        self._versions = tuple(HTTPVersion(version) for version in versions)
        # over TCP the ClientHello's own ALPN goes out when one is given, else the ALPN of versions
        offered = (
            tls.application_protocols
            if tls is not None
            else tuple(
                ALPN[version].value for version in self._versions if version in ALPN
            )
        )
        if http2 is None and NextProtocol.H2.value in offered:
            raise ValueError("h2 is offered, so http2= needs an Http2Settings")
        if http3 is None and HTTPVersion.HTTP_3 in self._versions:
            raise ValueError("h3 is in versions, so http3= needs an Http3Settings")
        self._trust_store = trust_store
        self._verify = verify
        self._revocations = Revocations(revocation, self._fetch_crl)
        self._certificate_chain = certificate_chain
        self._check_peer = check_peer
        self._key_log = key_log
        self._resolve = {} if resolve is None else dict(resolve)
        self._base_url = base_url
        self._max_redirects = max_redirects
        self._max_message_size = max_message_size
        self._decode = decode
        self._contexts: dict[tuple[NextProtocol, ...] | None, ClientContext] = {}
        self._memory: dict[tuple[str, int], OriginMemory] = {}
        self._pool = Pool(
            self._connect, max_connections, max_connections_per_host, max_idle_time
        )
        self.cookies = CookieJar() if cookies is None else cookies

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._pool.close()

    async def request(
        self, method: str, url: str, **options: Unpack[RequestOptions]
    ) -> Response:
        request = self.build(
            method,
            url,
            params=options.get("params"),
            headers=options.get("headers"),
            json=options.get("json"),
            data=options.get("data"),
            content=options.get("content"),
            files=options.get("files"),
            auth=options.get("auth"),
        )
        return await self.send(
            request,
            cookies=options.get("cookies"),
            timeout=options.get("timeout", UNSET),
            allow_redirects=options.get("allow_redirects", True),
            proxy=options.get("proxy", UNSET),
        )

    async def get(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request("GET", url, **options)

    async def post(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request("POST", url, **options)

    async def put(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request("PUT", url, **options)

    async def patch(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request("PATCH", url, **options)

    async def delete(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request("DELETE", url, **options)

    async def head(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request("HEAD", url, **options)

    async def options(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request("OPTIONS", url, **options)

    @asynccontextmanager
    async def stream(
        self, method: str, url: str, **options: Unpack[RequestOptions]
    ) -> AsyncGenerator[Response]:
        request = self.build(
            method,
            url,
            params=options.get("params"),
            headers=options.get("headers"),
            json=options.get("json"),
            data=options.get("data"),
            content=options.get("content"),
            files=options.get("files"),
            auth=options.get("auth"),
        )
        response = await self.send(
            request,
            cookies=options.get("cookies"),
            timeout=options.get("timeout", UNSET),
            allow_redirects=options.get("allow_redirects", True),
            proxy=options.get("proxy", UNSET),
            stream=True,
        )
        try:
            yield response
        finally:
            await response.close()

    def build(
        self,
        method: str,
        url: str,
        *,
        params: Params | None = None,
        headers: HeaderItems | None = None,
        json: object = None,
        data: FormFields | bytes | AsyncIterable[bytes] | None = None,
        content: bytes | str | AsyncIterable[bytes] | None = None,
        files: Mapping[str, FileField] | None = None,
        auth: tuple[str, str] | None = None,
    ) -> Request:
        target = URL.parse(
            url if self._base_url is None else URL.parse(self._base_url).join(url).text
        )
        if params is not None:
            target = target.with_params(params)
        body = self._body(json, data, content, files)
        merged = (
            self._headers.copy()
            if headers is None
            else self._headers.merged(Headers(headers))
        )
        if (
            body is not None
            and body.content_type is not None
            and "content-type" not in merged
        ):
            merged.add("Content-Type", body.content_type)
        if auth is not None:
            merged.set(
                "Authorization",
                "Basic "
                + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode("ascii"),
            )
        if "user-agent" not in merged:
            merged.insert(0, "User-Agent", USER_AGENT)
        if self._decode and "accept-encoding" not in merged:
            merged.add("Accept-Encoding", ACCEPTED_ENCODINGS)
        return Request(method.upper(), target, merged, body)

    async def send(
        self,
        request: Request,
        *,
        cookies: Mapping[str, str] | None = None,
        timeout: float | Timeout | None | Unset = UNSET,
        allow_redirects: bool = True,
        proxy: Proxy | str | None | Unset = UNSET,
        stream: bool = False,
    ) -> Response:
        deadline = Deadline(
            self._timeout if isinstance(timeout, Unset) else Timeout.of(timeout)
        )
        route = (
            self._proxy
            if isinstance(proxy, Unset)
            else Proxy.parse(proxy)
            if isinstance(proxy, str)
            else proxy
        )
        history: list[Response] = []
        while True:
            response = await self._once(
                self._with_cookies(request, cookies), deadline, route
            )
            self.cookies.store(response.cookies)
            self._learn_alt_svc(response)
            if not allow_redirects or not response.is_redirect:
                response.history = tuple(history)
                if not stream:
                    try:
                        await response.read()
                    except BaseException:
                        await response.close()
                        raise
                return response
            if len(history) >= self._max_redirects:
                await response.close()
                raise TooManyRedirects(
                    f"more than {self._max_redirects} redirects from {history[0].url if history else request.url}"
                )
            await response.read()
            history.append(response)
            request = self._redirect(request, response)

    async def websocket(
        self,
        url: str,
        *,
        headers: HeaderItems | None = None,
        subprotocols: Sequence[str] = (),
        timeout: float | Timeout | None | Unset = UNSET,
        proxy: Proxy | str | None | Unset = UNSET,
    ) -> WebSocket:
        request = self.build("GET", url, headers=headers)
        if request.url.scheme not in ("ws", "wss"):
            raise ValueError(
                f"websocket needs a ws or wss URL, got {request.url.scheme}"
            )
        deadline = Deadline(
            self._timeout if isinstance(timeout, Unset) else Timeout.of(timeout)
        )
        route = (
            self._proxy
            if isinstance(proxy, Unset)
            else Proxy.parse(proxy)
            if isinstance(proxy, str)
            else proxy
        )
        request = Request("GET", request.url, request.headers)
        request.headers.remove("Accept-Encoding")
        async with deadline.phase("connect"):
            connection = await self._connect(
                request.url, route, self._prefers_quic(request.url, route)
            )
        if (
            isinstance(connection, (Http2Connection, Http3Connection))
            and connection.connect_protocol
        ):
            return await self._websocket_tunnel(
                connection,
                self._with_cookies(request, None),
                deadline,
                tuple(subprotocols),
            )
        if isinstance(connection, (Http2Connection, Http3Connection)):
            await connection.close()
            async with deadline.phase("connect"):
                connection = await self._connect(request.url, route, http1_only=True)
        if not isinstance(connection, Http1Connection):
            raise ProtocolError(
                "websocket needs an HTTP/1.1 or Extended CONNECT capable connection"
            )
        handshake, key = WebSocket.handshake(request.headers, tuple(subprotocols))
        request = Request("GET", request.url, handshake)
        try:
            response = await connection.send(
                self._with_cookies(request, None), deadline, decode=False
            )
            self.cookies.store(response.cookies)
            if response.status != 101:
                await response.read()
                raise ProtocolError(
                    f"websocket handshake answered {response.status} {response.reason}: {response.text[:200]}"
                )
            if response.headers.get("sec-websocket-accept") != WebSocket.accept(key):
                raise ProtocolError(
                    "websocket handshake answered with a wrong Sec-WebSocket-Accept"
                )
            chosen = response.headers.get("sec-websocket-protocol")
            if chosen is not None and chosen not in subprotocols:
                raise ProtocolError(
                    f"websocket handshake chose an unoffered subprotocol {chosen!r}"
                )
        except BaseException:
            await connection.close()
            raise
        transport, leftover = connection.detach()
        return WebSocket(
            transport,
            leftover,
            deadline,
            subprotocol=chosen,
            max_message_size=self._max_message_size,
        )

    async def _websocket_tunnel(
        self,
        connection: Http2Connection | Http3Connection,
        request: Request,
        deadline: Deadline,
        subprotocols: tuple[str, ...],
    ) -> WebSocket:
        headers = request.headers.copy()
        for name in ("Upgrade", "Connection", "Sec-WebSocket-Key"):
            headers.remove(name)
        headers.set("Sec-WebSocket-Version", "13")
        if subprotocols:
            headers.set("Sec-WebSocket-Protocol", ", ".join(subprotocols))
        status, response_headers, transport = await connection.tunnel(
            Request("CONNECT", request.url, headers), deadline
        )
        if status != 200:
            await transport.close()
            raise ProtocolError(f"websocket Extended CONNECT answered {status}")
        chosen = response_headers.get("sec-websocket-protocol")
        if chosen is not None and chosen not in subprotocols:
            await transport.close()
            raise ProtocolError(
                f"websocket handshake chose an unoffered subprotocol {chosen!r}"
            )
        return WebSocket(
            transport,
            b"",
            deadline,
            subprotocol=chosen,
            max_message_size=self._max_message_size,
        )

    def _context(
        self, protocols: tuple[NextProtocol, ...] | None = None
    ) -> ClientContext:
        if protocols not in self._contexts:
            hello = (
                self._http3.tls
                if protocols == (NextProtocol.H3,) and self._http3 is not None
                else self._adapted(protocols)
            )
            if hello is None:
                offered = protocols or tuple(
                    ALPN[version] for version in self._versions if version in ALPN
                )
                configuration = TLSClientConfiguration(
                    certificate_chain=self._certificate_chain,
                    trust_store=self._trust_store,
                    inner_protocols=offered,
                    verify_certificates=self._verify,
                )
            else:
                configuration = TLSClientConfiguration(
                    certificate_chain=self._certificate_chain,
                    trust_store=self._trust_store,
                    client_hello=hello,
                    verify_certificates=self._verify,
                )
            cache = (
                SessionCache()
                if hello is None or hello.offers(ExtensionType.pre_shared_key)
                else None
            )
            self._contexts[protocols] = ClientContext(
                configuration, session_cache=cache, key_log=self._key_log
            )
        return self._contexts[protocols]

    def _adapted(
        self, protocols: tuple[NextProtocol, ...] | None
    ) -> ClientHello | None:
        if self._tls is None or protocols is None:
            return self._tls
        # an HTTP/1.1-only connection keeps the ClientHello but can offer only its own protocol
        names = tuple(protocol.value for protocol in protocols)
        settings = tuple(
            name for name in self._tls.application_settings if name in names
        )
        return replace(
            self._tls,
            application_protocols=names,
            application_settings=settings,
            extensions=self._tls.extensions
            if settings
            else tuple(
                extension
                for extension in self._tls.extensions
                if extension
                not in (
                    ExtensionType.application_settings,
                    ExtensionType.application_settings_old,
                )
            ),
        )

    async def _checked(self, stream: TLSStream, authority: str) -> None:
        try:
            await self._verified(stream.buffer.getpeerchain(), authority)
        except BaseException:
            await stream.close()
            raise

    async def _verified(self, chain: tuple[bytes, ...], authority: str) -> None:
        await self._revocations.check(chain, authority)
        if self._check_peer is not None:
            await self._check_peer(chain, authority)

    async def _fetch_crl(self, url: str) -> bytes:
        async with Client(
            versions=(HTTPVersion.HTTP_1,), revocation=Revocation.NONE, timeout=10
        ) as inner:
            return (await inner.get(url)).body

    async def _connect(
        self,
        url: URL,
        proxy: Proxy | None,
        quic: bool = False,
        *,
        http1_only: bool = False,
    ) -> Connection:
        # a resolve= entry sends a direct connection elsewhere, while the URL's host stays the name sent and verified
        address = (
            self._resolve.get(url.address, url.address)
            if proxy is None
            else url.address
        )
        try:
            if quic and self._http3 is not None:
                memory = self._memory.setdefault(url.address, OriginMemory())
                client = await QuicClient.connect(
                    self._context((NextProtocol.H3,)),
                    url.host,
                    address,
                    self._http3.transport,
                    version=self._http3.quic_version,
                    proxy=proxy,
                    memory=memory,
                )
                try:
                    await self._verified(client.connection.peer_chain, url.authority)
                except BaseException:
                    client.close()
                    raise
                connection = Http3Connection(client, self._http3, memory)
                await connection.start()
                return connection
            if url.secure:
                stream = await TLSStream.connect(
                    self._context((NextProtocol.HTTP1,) if http1_only else None),
                    address,
                    proxy=proxy,
                    proxy_context=self._context((NextProtocol.HTTP1,))
                    if proxy is not None and proxy.scheme is ProxyScheme.HTTPS
                    else None,
                    server_hostname=url.host,
                )
                await self._checked(stream, url.authority)
                if (
                    stream.negotiated_protocol() is NextProtocol.H2
                    and self._http2 is not None
                ):
                    connection = Http2Connection(stream, self._http2)
                    await connection.start()
                    return connection
                return Http1Connection(stream)
            if proxy is not None and proxy.scheme in (
                ProxyScheme.HTTP,
                ProxyScheme.HTTPS,
            ):
                transport: AsyncTransport
                if proxy.scheme is ProxyScheme.HTTPS:
                    secured = await TLSStream.connect(
                        self._context((NextProtocol.HTTP1,)), (proxy.host, proxy.port)
                    )
                    await self._checked(secured, f"{proxy.host}:{proxy.port}")
                    transport = secured
                else:
                    transport = await SocketTransport.connect((proxy.host, proxy.port))
                authorization = None
                if proxy.credentials is not None:
                    authorization = "Basic " + base64.b64encode(
                        f"{proxy.credentials.username}:{proxy.credentials.password}".encode()
                    ).decode("ascii")
                return Http1Connection(
                    transport, absolute_form=True, proxy_authorization=authorization
                )
            tunnel = await TLSStream.tunnel(self._context(), address, proxy)
            return Http1Connection(tunnel.transport, leftover=tunnel.leftover)
        except ProxyError, ConfigurationError, RevocationError:
            raise
        except TLSError as error:
            raise ConnectError(
                f"TLS handshake with {url.authority} failed: {error}"
            ) from error
        except OSError as error:
            raise ConnectError(f"cannot connect to {url.authority}: {error}") from error

    async def _once(
        self, request: Request, deadline: Deadline, proxy: Proxy | None
    ) -> Response:
        quic = self._prefers_quic(request.url, proxy)
        for attempt in (1, 2):
            try:
                connection = await self._pool.acquire(
                    request.url, proxy, deadline, quic=quic
                )
            except ConnectError, TimeoutError:
                if quic and self._versions != (HTTPVersion.HTTP_3,):
                    # the learned HTTP/3 route is unreachable, so this origin goes back to TCP
                    self._alt_svc.pop(request.url.address, None)
                    quic = False
                    continue
                raise
            started = monotonic()
            replayable = request.body is None or request.body.replayable
            try:
                response = await connection.send(request, deadline, decode=self._decode)
            except StreamRefused:
                if attempt == 1 and replayable:
                    continue
                raise
            except RemoteDisconnected:
                if attempt == 1 and connection.reused and replayable:
                    continue
                raise
            response.started = started
            response.elapsed = monotonic() - started
            response.connection = replace(connection.info, reused=connection.reused)
            return response
        raise HTTPError("unreachable")

    def _prefers_quic(self, url: URL, proxy: Proxy | None) -> bool:
        if (
            HTTPVersion.HTTP_3 not in self._versions
            or not url.secure
            or (
                proxy is not None
                and proxy.scheme not in (ProxyScheme.SOCKS5, ProxyScheme.SOCKS5H)
            )
        ):
            return False
        if self._versions == (HTTPVersion.HTTP_3,):
            return True
        expiry = self._alt_svc.get(url.address)
        return expiry is not None and expiry > monotonic()

    def _learn_alt_svc(self, response: Response) -> None:
        if "alt-svc" not in response.headers:
            return
        for alternative in response.headers.get_all("alt-svc"):
            for entry in alternative.split(","):
                protocol, _, rest = entry.strip().partition("=")
                if protocol != "h3":
                    continue
                authority, *parameters = (part.strip() for part in rest.split(";"))
                if (
                    authority.strip('"')
                    != f":{response.url.port or response.url.default_port}"
                ):
                    continue
                age = next(
                    (
                        int(parameter[3:])
                        for parameter in parameters
                        if parameter.startswith("ma=")
                        and parameter[3:].isascii()
                        and parameter[3:].isdigit()
                    ),
                    86400,
                )
                self._alt_svc[response.url.address] = monotonic() + age

    def _with_cookies(
        self, request: Request, extra: Mapping[str, str] | None
    ) -> Request:
        parts = [
            value
            for value in (
                request.headers.get("cookie"),
                self.cookies.header(
                    request.url.host, request.url.path or "/", request.url.secure
                ),
            )
            if value
        ]
        if extra:
            parts.append("; ".join(f"{name}={value}" for name, value in extra.items()))
        if not parts:
            return request
        headers = request.headers.copy()
        headers.set("Cookie", "; ".join(parts))
        return Request(request.method, request.url, headers, request.body)

    def _redirect(self, request: Request, response: Response) -> Request:
        location = response.location
        if location is None:
            raise ProtocolError("redirect without a Location header")
        if not location.fragment and request.url.fragment:
            location = URL(
                location.scheme,
                location.host,
                location.port,
                location.path,
                location.query,
                request.url.fragment,
                location.username,
                location.password,
            )
        method, body = request.method, request.body
        headers = request.headers.copy()
        if response.status == 303 or (
            response.status in (301, 302) and method == "POST"
        ):
            method, body = ("HEAD" if method == "HEAD" else "GET"), None
            for name in ("Content-Type", "Content-Length", "Transfer-Encoding"):
                headers.remove(name)
        elif body is not None and not body.replayable:
            raise HTTPError(
                f"cannot repeat a streamed body for the {response.status} redirect to {location}"
            )
        if location.origin != request.url.origin:
            headers.remove("Authorization")
            headers.remove("Cookie")
        return Request(method, location, headers, body)

    @staticmethod
    def _body(
        json: object,
        data: FormFields | bytes | AsyncIterable[bytes] | None,
        content: bytes | str | AsyncIterable[bytes] | None,
        files: Mapping[str, FileField] | None,
    ) -> Body | None:
        given = [
            name
            for name, value in (
                ("json", json),
                ("data", data),
                ("content", content),
                ("files", files),
            )
            if value is not None
        ]
        if files is not None:
            if json is not None or content is not None:
                raise ValueError("files= cannot be combined with json= or content=")
            if isinstance(data, (bytes, AsyncIterable)):
                raise ValueError("files= takes form fields in data=, not a raw body")
            return Body.multipart(data, files)
        if len(given) > 1:
            raise ValueError(f"give one body, not {', '.join(given)}")
        if json is not None:
            return Body.json(json)
        if content is not None:
            return Body.content(content)
        match data:
            case None:
                return None
            case bytes():
                return Body.content(data)
            case Mapping() | Sequence():
                return Body.form(data)
            case _:
                return Body.content(data)
