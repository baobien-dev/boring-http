import ipaddress
import logging
import os
import socket
from collections.abc import AsyncGenerator, AsyncIterable, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import replace
from enum import Enum, IntEnum
from http import HTTPStatus
from time import monotonic
from typing import ClassVar, Self, TypedDict, Unpack

from boring_ssl2 import ClientContext, Library
from ssl2.asynchronous import AsyncTransport, SocketTransport, TLSStream
from ssl2.client_hello import ClientHello
from ssl2.credentials import SigningChain, TrustStore
from ssl2.errors import ConfigurationError, ProxyError, TLSError
from ssl2.interface import SessionCache, TLSClientConfiguration
from ssl2.proxy import Proxy, ProxyCredentials, ProxyScheme
from ssl2.registry import ExtensionType, NextProtocol
from ssl2.tracing import Phase as TracePhase
from ssl2.tracing import Trace

from boring_http.codings import ContentCoding
from boring_http.cookies import CookieJar
from boring_http.dns import Resolver, SystemResolver
from boring_http.errors import (
    ConnectError,
    HTTPError,
    ProtocolError,
    RemoteDisconnectedError,
    RequestTimeoutError,
    ResolveError,
    RevocationError,
    StreamRefusedError,
    TooManyRedirectsError,
)
from boring_http.headers import HeaderItems, Headers
from boring_http.http1 import Http1Connection
from boring_http.http2 import Http2Connection
from boring_http.http3 import Http3Connection
from boring_http.pool import Connection, Pool
from boring_http.profiles import Http1Profile, Http2Profile, Http3Profile, HTTPVersion
from boring_http.quic.protocol import OriginMemory, QuicClient
from boring_http.request import Body, FileField, FormFields, Method, Request
from boring_http.response import Response
from boring_http.revocation import Revocation, Revocations
from boring_http.timing import Deadline, Phase, Timeout
from boring_http.tracing import Event, Step
from boring_http.url import Params, Scheme, Url
from boring_http.websocket import Handshake, WebSocket


class Limit(IntEnum):
    CONNECTIONS = 100
    CONNECTIONS_PER_HOST = 10
    REDIRECTS = 20
    MESSAGE_SIZE = 16 << 20
    # a request is sent once more when a reused connection or a refused stream fails it before any response
    ATTEMPTS = 2
    CRL_TIMEOUT = 10
    # RFC 7838 section 3.1: an Alt-Svc entry without ma= lasts a day
    ALT_SVC_DEFAULT_AGE = 86400


class Seconds:
    IDLE = 90.0


class Inherit(Enum):
    # a per-request option left at this takes the client's setting; None is a value of its own
    CLIENT = "client"


class RequestOptions(TypedDict, total=False):
    params: Params | None
    headers: HeaderItems | None
    json: object
    data: FormFields | bytes | AsyncIterable[bytes] | None
    content: bytes | str | AsyncIterable[bytes] | None
    files: Mapping[str, FileField] | None
    auth: tuple[str, str] | None
    cookies: Mapping[str, str] | None
    timeout: float | Timeout | Inherit | None
    allow_redirects: bool
    proxy: Proxy | str | Inherit | None


class Client:
    logger = logging.getLogger("boring_http")
    USER_AGENT: ClassVar[str] = "boring-http"

    def __init__(
        self,
        *,
        headers: HeaderItems | None = None,
        timeout: float | Timeout | None = Timeout(),
        proxy: Proxy | str | None = None,
        tls: ClientHello | None = None,
        http1: Http1Profile | None = None,
        http2: Http2Profile | None = None,
        http3: Http3Profile | None = None,
        versions: Sequence[HTTPVersion | str] = (HTTPVersion.HTTP_2, HTTPVersion.HTTP_1),
        trust_store: TrustStore | None = None,
        verify: bool = True,
        revocation: Revocation = Revocation.SOFT,
        certificate_chain: SigningChain | None = None,
        check_peer: Callable[[tuple[bytes, ...], str], Awaitable[None]] | None = None,
        key_log: str | os.PathLike[str] | None = None,
        resolve: Mapping[tuple[str, int], tuple[str, int]] | None = None,
        resolver: Resolver | None = None,
        cookies: CookieJar | None = None,
        base_url: str | None = None,
        max_connections: int = Limit.CONNECTIONS,
        max_connections_per_host: int = Limit.CONNECTIONS_PER_HOST,
        max_idle_time: float | None = Seconds.IDLE,
        max_redirects: int = Limit.REDIRECTS,
        max_message_size: int = Limit.MESSAGE_SIZE,
        decode: bool = True,
        trace: bool = False,
        library: Library | None = None,
    ) -> None:
        self._headers = Headers(headers)
        self._timeout = Timeout.of(timeout)
        self._proxy = self._proxy_of(proxy)
        self._tls = tls
        self._http1 = http1 or Http1Profile()
        self._http2 = http2
        self._http3 = http3
        self._versions = tuple(HTTPVersion(version) for version in versions)
        # over TCP the ClientHello's own ALPN goes out when one is given, else the ALPN of versions
        offered = (
            tls.application_protocols
            if tls is not None
            else tuple(version.alpn.value for version in self._versions if version is not HTTPVersion.HTTP_3)
        )
        if http2 is None and NextProtocol.H2.value in offered:
            raise ConfigurationError("h2 is offered, so http2= needs an Http2Profile")
        if http3 is None and HTTPVersion.HTTP_3 in self._versions:
            raise ConfigurationError("h3 is in versions, so http3= needs an Http3Profile")
        self._library = library or Library.default()
        self._trust_store = trust_store
        self._verify = verify
        self._revocations = Revocations(revocation, self._fetch_crl, self._library)
        self._certificate_chain = certificate_chain
        self._check_peer = check_peer
        self._key_log = key_log
        self._resolve = {} if resolve is None else dict(resolve)
        self._resolver = SystemResolver() if resolver is None else resolver
        self._base_url = None if base_url is None else Url.parse(base_url)
        self._max_redirects = max_redirects
        self._max_message_size = max_message_size
        self._decode = decode
        self._trace = trace
        self._contexts: dict[tuple[NextProtocol, ...] | None, ClientContext] = {}
        self._memory: dict[tuple[str, int], OriginMemory] = {}
        # origins that announced HTTP/3 through Alt-Svc, and until when
        self._alt_svc: dict[tuple[str, int], float] = {}
        self._pool = Pool(self._connect, max_connections, max_connections_per_host, max_idle_time)
        self.cookies = CookieJar() if cookies is None else cookies

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._pool.close()

    async def request(self, method: str, url: str, **options: Unpack[RequestOptions]) -> Response:
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
            timeout=options.get("timeout", Inherit.CLIENT),
            allow_redirects=options.get("allow_redirects", True),
            proxy=options.get("proxy", Inherit.CLIENT),
        )

    async def get(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request(Method.GET, url, **options)

    async def post(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request(Method.POST, url, **options)

    async def put(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request(Method.PUT, url, **options)

    async def patch(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request(Method.PATCH, url, **options)

    async def delete(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request(Method.DELETE, url, **options)

    async def head(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request(Method.HEAD, url, **options)

    async def options(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        return await self.request(Method.OPTIONS, url, **options)

    @asynccontextmanager
    async def stream(self, method: str, url: str, **options: Unpack[RequestOptions]) -> AsyncGenerator[Response]:
        # the response with its body unread, to iterate; the body is closed with the block
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
            timeout=options.get("timeout", Inherit.CLIENT),
            allow_redirects=options.get("allow_redirects", True),
            proxy=options.get("proxy", Inherit.CLIENT),
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
        target = Url.parse(url) if self._base_url is None else self._base_url.join(url)
        if params is not None:
            target = target.with_params(params)
        body = self._body(json, data, content, files)
        merged = self._headers.copy() if headers is None else self._headers.merged(Headers(headers))
        if body is not None and body.content_type is not None and "content-type" not in merged:
            merged.add("Content-Type", body.content_type)
        if auth is not None:
            username, password = auth
            merged.set("Authorization", ProxyCredentials(username, password).basic)
        if "user-agent" not in merged:
            merged.insert(0, "User-Agent", self.USER_AGENT)
        if self._decode and "accept-encoding" not in merged:
            merged.add("Accept-Encoding", ContentCoding.accepted())
        return Request(method.upper(), target, merged, body)

    async def send(
        self,
        request: Request,
        *,
        cookies: Mapping[str, str] | None = None,
        timeout: float | Timeout | Inherit | None = Inherit.CLIENT,
        allow_redirects: bool = True,
        proxy: Proxy | str | Inherit | None = Inherit.CLIENT,
        stream: bool = False,
    ) -> Response:
        deadline = Deadline(self._timeout if timeout is Inherit.CLIENT else Timeout.of(timeout))
        route = self._proxy if proxy is Inherit.CLIENT else self._proxy_of(proxy)
        trace = Trace() if self._trace else None
        history: list[Response] = []
        while True:
            response = await self._once(self._with_cookies(request, cookies), deadline, route, trace)
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
                first = history[0].url if history else request.url
                raise TooManyRedirectsError(f"more than {self._max_redirects} redirects from {first}")
            await response.read()
            history.append(response)
            request = self._redirect(request, response)

    async def websocket(
        self,
        url: str,
        *,
        headers: HeaderItems | None = None,
        subprotocols: Sequence[str] = (),
        timeout: float | Timeout | Inherit | None = Inherit.CLIENT,
        proxy: Proxy | str | Inherit | None = Inherit.CLIENT,
    ) -> WebSocket:
        built = self.build(Method.GET, url, headers=headers)
        if built.url.scheme not in (Scheme.WS, Scheme.WSS):
            raise ConfigurationError(f"a websocket needs a ws or wss URL, not {built.url.scheme}")
        deadline = Deadline(self._timeout if timeout is Inherit.CLIENT else Timeout.of(timeout))
        route = self._proxy if proxy is Inherit.CLIENT else self._proxy_of(proxy)
        request_headers = built.headers.copy()
        request_headers.remove("Accept-Encoding")
        request = Request(Method.GET, built.url, request_headers)
        offered = tuple(subprotocols)
        async with deadline.phase(Phase.CONNECT):
            connection = await self._connect(
                request.url, route, quic=self._prefers_quic(request.url, route), trace=None
            )
        if isinstance(connection, Http2Connection | Http3Connection):
            if connection.connect_protocol:
                return await self._websocket_tunnel(connection, self._with_cookies(request, None), deadline, offered)
            # the server does not take Extended CONNECT, so the upgrade goes over a fresh HTTP/1.1 connection
            await connection.close()
            async with deadline.phase(Phase.CONNECT):
                connection = await self._connect(request.url, route, quic=False, trace=None, http1_only=True)
        if not isinstance(connection, Http1Connection):
            raise ProtocolError("a websocket needs an HTTP/1.1 or Extended CONNECT capable connection")
        return await self._websocket_upgrade(connection, request, deadline, offered)

    async def _websocket_upgrade(
        self, connection: Http1Connection, request: Request, deadline: Deadline, subprotocols: tuple[str, ...]
    ) -> WebSocket:
        # RFC 6455 section 4.1: the upgrade over HTTP/1.1, after which the connection carries frames
        handshake, key = WebSocket.handshake(request.headers, subprotocols)
        upgrade = self._with_cookies(Request(Method.GET, request.url, handshake), None)
        try:
            response = await connection.send(upgrade, deadline, decode=False, trace=None)
            self.cookies.store(response.cookies)
            if response.status != HTTPStatus.SWITCHING_PROTOCOLS:
                await response.read()
            chosen = self._accepted_upgrade(response, key, subprotocols)
        except BaseException:
            await connection.close()
            raise
        transport, leftover = connection.detach()
        return WebSocket(transport, leftover, deadline, subprotocol=chosen, max_message_size=self._max_message_size)

    @staticmethod
    def _accepted_upgrade(response: Response, key: str, subprotocols: tuple[str, ...]) -> str | None:
        # RFC 6455 section 4.1: what the server's answer must say; returns the subprotocol it chose
        if response.status != HTTPStatus.SWITCHING_PROTOCOLS:
            raise ProtocolError(
                f"the websocket handshake was answered {response.status} {response.reason}: {response.text[:200]}"
            )
        if response.headers.get("sec-websocket-accept") != WebSocket.accept(key):
            raise ProtocolError("the websocket handshake was answered with a wrong Sec-WebSocket-Accept")
        chosen = response.headers.get("sec-websocket-protocol")
        if chosen is not None and chosen not in subprotocols:
            raise ProtocolError(f"the websocket handshake chose an unoffered subprotocol {chosen!r}")
        return chosen

    async def _websocket_tunnel(
        self,
        connection: Http2Connection | Http3Connection,
        request: Request,
        deadline: Deadline,
        subprotocols: tuple[str, ...],
    ) -> WebSocket:
        # RFC 8441 and RFC 9220: a CONNECT stream with :protocol websocket
        headers = request.headers.copy()
        for name in ("Upgrade", "Connection", "Sec-WebSocket-Key"):
            headers.remove(name)
        headers.set("Sec-WebSocket-Version", Handshake.VERSION)
        if subprotocols:
            headers.set("Sec-WebSocket-Protocol", ", ".join(subprotocols))
        status, response_headers, transport = await connection.tunnel(
            Request(Method.CONNECT, request.url, headers), deadline
        )
        if status != HTTPStatus.OK:
            await transport.close()
            raise ProtocolError(f"the websocket Extended CONNECT was answered {status}")
        chosen = response_headers.get("sec-websocket-protocol")
        if chosen is not None and chosen not in subprotocols:
            await transport.close()
            raise ProtocolError(f"the websocket handshake chose an unoffered subprotocol {chosen!r}")
        return WebSocket(transport, b"", deadline, subprotocol=chosen, max_message_size=self._max_message_size)

    @staticmethod
    def _proxy_of(proxy: Proxy | str | None) -> Proxy | None:
        return Proxy.parse(proxy) if isinstance(proxy, str) else proxy

    def _context(self, protocols: tuple[NextProtocol, ...] | None) -> ClientContext:
        # one TLS context per set of offered protocols; None offers what versions says
        if protocols not in self._contexts:
            if protocols == (NextProtocol.H3,) and self._http3 is not None:
                hello = self._http3.tls
            else:
                hello = self._adapted(protocols)
            if hello is None:
                offered = protocols or tuple(
                    version.alpn for version in self._versions if version is not HTTPVersion.HTTP_3
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
            cache = SessionCache() if hello is None or hello.offers(ExtensionType.pre_shared_key) else None
            self._contexts[protocols] = ClientContext(
                configuration, session_cache=cache, key_log=self._key_log, library=self._library
            )
        return self._contexts[protocols]

    def _adapted(self, protocols: tuple[NextProtocol, ...] | None) -> ClientHello | None:
        if self._tls is None or protocols is None:
            return self._tls
        # an HTTP/1.1-only connection keeps the ClientHello but can offer only its own protocol
        names = tuple(protocol.value for protocol in protocols)
        settings = tuple(name for name in self._tls.application_settings if name in names)
        extensions = (
            self._tls.extensions
            if settings
            else tuple(
                extension
                for extension in self._tls.extensions
                if extension not in (ExtensionType.application_settings, ExtensionType.application_settings_old)
            )
        )
        return replace(self._tls, application_protocols=names, application_settings=settings, extensions=extensions)

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
        # the CRL is fetched the way this client resolves names, so no lookup goes past the resolver it was given
        async with Client(
            versions=(HTTPVersion.HTTP_1,),
            revocation=Revocation.NONE,
            timeout=Limit.CRL_TIMEOUT,
            resolver=self._resolver,
            library=self._library,
        ) as inner:
            return (await inner.get(url)).body

    async def _connect(
        self, url: Url, proxy: Proxy | None, *, quic: bool, trace: Trace | None, http1_only: bool = False
    ) -> Connection:
        addresses = await self._addresses(url, proxy, trace)
        try:
            # an address that fails at the socket or in QUIC passes to the next; the last one's failure is the error
            for address in addresses[:-1]:
                try:
                    return await self._connect_to(url, address, proxy, quic=quic, trace=trace, http1_only=http1_only)
                except ProxyError, RevocationError:
                    raise
                except (OSError, ConnectError) as error:
                    # an address passed over while others remain is routine, so it is a line for the record, not a warning
                    self.logger.info(
                        "%s host=%s address=%s error=%s", Event.CONNECTION_FAILED, url.host, address[0], error
                    )
            return await self._connect_to(url, addresses[-1], proxy, quic=quic, trace=trace, http1_only=http1_only)
        except ProxyError, ConfigurationError, RevocationError:
            raise
        except TLSError as error:
            raise ConnectError(f"the TLS handshake with {url.authority} failed: {error}") from error
        except OSError as error:
            raise ConnectError(f"cannot connect to {url.authority}: {error}") from error

    async def _addresses(self, url: Url, proxy: Proxy | None, trace: Trace | None) -> tuple[tuple[str, int], ...]:
        # a proxy that resolves names itself is handed the name; a resolve entry pins the address; the resolver
        # answers the rest, IPv4 only for a proxy that carries nothing else
        family = None if proxy is None else proxy.scheme.local_address_family
        if proxy is not None and family is None:
            return (url.address,)
        pinned = self._resolve.get(url.address)
        if pinned is not None:
            return (pinned,)
        started = monotonic()
        with Trace.timing(trace, TracePhase.RESOLVE):
            addresses = await self._resolver.resolve(url.host, url.port)
        if family == socket.AF_INET:
            addresses = tuple(
                address for address in addresses if isinstance(ipaddress.ip_address(address[0]), ipaddress.IPv4Address)
            )
        if not addresses:
            raise ResolveError(f"{url.host} resolves to no address")
        self.logger.info(
            "%s host=%s port=%d addresses=%d seconds=%.3f",
            Event.RESOLVED,
            url.host,
            url.port,
            len(addresses),
            monotonic() - started,
        )
        return addresses

    async def _connect_to(
        self,
        url: Url,
        address: tuple[str, int],
        proxy: Proxy | None,
        *,
        quic: bool,
        trace: Trace | None,
        http1_only: bool,
    ) -> Connection:
        # the address is where the packets go, while the URL's host stays the name sent and verified
        if quic and self._http3 is not None:
            return await self._connect_quic(url, address, proxy, self._http3, trace)
        if url.secure:
            return await self._connect_tls(url, address, proxy, trace, http1_only=http1_only)
        if proxy is not None and proxy.scheme in (ProxyScheme.HTTP, ProxyScheme.HTTPS):
            return await self._connect_forward_proxy(proxy, trace)
        tunnel = await TLSStream.tunnel(self._context(None), address, proxy, trace)
        return Http1Connection(tunnel.transport, self._http1, self._library, leftover=tunnel.leftover)

    async def _connect_quic(
        self, url: Url, address: tuple[str, int], proxy: Proxy | None, profile: Http3Profile, trace: Trace | None
    ) -> Connection:
        memory = self._memory.setdefault(url.address, OriginMemory())
        quic = await QuicClient.connect(
            self._context((NextProtocol.H3,)),
            url.host,
            address,
            profile.transport,
            version=profile.quic_version,
            proxy=proxy,
            memory=memory,
            trace=trace,
        )
        try:
            await self._verified(quic.connection.peer_chain, url.authority)
            connection = Http3Connection(quic, profile, self._library, memory)
            await connection.start()
        except BaseException:
            await quic.close()
            raise
        return connection

    async def _connect_tls(
        self, url: Url, address: tuple[str, int], proxy: Proxy | None, trace: Trace | None, *, http1_only: bool
    ) -> Connection:
        proxy_context = None
        if proxy is not None and proxy.scheme is ProxyScheme.HTTPS:
            proxy_context = self._context((NextProtocol.HTTP1,))
        stream = await TLSStream.connect(
            self._context((NextProtocol.HTTP1,) if http1_only else None),
            address,
            proxy=proxy,
            proxy_context=proxy_context,
            server_hostname=url.host,
            trace=trace,
        )
        await self._checked(stream, url.authority)
        if stream.negotiated_protocol() is NextProtocol.H2 and self._http2 is not None:
            connection = Http2Connection(stream, self._http2, self._library)
            await connection.start()
            return connection
        return Http1Connection(stream, self._http1, self._library)

    async def _connect_forward_proxy(self, proxy: Proxy, trace: Trace | None) -> Connection:
        # a plain http URL through an HTTP proxy: requests name the whole URL and carry the proxy's credentials
        transport: AsyncTransport
        if proxy.scheme is ProxyScheme.HTTPS:
            secured = await TLSStream.connect(self._context((NextProtocol.HTTP1,)), proxy.address, trace=trace)
            await self._checked(secured, f"{proxy.host}:{proxy.port}")
            transport = secured
        else:
            transport = await SocketTransport.connect(proxy.address)
        authorization = None if proxy.credentials is None else proxy.credentials.basic
        return Http1Connection(
            transport, self._http1, self._library, absolute_form=True, proxy_authorization=authorization
        )

    async def _once(self, request: Request, deadline: Deadline, proxy: Proxy | None, trace: Trace | None) -> Response:
        quic = self._prefers_quic(request.url, proxy)
        attempt = 1
        while True:
            try:
                with Trace.timing(trace, Step.POOL):
                    connection = await self._pool.acquire(request.url, proxy, deadline, quic=quic, trace=trace)
            except ConnectError, RequestTimeoutError:
                if quic and self._versions != (HTTPVersion.HTTP_3,):
                    # the learned HTTP/3 route is unreachable, so this origin goes back to TCP
                    self.logger.info("%s host=%s port=%d", Event.ALT_SVC_DROPPED, request.url.host, request.url.port)
                    self._alt_svc.pop(request.url.address, None)
                    quic = False
                    continue
                raise
            started = monotonic()
            replayable = request.body is None or request.body.replayable
            try:
                response = await connection.send(request, deadline, decode=self._decode, trace=trace)
            except StreamRefusedError as error:
                if attempt < Limit.ATTEMPTS and replayable:
                    self.logger.info("%s attempt=%d reason=%s", Event.RETRY, attempt, error)
                    attempt += 1
                    continue
                raise
            except RemoteDisconnectedError as error:
                if attempt < Limit.ATTEMPTS and connection.reused and replayable:
                    self.logger.info("%s attempt=%d reason=%s", Event.RETRY, attempt, error)
                    attempt += 1
                    continue
                raise
            response.started = started
            response.connection = replace(
                connection.info, reused=connection.reused, connect_time=connection.connect_time
            )
            return response

    def _prefers_quic(self, url: Url, proxy: Proxy | None) -> bool:
        if HTTPVersion.HTTP_3 not in self._versions or not url.secure:
            return False
        if proxy is not None and proxy.scheme not in (ProxyScheme.SOCKS5, ProxyScheme.SOCKS5H):
            return False
        if self._versions == (HTTPVersion.HTTP_3,):
            return True
        expiry = self._alt_svc.get(url.address)
        return expiry is not None and expiry > monotonic()

    def _learn_alt_svc(self, response: Response) -> None:
        # RFC 7838 section 3: h3=":443"; ma=86400 names an HTTP/3 service on the same host
        for value in response.headers.get_all("alt-svc"):
            for entry in value.split(","):
                protocol, equals, rest = entry.strip().partition("=")
                if not equals or protocol != HTTPVersion.HTTP_3:
                    continue
                authority, *parameters = (part.strip() for part in rest.split(";"))
                if authority.strip('"') != f":{response.url.port}":
                    continue
                age = Limit.ALT_SVC_DEFAULT_AGE
                for parameter in parameters:
                    name, _, argument = parameter.partition("=")
                    if name == "ma" and argument.isascii() and argument.isdigit():
                        age = int(argument)
                self._alt_svc[response.url.address] = monotonic() + age
                self.logger.info(
                    "%s host=%s port=%d seconds=%d", Event.ALT_SVC_LEARNED, response.url.host, response.url.port, age
                )

    def _with_cookies(self, request: Request, extra: Mapping[str, str] | None) -> Request:
        parts = [
            value
            for value in (
                request.headers.get("cookie"),
                self.cookies.header(request.url.host, request.url.path or "/", secure=request.url.secure),
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
        # RFC 9110 section 15.4: where the next request goes and what it keeps
        location = response.location
        if location is None:
            raise ProtocolError("a redirect without a Location header")
        if not location.fragment and request.url.fragment:
            location = location.with_fragment(request.url.fragment)
        method, body = request.method, request.body
        headers = request.headers.copy()
        if response.status == HTTPStatus.SEE_OTHER or (
            response.status in (HTTPStatus.MOVED_PERMANENTLY, HTTPStatus.FOUND) and method == Method.POST
        ):
            method, body = (Method.HEAD if method == Method.HEAD else Method.GET), None
            for name in ("Content-Type", "Content-Length", "Transfer-Encoding"):
                headers.remove(name)
        elif body is not None and not body.replayable:
            raise HTTPError(f"cannot repeat a streamed body for the {response.status} redirect to {location}")
        if location.origin != request.url.origin:
            headers.remove("Authorization")
            headers.remove("Cookie")
        self.logger.info("%s status=%d url=%s", Event.REDIRECT, response.status, location)
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
            for name, value in (("json", json), ("data", data), ("content", content), ("files", files))
            if value is not None
        ]
        if files is not None:
            if json is not None or content is not None:
                raise ConfigurationError("files= cannot be combined with json= or content=")
            if isinstance(data, bytes | AsyncIterable):
                raise ConfigurationError("files= takes form fields in data=, not a raw body")
            return Body.multipart(data, files)
        if len(given) > 1:
            raise ConfigurationError(f"give one body, not {', '.join(given)}")
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
