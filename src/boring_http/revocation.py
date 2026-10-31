import logging
from collections.abc import Awaitable, Callable
from enum import StrEnum

from boring_ssl2 import CertificateRevocationList, Library, ParsedCertificate
from ssl2.errors import TLSError

from boring_http.errors import HTTPError, RevocationError


class Revocation(StrEnum):
    # none fetches no CRL; soft lets a connection through when no valid CRL can be had, as browsers do; strict does not
    NONE = "none"
    SOFT = "soft"
    STRICT = "strict"


class Revocations:
    # checks a leaf certificate against the CRLs it names, fetched through the caller and kept while they are current
    logger = logging.getLogger("boring_http")

    def __init__(self, policy: Revocation, fetch: Callable[[str], Awaitable[bytes]], library: Library) -> None:
        self._policy = policy
        self._fetch = fetch
        self._library = library
        self._lists: dict[str, CertificateRevocationList] = {}

    async def check(self, chain: tuple[bytes, ...], authority: str) -> None:
        if self._policy is Revocation.NONE:
            return
        match chain:
            case (leaf_der, issuer_der, *_):
                pass
            case _:
                self._unavailable(f"{authority}: the chain has no issuer to check a CRL against")
                return
        leaf = ParsedCertificate(leaf_der, self._library)
        urls = leaf.crl_urls
        if not urls:
            self._unavailable(f"{authority}: the certificate names no CRL to check")
            return
        issuer = ParsedCertificate(issuer_der, self._library)
        for url in urls:
            revocation_list = self._lists.get(url)
            if revocation_list is None or not revocation_list.current:
                try:
                    revocation_list = CertificateRevocationList(await self._fetch(url), self._library)
                except (HTTPError, TLSError) as error:
                    self._unavailable(f"{authority}: CRL {url} unavailable: {error}")
                    continue
                if not revocation_list.signed_by(issuer):
                    self._unavailable(f"{authority}: CRL {url} is not signed by the certificate's issuer")
                    continue
                self._lists[url] = revocation_list
            if revocation_list.revokes(leaf):
                raise RevocationError(f"{authority}: certificate {leaf.serial} is revoked, says {url}")
            return

    def _unavailable(self, reason: str) -> None:
        if self._policy is Revocation.STRICT:
            raise RevocationError(reason)
        self.logger.warning("revocation.unavailable %s", reason)
