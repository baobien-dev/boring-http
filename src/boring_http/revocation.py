from collections.abc import Awaitable, Callable
from enum import Enum

from boring_ssl2 import CertificateRevocationList, ParsedCertificate
from ssl2 import TLSError

from boring_http.errors import HTTPError, RevocationError


class Revocation(Enum):
    NONE = "none"
    SOFT = "soft"
    STRICT = "strict"


class Revocations:
    def __init__(
        self, policy: Revocation, fetch: Callable[[str], Awaitable[bytes]]
    ) -> None:
        self._policy = policy
        self._fetch = fetch
        self._lists: dict[str, CertificateRevocationList] = {}

    async def check(self, chain: tuple[bytes, ...], authority: str) -> None:
        if self._policy is Revocation.NONE or not chain:
            return
        leaf = ParsedCertificate(chain[0])
        urls = leaf.crl_urls
        if len(chain) < 2 or not urls:
            self._unavailable(f"{authority}: the certificate names no CRL to check")
            return
        issuer = ParsedCertificate(chain[1])
        for url in urls:
            revocation_list = self._lists.get(url)
            if revocation_list is None or not revocation_list.current:
                try:
                    revocation_list = CertificateRevocationList(await self._fetch(url))
                except (HTTPError, TLSError) as error:
                    self._unavailable(f"{authority}: CRL {url} unavailable: {error}")
                    continue
                if not revocation_list.signed_by(issuer):
                    self._unavailable(
                        f"{authority}: CRL {url} is not signed by the certificate's issuer"
                    )
                    continue
                self._lists[url] = revocation_list
            if revocation_list.revokes(leaf):
                raise RevocationError(
                    f"{authority}: certificate {leaf.serial} is revoked, says {url}"
                )
            return

    def _unavailable(self, reason: str) -> None:
        # the soft policy lets a connection through when no valid CRL can be had, as browsers do; the strict one does not
        if self._policy is Revocation.STRICT:
            raise RevocationError(reason)
