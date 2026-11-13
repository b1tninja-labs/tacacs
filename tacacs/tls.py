"""The TLS 1.3 transport (RFC 9887).

``tls_client_context`` and ``check_tls_header`` are the policy RFC 9887 sec. 3.2 and 4 put on
top of the RFC 8907 codec. ``connect_tls`` itself is still a placeholder: it raises instead of
connecting, so nothing mistakes it for a working transport.
"""

from __future__ import annotations

import ssl
import sys
from collections.abc import Mapping
from typing import TYPE_CHECKING

from .header import Header

if TYPE_CHECKING:
    from typing import Any

    Connection = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "PSK_SUPPORTED",
    "TLS_PORT",
    "PskUnavailableError",
    "TlsPolicyError",
    "check_tls_header",
    "connect_tls",
    "psk_client_context",
    "psk_server_context",
    "tls_client_context",
]

TLS_PORT = 300  # RFC 9887 sec. 7: service "tacacss", TCP port 300


class TlsPolicyError(ValueError):
    """A packet that breaks RFC 9887 sec. 4: the unencrypted flag is not set over TLS."""


class PskUnavailableError(NotImplementedError):
    """TLS external PSK is asked for on a Python whose ``ssl`` has no PSK callbacks (before 3.13).

    There is no fallback to certificates: a caller that asked for a PSK is told it cannot have one.
    """


def tls_client_context(
    *, cafile: str | None = None, certfile: str | None = None, keyfile: str | None = None
) -> ssl.SSLContext:
    """A client context for TACACS+ over TLS: TLS 1.3 minimum, server verified (RFC 9887 sec. 3.2).

    ``certfile`` and ``keyfile`` give the client certificate for mutual authentication
    (sec. 3.3 and 3.4). Earlier TLS versions MUST NOT be used, so the minimum is 1.3.
    Revocation checking (sec. 3.4.1) is not done by this helper.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    if cafile is None:
        context.load_default_certs()
    else:
        context.load_verify_locations(cafile=cafile)
    if certfile is not None:
        context.load_cert_chain(certfile, keyfile)
    return context


def check_tls_header(header: Header) -> None:
    """Refuse a header lacking the unencrypted flag over TLS (RFC 9887 sec. 4).

    The client sets the flag on every packet; a receiver that sees it clear must end the
    session (a server first answers with the status ERROR for the packet type, flag set).
    """
    if not header.unencrypted:
        raise TlsPolicyError("TAC_PLUS_UNENCRYPTED_FLAG is not set on a TLS connection")


async def connect_tls(server: str, context: ssl.SSLContext) -> Connection:
    """Pending behaviour defined by RFC 9887 sec. 3.

    Not implemented yet. See the ``tls.connect_tls()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("connect_tls() is not implemented: RFC 9887 sec. 3")


PSK_SUPPORTED = hasattr(ssl.SSLContext, "set_psk_client_callback")
"""``ssl`` offers external-PSK callbacks from Python 3.13; this project admits 3.12, which does not."""


_NO_PSK = (
    "TLS external PSK needs Python 3.13 or newer (ssl PSK callbacks); "
    "this project does not fall back to certificates"
)


def psk_client_context(identity: str, key: bytes) -> ssl.SSLContext:
    """A client context that authenticates with an external PSK, TLS 1.3 only (RFC 9887 sec. 3.5).

    Measured on Python 3.14.3 with OpenSSL 3.0.18 (``tests/test_tls_psk.py``): the handshake
    completes at TLS 1.3 with no certificate on either side, and a wrong key fails it. There is no
    server certificate, so ``check_hostname`` is off and the PSK is the authentication. The ``ssl``
    callback gives the identity as ``str``, so an identity that is not text cannot be offered
    (sec. 3.5 para 4 asks for identities of at least 16 octets, which text can be). The key is
    used as given: choosing, generating and distributing it follows RFC 9257 and is the caller's,
    and sec. 3.5 para 5 forbids reusing an obfuscation secret as a PSK.

    Raises:
        PskUnavailableError: this Python has no ``ssl`` PSK callbacks (before 3.13). It is a
            ``NotImplementedError``, and no certificate context is returned instead.
    """
    if sys.version_info < (3, 13):
        raise PskUnavailableError(_NO_PSK)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_psk_client_callback(lambda _hint: (identity, bytes(key)))
    return context


def psk_server_context(keys: Mapping[str, bytes]) -> ssl.SSLContext:
    """A server context that accepts the external PSKs in ``keys``, by identity (RFC 9887 sec. 3.5).

    An identity not in ``keys`` gets an empty key, which makes the handshake fail; the lookup
    does not say whether the identity or the key was wrong.
    """
    if sys.version_info < (3, 13):
        raise PskUnavailableError(_NO_PSK)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    table = {name: bytes(key) for name, key in keys.items()}
    context.set_psk_server_callback(lambda identity: table.get(identity or "", b""))
    return context
