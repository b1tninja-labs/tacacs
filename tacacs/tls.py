"""The TLS 1.3 transport (RFC 9887).

``tls_client_context`` and ``check_tls_header`` are the policy RFC 9887 sec. 3.2 and 4 put on
top of the RFC 8907 codec. ``connect_tls`` itself is still a placeholder: it raises instead of
connecting, so nothing mistakes it for a working transport.
"""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING

from .header import Header

if TYPE_CHECKING:
    from typing import Any

    Connection = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "TLS_PORT",
    "TlsPolicyError",
    "check_tls_header",
    "connect_tls",
    "tls_client_context",
]

TLS_PORT = 300  # RFC 9887 sec. 7: service "tacacss", TCP port 300


class TlsPolicyError(ValueError):
    """A packet that breaks RFC 9887 sec. 4: the unencrypted flag is not set over TLS."""


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
