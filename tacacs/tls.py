"""The TLS 1.3 transport (RFC 9887).

``tls_client_context``, ``tls_server_context`` and ``check_tls_header`` are the policy RFC 9887
sec. 3.2 and 4 put on top of the RFC 8907 codec, and ``connect_tls`` opens the client connection
under it: TCP, then the TLS 1.3 handshake before any TACACS+ byte is sent.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import sys
from collections.abc import Mapping
from dataclasses import dataclass

from .header import Header

__all__ = [
    "PSK_SUPPORTED",
    "TLS_PORT",
    "PskUnavailableError",
    "TlsConnection",
    "TlsPolicyError",
    "check_tls_header",
    "connect_tls",
    "psk_client_context",
    "psk_server_context",
    "tls_client_context",
    "tls_server_context",
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


def tls_server_context(certfile: str, keyfile: str | None, *, client_cafile: str) -> ssl.SSLContext:
    """A server context for certificate-based mutual authentication: TLS 1.3, client verified.

    RFC 9887 sec. 3.1 says peers "MUST apply mutual authentication" and sec. 3.2 allows nothing
    below TLS 1.3, so the client's certificate is required and checked against ``client_cafile``
    (sec. 3.4). Which certificate fields identify the client (sec. 3.4.2: a network address or a
    shared subjectAltName identity) is policy for the caller, who reads the peer certificate from
    the connection. Revocation checking (sec. 3.4.1) is not done here.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile, keyfile)
    context.load_verify_locations(cafile=client_cafile)
    return context


@dataclass
class TlsConnection:
    """An established TACACS+ over TLS connection: the stream pair and what the handshake gave."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    version: str
    """The negotiated protocol, always ``"TLSv1.3"`` here (sec. 3.2)."""
    server_name: str
    """The name sent in SNI and checked against the server certificate (sec. 3.4.2)."""

    def peer_certificate(self) -> bytes | None:
        """The server's certificate in DER, or ``None`` for a PSK connection."""
        ssl_object = self.writer.get_extra_info("ssl_object")
        return None if ssl_object is None else ssl_object.getpeercert(binary_form=True)

    async def close(self) -> None:
        """Close the connection and wait for the transport to finish."""
        self.writer.close()
        # the peer may already have closed, or a TLS error ended it: either way it is closed
        with contextlib.suppress(OSError):  # ssl.SSLError and ConnectionError are OSErrors
            await self.writer.wait_closed()


async def connect_tls(
    server: str,
    context: ssl.SSLContext,
    *,
    port: int = TLS_PORT,
    server_name: str | None = None,
    timeout: float | None = 10.0,
) -> TlsConnection:
    """Open a TACACS+ over TLS connection and finish the handshake, RFC 9887 sec. 3.

    Sec. 3.2: the client makes the TCP connection to the TACACS+ TLS port (``TLS_PORT``, 300,
    unless sec. 3.1 deployment reasons set another) and "MUST immediately begin the TLS
    negotiation before sending any TACACS+ protocol data". This returns once the handshake is
    done, so the first byte the caller writes is already TLS application data. ``context`` must
    allow nothing below TLS 1.3 (a lower ``minimum_version`` raises ``ValueError``) and the
    negotiated version is checked again. ``server_name`` is the server's domain name for the SNI
    extension and for certificate verification; it defaults to ``server`` and is how a client
    configured with an address verifies a certificate issued to a name (sec. 3.4.2).

    Raises:
        ValueError: the context would allow a TLS version before 1.3.
        TimeoutError: TCP or the handshake did not finish within ``timeout`` seconds.
        ssl.SSLError, OSError: the handshake or the connection failed (a certificate that does not
            verify is an ``ssl.SSLCertVerificationError``).
    """
    if context.minimum_version != ssl.TLSVersion.TLSv1_3 or (
        context.maximum_version == ssl.TLSVersion.TLSv1_2
    ):
        raise ValueError("a TACACS+ TLS client needs minimum_version TLS 1.3 (RFC 9887 sec. 3.2)")
    name = server if server_name is None else server_name
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(server, port, ssl=context, server_hostname=name), timeout
    )
    ssl_object = writer.get_extra_info("ssl_object")
    version = ssl_object.version() if ssl_object is not None else None
    if version != "TLSv1.3":  # pragma: no cover - the context minimum already forbids this
        writer.close()
        raise ssl.SSLError(f"TACACS+ over TLS needs TLS 1.3, the handshake gave {version!r}")
    return TlsConnection(reader, writer, version, name)


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
