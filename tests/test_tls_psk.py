"""TLS 1.3 external PSK through the standard library (RFC 9887 sec. 3.5).

Provenance: measured, not assumed. The probe ran on Python 3.14.3 with OpenSSL 3.0.18 and showed
that ``SSLContext.set_psk_client_callback`` and ``set_psk_server_callback`` complete a TLS 1.3
handshake with no certificate on either side. These tests keep that finding true: they connect
two contexts over a socket pair, so a Python or OpenSSL that stops doing it fails here.
"""

from __future__ import annotations

import socket
import ssl
import threading

import pytest

from tacacs.header import FLAG_UNENCRYPTED, Header, PacketType, decode_header, encode_header
from tacacs.tls import PSK_SUPPORTED, check_tls_header, psk_client_context, psk_server_context

pytestmark = pytest.mark.skipif(not PSK_SUPPORTED, reason="ssl PSK callbacks need Python 3.13")

IDENTITY = "tacacs-client-0001-identity"  # 27 octets: sec. 3.5 para 4 asks for 16 or more
KEY = bytes(range(32))


def handshake(client_ctx, server_ctx, payload=b""):
    a, b = socket.socketpair()
    result = {}

    def serve():
        try:
            with server_ctx.wrap_socket(a, server_side=True) as s:
                result["server_version"] = s.version()
                if payload:
                    result["received"] = s.recv(4096)
                    s.sendall(result["received"])
        except (ssl.SSLError, OSError) as error:
            result["server_error"] = error
            a.close()

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        with client_ctx.wrap_socket(b, server_hostname="tacacs.example") as c:
            result["client_version"] = c.version()
            if payload:
                c.sendall(payload)
                result["echo"] = c.recv(4096)
    except (ssl.SSLError, OSError) as error:
        result["client_error"] = error
        b.close()
    thread.join(10)
    return result


def test_psk_handshake_is_tls13_and_carries_a_tacacs_packet():
    header = Header(0xC, 0, PacketType.AUTHEN, 1, FLAG_UNENCRYPTED, 7, 0)
    wire = encode_header(header)
    result = handshake(psk_client_context(IDENTITY, KEY), psk_server_context({IDENTITY: KEY}), wire)
    assert result["client_version"] == "TLSv1.3"
    assert result["server_version"] == "TLSv1.3"
    # the TACACS+ packet crosses the TLS channel unobfuscated, as RFC 9887 sec. 4 requires
    check_tls_header(decode_header(result["echo"]))
    # a 16-octet key and a 16-octet identity are the floor sec. 3.5 says MUST be supported
    short = handshake(
        psk_client_context("0123456789abcdef", b"k" * 16),
        psk_server_context({"0123456789abcdef": b"k" * 16}),
    )
    assert short["client_version"] == "TLSv1.3"


def test_psk_handshake_fails_with_the_wrong_key_or_identity():
    server = psk_server_context({IDENTITY: KEY})
    wrong_key = handshake(psk_client_context(IDENTITY, bytes(reversed(KEY))), server)
    assert "client_error" in wrong_key or "server_error" in wrong_key
    assert "client_version" not in wrong_key
    unknown = handshake(psk_client_context("someone-else-entirely", KEY), server)
    assert "client_version" not in unknown
    # the contexts are TLS 1.3 only: a TLS 1.2 client cannot reach them
    old = psk_client_context(IDENTITY, KEY)
    old.minimum_version = ssl.TLSVersion.TLSv1_2
    old.maximum_version = ssl.TLSVersion.TLSv1_2
    assert "client_version" not in handshake(old, server)
