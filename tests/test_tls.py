"""RFC 9887 policy that needs no network."""

from __future__ import annotations

import ssl
from types import SimpleNamespace

import pytest

from tacacs import tls
from tacacs.header import Header, PacketType
from tacacs.tls import (
    TLS_PORT,
    PskUnavailableError,
    TlsPolicyError,
    check_tls_header,
    tls_client_context,
)


def test_client_context_requires_tls13_and_verification():
    context = tls_client_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_port_is_the_iana_assignment():
    assert TLS_PORT == 300


def test_check_tls_header_demands_the_unencrypted_flag():
    check_tls_header(Header(0xC, 0, PacketType.AUTHEN, 1, 0x01, 1, 0))
    with pytest.raises(TlsPolicyError):
        check_tls_header(Header(0xC, 0, PacketType.AUTHEN, 1, 0x00, 1, 0))


def test_psk_unavailable_on_312(monkeypatch):
    # PORTFOLIO.md sec. 9 item 15: on Python 3.12 tls.psk raises a named error and never hands
    # back a certificate context. The version is faked so this runs on every interpreter.
    monkeypatch.setattr(tls, "sys", SimpleNamespace(version_info=(3, 12, 9)))
    with pytest.raises(PskUnavailableError, match="does not fall back"):
        tls.psk_client_context("identity", b"k" * 32)
    with pytest.raises(PskUnavailableError):
        tls.psk_server_context({"identity": b"k" * 32})
    assert issubclass(PskUnavailableError, NotImplementedError)
