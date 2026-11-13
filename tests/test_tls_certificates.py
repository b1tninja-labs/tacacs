"""The TLS listener and ``connect_tls`` under certificate-based mutual authentication (RFC 9887 sec. 3.4).

Provenance: nothing here is a vendor capture. The certificates are minted per test run with the
``cryptography`` package (a dev dependency, used for nothing else): a throwaway CA, a server
certificate whose subjectAltName holds a DNS name and the loopback address, and a client certificate
with its own DNS name. The TACACS+ bytes are the package's own codecs, which their own tests pin.
Certificates work on every Python this project admits, so unlike the PSK tests these never skip.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import ssl
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tacacs import header as hdr
from tacacs.body import AuthenContinue, AuthenReply, AuthenStatus, authenticate_start
from tacacs.header import Header, PacketType
from tacacs.server import SecretStore, StaticPolicy, start_server
from tacacs.tls import TLS_PORT, TlsConnection, connect_tls, tls_client_context, tls_server_context

SERVER_NAME = "tacacs.example"
CLIENT_NAME = "client.example"
NOW = datetime.datetime(2026, 11, 13, tzinfo=datetime.UTC)


@dataclass
class Issued:
    cert_pem: Path
    key_pem: Path
    der: bytes


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _write(directory: Path, name: str, cert: x509.Certificate, key) -> Issued:
    cert_pem = directory / f"{name}.pem"
    key_pem = directory / f"{name}.key"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return Issued(cert_pem, key_pem, cert.public_bytes(serialization.Encoding.DER))


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def make_ca(directory: Path, name: str):
    key = _key()
    subject = _name(name)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert, _write(directory, name, cert, key)


def make_leaf(directory, name, ca_key, ca_cert, sans, *, client: bool):
    key = _key()
    usage = (
        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        if client
        else x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return _write(directory, name, cert, key)


@pytest.fixture
def pki(tmp_path):
    ca_key, ca_cert, ca = make_ca(tmp_path, "tacacs-test-ca")
    server = make_leaf(
        tmp_path,
        "server",
        ca_key,
        ca_cert,
        [x509.DNSName(SERVER_NAME), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
        client=False,
    )
    client = make_leaf(
        tmp_path, "client", ca_key, ca_cert, [x509.DNSName(CLIENT_NAME)], client=True
    )
    _other_key, _other_cert, stranger = make_ca(tmp_path, "some-other-ca")
    return {"ca": ca, "server": server, "client": client, "stranger": stranger}


def policy() -> StaticPolicy:
    return StaticPolicy(SecretStore(), users={b"alice": b"wonderland"})


async def listener(pki):
    context = tls_server_context(
        str(pki["server"].cert_pem),
        str(pki["server"].key_pem),
        client_cafile=str(pki["ca"].cert_pem),
    )
    server = await start_server("127.0.0.1", 0, policy(), ssl_context=context)
    return server, server.sockets[0].getsockname()[1]


def client_context(pki, *, with_certificate=True, cafile="ca"):
    return tls_client_context(
        cafile=str(pki[cafile].cert_pem),
        certfile=str(pki["client"].cert_pem) if with_certificate else None,
        keyfile=str(pki["client"].key_pem) if with_certificate else None,
    )


async def send(connection: TlsConnection, kind, session, seq, body):
    header = Header(0xC, 0, kind, seq, hdr.FLAG_UNENCRYPTED, session, len(body))
    connection.writer.write(hdr.encode_header(header) + body)
    await connection.writer.drain()


async def receive(connection: TlsConnection):
    head = hdr.decode_header(
        await asyncio.wait_for(connection.reader.readexactly(hdr.HEADER_LENGTH), 5)
    )
    return head, await connection.reader.readexactly(head.length)


async def test_connect_tls_defaults_to_port_300(monkeypatch):
    # RFC 9887 sec. 3.1 and sec. 7 assign port 300; the connection attempt is captured, not made
    seen = {}

    async def fake_open_connection(host, port, **options):
        seen.update(host=host, port=port, **options)
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    context = tls_client_context()
    with pytest.raises(ConnectionRefusedError):
        await connect_tls("aaa.example", context)
    assert seen["port"] == TLS_PORT == 300
    assert seen["server_hostname"] == "aaa.example"  # SNI defaults to the configured name
    assert seen["ssl"] is context


async def test_certificate_listener_serves_a_mutually_authenticated_client(pki):
    server, port = await listener(pki)
    async with server:
        connection = await connect_tls(
            "127.0.0.1", client_context(pki), port=port, server_name=SERVER_NAME
        )
        assert connection.version == "TLSv1.3"
        assert connection.server_name == SERVER_NAME
        assert connection.peer_certificate() == pki["server"].der
        start = authenticate_start("alice", "tty1", "127.0.0.1")
        await send(connection, PacketType.AUTHEN, 0xCC000001, 1, start.encode())
        head, body = await receive(connection)
        assert head.unencrypted  # sec. 4: set on every packet, and the body is plain text
        assert AuthenReply.decode(body).status == AuthenStatus.GETPASS
        await send(
            connection, PacketType.AUTHEN, 0xCC000001, 3, AuthenContinue(b"wonderland").encode()
        )
        head, body = await receive(connection)
        assert AuthenReply.decode(body).status == AuthenStatus.PASS
        await connection.close()


async def test_connect_tls_verifies_an_address_against_the_certificate_without_a_name(pki):
    # sec. 3.4.2: IP-ID is an applicable identifier, and the certificate holds 127.0.0.1
    server, port = await listener(pki)
    async with server:
        connection = await connect_tls("127.0.0.1", client_context(pki), port=port)
        assert connection.server_name == "127.0.0.1"
        await connection.close()


async def test_connect_tls_refuses_a_server_certificate_for_another_name(pki):
    server, port = await listener(pki)
    async with server:
        with pytest.raises(ssl.SSLCertVerificationError):
            await connect_tls(
                "127.0.0.1", client_context(pki), port=port, server_name="other.example"
            )


async def test_connect_tls_refuses_a_server_from_an_untrusted_ca(pki):
    server, port = await listener(pki)
    async with server:
        with pytest.raises(ssl.SSLCertVerificationError):
            await connect_tls(
                "127.0.0.1",
                client_context(pki, cafile="stranger"),
                port=port,
                server_name=SERVER_NAME,
            )


async def test_certificate_listener_refuses_a_client_without_a_certificate(pki):
    # sec. 3.1: mutual authentication. TLS 1.3 completes the client's side of the handshake before
    # the server's certificate check fails, so the refusal shows on the first use of the stream.
    server, port = await listener(pki)
    async with server:
        try:
            connection = await connect_tls(
                "127.0.0.1",
                client_context(pki, with_certificate=False),
                port=port,
                server_name=SERVER_NAME,
            )
        except (ssl.SSLError, OSError):
            return
        start = authenticate_start("alice", "tty1", "127.0.0.1")
        await send(connection, PacketType.AUTHEN, 1, 1, start.encode())
        with pytest.raises((ssl.SSLError, OSError, asyncio.IncompleteReadError)):
            await asyncio.wait_for(connection.reader.readexactly(hdr.HEADER_LENGTH), 5)


async def test_certificate_listener_refuses_a_client_from_an_untrusted_ca(pki, tmp_path):
    ca_key, ca_cert, _ = make_ca(tmp_path, "rogue-ca")
    rogue = make_leaf(tmp_path, "rogue", ca_key, ca_cert, [x509.DNSName(CLIENT_NAME)], client=True)
    server, port = await listener(pki)
    async with server:
        context = tls_client_context(
            cafile=str(pki["ca"].cert_pem),
            certfile=str(rogue.cert_pem),
            keyfile=str(rogue.key_pem),
        )
        try:
            connection = await connect_tls("127.0.0.1", context, port=port, server_name=SERVER_NAME)
        except (ssl.SSLError, OSError):
            return
        start = authenticate_start("alice", "tty1", "127.0.0.1")
        await send(connection, PacketType.AUTHEN, 2, 1, start.encode())
        with pytest.raises((ssl.SSLError, OSError, asyncio.IncompleteReadError)):
            await asyncio.wait_for(connection.reader.readexactly(hdr.HEADER_LENGTH), 5)


async def test_connect_tls_refuses_a_context_below_tls_13(pki):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises(ValueError, match=r"TLS 1\.3"):
        await connect_tls("127.0.0.1", context, port=1)


async def test_connect_tls_times_out_a_silent_server():
    # a server that accepts the TCP connection and never answers the handshake
    async def silent(reader, writer):
        await reader.read()  # never answers; returns when the client gives up and closes
        writer.close()

    server = await asyncio.start_server(silent, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        context = tls_client_context()
        with pytest.raises(TimeoutError):
            await connect_tls("127.0.0.1", context, port=port, timeout=0.3)


def test_tls_server_context_is_tls13_and_demands_a_client_certificate(pki):
    context = tls_server_context(
        str(pki["server"].cert_pem),
        str(pki["server"].key_pem),
        client_cafile=str(pki["ca"].cert_pem),
    )
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.verify_mode == ssl.CERT_REQUIRED
