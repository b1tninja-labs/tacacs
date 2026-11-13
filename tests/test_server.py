"""The fixture server: one secret per client, sessions, Single Connection Mode, wrong secrets.

Provenance: the client side is hand-driven in this file with the package's own header, body and
obfuscation codecs (all pinned by their own tests), over a real loopback TCP connection to the
server. The replies are checked field by field against RFC 8907 sec. 5.2, 6.2 and 7.2. No vendor
capture; ROADMAP.md keeps ``interop.vendor-capture`` open.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from tacacs import header as hdr
from tacacs.body import (
    AcctFlag,
    AcctReply,
    AcctStatus,
    AuthenContinue,
    AuthenReply,
    AuthenStatus,
    AuthorReply,
    AuthorStatus,
    account_command,
    authenticate_start,
    authorize_command,
)
from tacacs.header import FLAG_SINGLE_CONNECT, Header, PacketType
from tacacs.obfuscation import deobfuscate, obfuscate
from tacacs.server import SecretStore, StaticPolicy, start_server

SECRET = b"a-secret-of-at-least-32-characters!!"
OTHER = b"another-secret-entirely-xxxxxxxx"


class Client:
    def __init__(self, reader, writer, secret=SECRET):
        self.reader, self.writer, self.secret = reader, writer, secret

    async def send(self, kind, session, seq, body, *, flags=0, secret=None):
        header = Header(0xC, 0, kind, seq, flags, session, len(body))
        wire = obfuscate(body, header, secret or self.secret)
        self.writer.write(hdr.encode_header(header) + wire)
        await self.writer.drain()

    async def receive(self):
        raw = await asyncio.wait_for(self.reader.readexactly(hdr.HEADER_LENGTH), 5)
        header = hdr.decode_header(raw)
        body = await self.reader.readexactly(header.length)
        return header, deobfuscate(body, header, self.secret)

    async def closed(self):
        try:
            return await asyncio.wait_for(self.reader.read(1), 5) == b""
        except ConnectionResetError:  # Windows reports an unread-data close as a reset
            return True


async def running(policy):
    server = await start_server("127.0.0.1", 0, policy)
    return server, server.sockets[0].getsockname()[1]


async def connect(port, secret=SECRET):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    return Client(reader, writer, secret)


def policy():
    return StaticPolicy(
        SecretStore({"127.0.0.1": SECRET}),
        users={b"alice": b"wonderland"},
        allowed=frozenset({b"show"}),
    )


async def test_serve():
    server, port = await running(policy())
    async with server:
        c = await connect(port)
        # an ASCII login with a username in the START: GETPASS (noecho), then PASS (sec. 5)
        start = authenticate_start("alice", "tty1", "127.0.0.1")
        await c.send(PacketType.AUTHEN, 0xAAAA0001, 1, start.encode())
        header, body = await c.receive()
        reply = AuthenReply.decode(body)
        assert (header.seq_no, header.session_id) == (2, 0xAAAA0001)
        assert reply.status == AuthenStatus.GETPASS
        assert reply.noecho
        await c.send(PacketType.AUTHEN, 0xAAAA0001, 3, AuthenContinue(b"wonderland").encode())
        header, body = await c.receive()
        assert header.seq_no == 4
        assert AuthenReply.decode(body).status == AuthenStatus.PASS
        # not negotiated: the connection closes after the first session (sec. 4.3 para 6)
        assert await c.closed()
        c.writer.close()


async def test_wrong_password_authorization_and_accounting():
    p = policy()
    server, port = await running(p)
    async with server:
        c = await connect(port)
        await c.send(PacketType.AUTHEN, 1, 1, authenticate_start("", "tty1").encode())
        assert AuthenReply.decode((await c.receive())[1]).status == AuthenStatus.GETUSER
        await c.send(PacketType.AUTHEN, 1, 3, AuthenContinue(b"alice").encode())
        assert AuthenReply.decode((await c.receive())[1]).status == AuthenStatus.GETPASS
        await c.send(PacketType.AUTHEN, 1, 5, AuthenContinue(b"wrong").encode())
        assert AuthenReply.decode((await c.receive())[1]).status == AuthenStatus.FAIL
        c.writer.close()
        c = await connect(port)
        await c.send(PacketType.AUTHOR, 2, 1, authorize_command("alice", "show", ["ip"]).encode())
        assert AuthorReply.decode((await c.receive())[1]).status == AuthorStatus.PASS_ADD
        c.writer.close()
        c = await connect(port)
        await c.send(PacketType.AUTHOR, 3, 1, authorize_command("alice", "reload").encode())
        assert AuthorReply.decode((await c.receive())[1]).status == AuthorStatus.FAIL
        c.writer.close()
        c = await connect(port)
        request = account_command("alice", "show", 7, flags=AcctFlag.START | AcctFlag.STOP)
        await c.send(PacketType.ACCT, 4, 1, request.encode())
        # START together with STOP is INVALID in Table 2 and the server MUST answer ERROR
        assert AcctReply.decode((await c.receive())[1]).status == AcctStatus.ERROR
        c.writer.close()
        c = await connect(port)
        good = account_command("alice", "show", 8, flags=AcctFlag.STOP)
        await c.send(PacketType.ACCT, 5, 1, good.encode())
        assert AcctReply.decode((await c.receive())[1]).status == AcctStatus.SUCCESS
        assert p.accounted[-1].flags == AcctFlag.STOP
        c.writer.close()


async def test_single_connection_multiplexes_sessions():
    server, port = await running(policy())
    async with server:
        c = await connect(port)
        request = authorize_command("alice", "show").encode()
        await c.send(PacketType.AUTHOR, 11, 1, request, flags=FLAG_SINGLE_CONNECT)
        header, _ = await c.receive()
        assert header.single_connect  # the server grants it in its first reply (sec. 4.3 para 4)
        # the connection stays open and carries a second session; the flag is ignored now
        await c.send(PacketType.AUTHOR, 12, 1, request)
        header, body = await c.receive()
        assert header.session_id == 12
        assert not header.single_connect
        assert AuthorReply.decode(body).status == AuthorStatus.PASS_ADD
        # a repeated session id on the connection ends it
        await c.send(PacketType.AUTHOR, 11, 1, request)
        assert await c.closed()
        c.writer.close()


async def test_server_does_not_grant_single_connect_when_disabled():
    p = policy()
    p.allow_single_connect = False
    server, port = await running(p)
    async with server:
        c = await connect(port)
        request = authorize_command("alice", "show").encode()
        await c.send(PacketType.AUTHOR, 1, 1, request, flags=FLAG_SINGLE_CONNECT)
        header, _ = await c.receive()
        assert not header.single_connect
        assert await c.closed()
        c.writer.close()


async def test_wrong_secret_gets_error_and_ends_the_connection():
    server, port = await running(policy())
    async with server:
        c = await connect(port)
        body = authorize_command("alice", "show").encode()
        # obfuscated with another secret the lengths no longer add up (sec. 4.5): the answer is ERROR
        await c.send(PacketType.AUTHOR, 21, 1, body, flags=FLAG_SINGLE_CONNECT, secret=OTHER)
        header, reply = await c.receive()
        assert AuthorReply.decode(reply).status == AuthorStatus.ERROR
        assert not header.single_connect
        assert await c.closed()
        c.writer.close()


async def test_secret_per_client():
    # the client address 127.0.0.1 has no secret here: the server answers nothing and closes
    other = StaticPolicy(SecretStore({"192.0.2.0/24": SECRET}))
    server, port = await running(other)
    async with server:
        c = await connect(port)
        await c.send(PacketType.AUTHOR, 1, 1, authorize_command("alice", "show").encode())
        assert await c.closed()
        c.writer.close()


def test_secret_store_lookup_and_warnings(caplog):
    store = SecretStore(
        {
            "10.0.0.0/8": b"x" * 32,
            "10.1.0.0/16": b"y" * 32,
            "10.2.3.4": b"short",
            "2001:db8::/32": b"x" * 32,
        }
    )
    assert store.lookup("10.9.9.9") == b"x" * 32
    assert store.lookup("10.1.2.3") == b"y" * 32  # the most specific network wins
    assert store.lookup("10.2.3.4") == b"short"
    assert store.lookup("2001:db8::1") == b"x" * 32
    assert store.lookup("192.0.2.1") is None
    assert store.lookup("::1") is None
    text = " ".join(store.warnings())
    assert "shorter than 16" in text
    assert "10.2.3.4" in text
    assert "share one secret" in text
    assert "x" * 32 not in text
    assert "x" * 32 not in repr(store)
    assert "yyyy" not in repr(store)
    assert SecretStore({"10.0.0.1": b"s" * 64}).lookup("10.0.0.1") == b"s" * 64  # 32+ accepted
    with pytest.raises(ValueError, match="non-empty"):
        store.add("10.0.0.9", b"")

    async def start():
        with caplog.at_level(logging.WARNING, logger="tacacs.server"):
            server = await start_server("127.0.0.1", 0, StaticPolicy(store))
            server.close()
            await server.wait_closed()

    asyncio.run(start())
    assert any("share one secret" in r.getMessage() for r in caplog.records)


async def test_unencrypted_flag_is_refused_unless_allowed():
    # sec. 4.1: the unencrypted flag MUST NOT be used in production, so the server closes on it
    server, port = await running(policy())
    async with server:
        c = await connect(port)
        body = authorize_command("alice", "show").encode()
        header = Header(0xC, 0, PacketType.AUTHOR, 1, 0x01, 31, len(body))
        c.writer.write(hdr.encode_header(header) + body)
        assert await c.closed()
        c.writer.close()
    lax = policy()
    lax.allow_unencrypted = True
    server, port = await running(lax)
    async with server:
        c = await connect(port)
        c.writer.write(hdr.encode_header(header) + body)
        answer = hdr.decode_header(await c.reader.readexactly(12))
        assert answer.unencrypted
        assert (
            AuthorReply.decode(await c.reader.readexactly(answer.length)).status
            == AuthorStatus.PASS_ADD
        )
        c.writer.close()
