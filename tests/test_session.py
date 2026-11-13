"""Sessions on a connection: RFC 8907 sec. 4.1 (sequence numbers), 4.3 (Single Connection Mode), 4.4.

Provenance: headers are built here from the field rules of sec. 4.1; nothing is captured. The
readings the module documents as its own (when "reached" 255 is, what the "second packet" rule
constrains, when the mode counts as established) are pinned so a change to them is deliberate.
"""

from __future__ import annotations

import pytest

from tacacs.body import AcctStatus, AuthenStatus, AuthorStatus
from tacacs.header import FLAG_SINGLE_CONNECT, FLAG_UNENCRYPTED, Header, PacketType
from tacacs.session import (
    MAX_SEQ,
    Connection,
    ReplyKind,
    SequenceExhausted,
    Sequencer,
    SessionError,
    classify_reply,
)

S1, S2, S3 = 0x11111111, 0x22222222, 0x33333333


def hdr(session, seq, flags=0, kind=PacketType.AUTHEN):
    return Header(0xC, 0, kind, seq, flags, session, 0)


def exchange(client, server, session, seq, *, cflags=0, sflags=0):
    """A client packet and the server's reply, both ends updated."""
    request, reply = hdr(session, seq, cflags), hdr(session, seq + 1, sflags)
    client.sent(request)
    server.received(request)
    server.sent(reply)
    client.received(reply)


def test_sequence_restart_at_255():
    client, server = Sequencer(client=True), Sequencer(client=False)
    numbers: list[int] = []

    def run() -> None:
        while True:
            number = client.send()
            numbers.append(number)
            server.receive(number)
            reply = server.send()
            numbers.append(reply)
            client.receive(reply)

    with pytest.raises(SequenceExhausted):
        run()
    # clients send odd numbers and servers even ones, 1 up to 254; 255 is never sent
    assert numbers[0] == 1
    assert numbers[-1] == 254
    assert numbers == list(range(1, 255))
    assert MAX_SEQ not in numbers
    # the restarted session is a fresh session with number 1 (a new Sequencer, a new session id)
    assert Sequencer(client=True).send() == 1
    # a peer that sends 255 anyway is refused
    with pytest.raises(SessionError, match="255"):
        server.receive(255)


def test_sequence_numbers_follow_one_per_packet_with_parity():
    client, server = Sequencer(client=True), Sequencer(client=False)
    assert client.send() == 1
    with pytest.raises(SessionError):
        client.send()  # not the client's turn: the server owes number 2
    server.receive(1)
    assert server.send() == 2
    for wrong in (4, 1, 3):
        with pytest.raises(SessionError):
            client.receive(wrong)
    client.receive(2)
    with pytest.raises(SessionError):
        server.receive(2)  # the wrong parity for a server to receive


def test_single_connection():
    # established: the client's first packet and the server's first reply both carry the flag
    client, server = Connection(client=True), Connection(client=False)
    assert client.single_connect is None
    assert client.can_start_session()
    exchange(client, server, S1, 1, cflags=FLAG_SINGLE_CONNECT, sflags=FLAG_SINGLE_CONNECT)
    assert client.single_connect is True
    assert server.single_connect is True
    client.complete(S1, ReplyKind.PASS)
    server.complete(S1, ReplyKind.PASS)
    assert not client.must_close  # SHOULD be left open (sec. 4.4)
    assert client.can_start_session()
    # a second session reuses the connection; the flag is ignored after the second packet
    exchange(client, server, S2, 1, cflags=0, sflags=0)
    assert client.single_connect is True
    assert client.active == 1
    # a session id is not reused on the connection
    client.complete(S2, ReplyKind.FAIL)
    with pytest.raises(SessionError, match="complete"):
        client.sent(hdr(S2, 1))


def test_single_connection_not_negotiated_closes_after_the_first_session():
    client, server = Connection(client=True), Connection(client=False)
    exchange(client, server, S1, 1, cflags=FLAG_SINGLE_CONNECT, sflags=0)  # server declines
    assert client.single_connect is False
    assert not client.can_start_session()
    with pytest.raises(SessionError, match="Single Connection Mode"):
        client.sent(hdr(S2, 1))
    assert not client.must_close  # the first session is still active
    client.complete(S1, ReplyKind.PASS)
    assert client.must_close  # sec. 4.3 para 6
    # a server flag the client never requested establishes nothing
    client, server = Connection(client=True), Connection(client=False)
    exchange(client, server, S1, 1, cflags=0, sflags=FLAG_SINGLE_CONNECT)
    assert client.single_connect is False


def test_session_completion_and_errors():
    # a connection error in single-connection mode: sessions in flight may finish, none starts
    client, server = Connection(client=True), Connection(client=False)
    exchange(client, server, S1, 1, cflags=FLAG_SINGLE_CONNECT, sflags=FLAG_SINGLE_CONNECT)
    client.sent(hdr(S2, 1))
    server.received(hdr(S2, 1))
    client.complete(S1, ReplyKind.ERROR, connection_error=True)  # an incorrect secret, say
    server.complete(S1, ReplyKind.ERROR, connection_error=True)
    assert not client.accepting
    assert not client.can_start_session()
    assert not client.must_close  # S2 is still in flight and MAY be completed (sec. 4.4 para 6)
    with pytest.raises(SessionError, match="no new sessions"):
        server.received(hdr(S3, 1))
    server.sent(hdr(S2, 2))
    client.received(hdr(S2, 2))
    client.complete(S2, ReplyKind.PASS)
    assert client.must_close  # once all active sessions are done the connection MUST close
    with pytest.raises(SessionError, match="completed"):
        client.received(hdr(S2, 4))
    with pytest.raises(SessionError, match="unknown session"):
        client.received(hdr(S3, 2))
    with pytest.raises(SessionError, match="more input"):
        client.complete(S2, ReplyKind.MORE)


def test_reply_statuses_map_to_what_the_client_does():
    authen = {
        AuthenStatus.PASS: ReplyKind.PASS,
        AuthenStatus.FAIL: ReplyKind.FAIL,
        AuthenStatus.FOLLOW: ReplyKind.FAIL,  # sec. 5.4.3 para 3: treat FOLLOW as FAIL
        AuthenStatus.ERROR: ReplyKind.ERROR,
        AuthenStatus.RESTART: ReplyKind.RESTART,
        AuthenStatus.GETDATA: ReplyKind.MORE,
        AuthenStatus.GETUSER: ReplyKind.MORE,
        AuthenStatus.GETPASS: ReplyKind.MORE,
    }
    for status, kind in authen.items():
        assert classify_reply(PacketType.AUTHEN, status) is kind
    assert classify_reply(PacketType.AUTHOR, AuthorStatus.PASS_ADD) is ReplyKind.PASS
    assert classify_reply(PacketType.AUTHOR, AuthorStatus.PASS_REPL) is ReplyKind.PASS
    assert classify_reply(PacketType.AUTHOR, AuthorStatus.FAIL) is ReplyKind.FAIL
    assert classify_reply(PacketType.AUTHOR, AuthorStatus.ERROR) is ReplyKind.ERROR
    assert classify_reply(PacketType.AUTHOR, AuthorStatus.FOLLOW) is ReplyKind.FAIL
    assert classify_reply(PacketType.ACCT, AcctStatus.SUCCESS) is ReplyKind.PASS
    assert classify_reply(PacketType.ACCT, AcctStatus.ERROR) is ReplyKind.ERROR
    for bad in ((PacketType.AUTHEN, 0x55), (PacketType.AUTHOR, 0x03), (0x09, 1)):
        with pytest.raises(SessionError):
            classify_reply(*bad)
    assert FLAG_UNENCRYPTED != FLAG_SINGLE_CONNECT
