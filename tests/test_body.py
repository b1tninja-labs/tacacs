"""RFC 8907 sec. 5, 6, 7 bodies, against octets laid out by hand from the section diagrams."""

from __future__ import annotations

import pytest

from tacacs.body import (
    AcctFlag,
    AcctReply,
    AcctRequest,
    AuthenContinue,
    AuthenReply,
    AuthenStart,
    AuthorReply,
    AuthorRequest,
    BodyError,
    account_command,
    authenticate_start,
    authorize_command,
    split_argument,
)


def test_authenticate_start():
    body = authenticate_start("adam", "tty10", "10.0.0.1")
    wire = bytes([1, 1, 1, 1, 4, 5, 8, 0]) + b"adamtty1010.0.0.1"
    assert body.encode() == wire
    assert AuthenStart.decode(wire) == body


def test_authenticate_start_rem_addr_len_counts_rem_addr_not_port():
    """Erratum 7754: rem_addr_len is the length of rem_addr."""
    wire = authenticate_start("u", "a-long-port-name", "::1").encode()
    assert wire[4:8] == bytes([1, 16, 3, 0])
    decoded = AuthenStart.decode(wire)
    assert (decoded.port, decoded.rem_addr) == (b"a-long-port-name", b"::1")


def test_authen_start_with_data_and_empty_optionals():
    body = AuthenStart(1, 15, 2, 1, user=b"", data=b"\x00\xff")
    assert AuthenStart.decode(body.encode()) == body
    assert body.encode()[:8] == bytes([1, 15, 2, 1, 0, 0, 0, 2])


def test_authen_reply():
    wire = bytes([0x05, 0x01, 0, 9, 0, 2]) + b"Password:" + b"\x01\x02"
    reply = AuthenReply.decode(wire)
    assert reply == AuthenReply(0x05, 0x01, b"Password:", b"\x01\x02")
    assert reply.noecho
    assert reply.encode() == wire


def test_authen_continue_lengths_follow_erratum_7754():
    wire = bytes([0, 3, 0, 1, 0x01]) + b"abc" + b"\x09"
    cont = AuthenContinue.decode(wire)
    assert cont == AuthenContinue(b"abc", b"\x09", 0x01)
    assert cont.abort
    assert cont.encode() == wire


def test_author_request():
    # sec. 6.1: method TACACSPLUS(6), priv 15, ASCII, LOGIN, user 3, port 0, rem_addr 7, 2 args.
    wire = (
        bytes([6, 15, 1, 1, 3, 0, 7, 2, 13, 5]) + b"bob" + b"1.2.3.4" + b"service=shell" + b"cmd*="
    )
    req = AuthorRequest.decode(wire)
    assert req.user == b"bob"
    assert req.rem_addr == b"1.2.3.4"
    assert req.args == (b"service=shell", b"cmd*=")
    assert req.encode() == wire


def test_authorize_command_builds_shell_arguments_in_order():
    req = authorize_command("bob", "show", ["ip", "route"], priv_lvl=15)
    assert req.args == (b"service=shell", b"cmd=show", b"cmd-arg=ip", b"cmd-arg=route")
    assert AuthorRequest.decode(req.encode()) == req


def test_author_reply():
    wire = bytes([0x01, 1, 0, 2, 0, 3, 8]) + b"ok" + b"log" + b"priv-lvl"
    reply = AuthorReply.decode(wire)
    assert reply == AuthorReply(0x01, b"ok", b"log", (b"priv-lvl",))
    assert reply.encode() == wire


def test_author_reply_pass_add_with_no_arguments():
    wire = AuthorReply(0x01).encode()
    assert wire == bytes([1, 0, 0, 0, 0, 0])


def test_acct_request_and_task_id_precedes_authorization_arguments():
    req = account_command("bob", "reload", 42, priv_lvl=15, port="tty1", rem_addr="1.2.3.4")
    assert req.args[0] == b"task_id=42"
    assert req.args[1:] == (b"service=shell", b"cmd=reload")
    assert req.flags == AcctFlag.START
    assert AcctRequest.decode(req.encode()) == req


def test_acct_request_wire_layout():
    req = AcctRequest(0x02, 6, 1, 1, 1, b"u", b"", b"", (b"a=b",))
    assert req.encode() == bytes([2, 6, 1, 1, 1, 1, 0, 0, 1, 3]) + b"u" + b"a=b"


def test_acct_reply_status_follows_the_lengths():
    wire = bytes([0, 2, 0, 1, 0x01]) + b"ok" + b"d"
    reply = AcctReply.decode(wire)
    assert reply == AcctReply(0x01, b"ok", b"d")
    assert reply.encode() == wire


@pytest.mark.parametrize(
    ("flags", "valid"),
    [
        (0x0, False),
        (0x2, True),
        (0x4, True),
        (0x6, False),
        (0x8, True),
        (0xA, True),
        (0xC, False),
        (0xE, False),
    ],
)
def test_accounting_flag_table(flags, valid):
    """sec. 7.2 Table 2."""
    assert AcctRequest(flags, 0, 0, 0, 0).flags_valid is valid


DECODERS = [
    AuthenStart,
    AuthenReply,
    AuthenContinue,
    AuthorRequest,
    AuthorReply,
    AcctRequest,
    AcctReply,
]


@pytest.mark.parametrize("cls", DECODERS)
def test_trailing_byte_is_a_length_mismatch(cls):
    sample = {
        AuthenStart: authenticate_start("a", "b"),
        AuthenReply: AuthenReply(1, 0, b"m"),
        AuthenContinue: AuthenContinue(b"m"),
        AuthorRequest: authorize_command("a", "b"),
        AuthorReply: AuthorReply(1, b"m", b"", (b"a=b",)),
        AcctRequest: account_command("a", "b", 1),
        AcctReply: AcctReply(1, b"m"),
    }[cls]
    wire = sample.encode()
    assert cls.decode(wire) == sample
    with pytest.raises(BodyError):
        cls.decode(wire + b"\x00")
    with pytest.raises(BodyError):
        cls.decode(wire[:-1])


@pytest.mark.parametrize("cls", DECODERS)
def test_every_truncation_is_refused(cls):
    for size in range(0, 4):
        with pytest.raises(BodyError):
            cls.decode(bytes(size) if size else b"")


def test_hostile_argument_count_does_not_overrun():
    wire = bytes([6, 15, 1, 1, 0, 0, 0, 255])
    with pytest.raises(BodyError):
        AuthorRequest.decode(wire)


def test_encode_refuses_oversize_fields():
    with pytest.raises(BodyError):
        AuthenStart(1, 1, 1, 1, user=b"x" * 256).encode()
    with pytest.raises(BodyError):
        AuthorRequest(1, 1, 1, 1, args=(b"a=" + b"x" * 254,)).encode()
    with pytest.raises(BodyError):
        AuthorRequest(1, 1, 1, 1, args=(b"a=b",) * 256).encode()
    with pytest.raises(BodyError):
        AuthenReply(1, 0, b"x" * 65536).encode()


def test_split_argument_uses_first_separator():
    assert split_argument(b"priv-lvl=15") == (b"priv-lvl", b"=", b"15")
    assert split_argument(b"cmd*show=x*y") == (b"cmd", b"*", b"show=x*y")
    assert split_argument(b"a=") == (b"a", b"=", b"")


@pytest.mark.parametrize("bad", [b"", b"a", b"=x", b"noseparator"])
def test_split_argument_refuses_malformed(bad):
    with pytest.raises(BodyError):
        split_argument(bad)
