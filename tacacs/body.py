"""Authentication, authorization and accounting packet bodies (RFC 8907 sec. 5, 6 and 7).

Each body type is a frozen dataclass with ``encode()`` and ``decode(raw)``. Text fields are
kept as ``bytes``: sec. 3.7 makes usernames a PRECIS profile and other text printable US-ASCII,
and that policy belongs to the caller, not to the byte codec.

Decoding is strict about lengths. After de-obfuscation RFC 8907 sec. 4.5 says the component
lengths are summed and compared with the header length, and a mismatch means the packet is
discarded and an error signalled; ``decode`` raises ``BodyError`` for any difference, short
or long. The length checks follow the corrected text of verified erratum 7754: rem_addr_len
is the length of rem_addr and user_msg_len is the length of user_msg.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import Self

__all__ = [
    "AcctFlag",
    "AcctReply",
    "AcctRequest",
    "AcctStatus",
    "AuthenAction",
    "AuthenContinue",
    "AuthenMethod",
    "AuthenReply",
    "AuthenService",
    "AuthenStart",
    "AuthenStatus",
    "AuthenType",
    "AuthorReply",
    "AuthorRequest",
    "AuthorStatus",
    "BodyError",
    "account_command",
    "authenticate_start",
    "authorize_command",
    "split_argument",
]


class BodyError(ValueError):
    """A body that cannot be encoded, or that is malformed or has the wrong total length."""


# --- registries (RFC 8907 sec. 5.1, 5.2, 5.3, 6.1, 6.2, 7.1, 7.2) ---------------------------


class AuthenAction(IntEnum):
    LOGIN = 0x01
    CHPASS = 0x02
    SENDAUTH = 0x04


class AuthenType(IntEnum):
    NOT_SET = 0x00  # valid only in authorization and accounting (sec. 6.1)
    ASCII = 0x01
    PAP = 0x02
    CHAP = 0x03
    MSCHAP = 0x05
    MSCHAPV2 = 0x06


class AuthenService(IntEnum):
    NONE = 0x00
    LOGIN = 0x01
    ENABLE = 0x02
    PPP = 0x03
    PT = 0x05
    RCMD = 0x06
    X25 = 0x07
    NASI = 0x08
    FWPROXY = 0x09


class AuthenStatus(IntEnum):
    PASS = 0x01
    FAIL = 0x02
    GETDATA = 0x03
    GETUSER = 0x04
    GETPASS = 0x05
    RESTART = 0x06
    ERROR = 0x07
    FOLLOW = 0x21


class AuthenMethod(IntEnum):
    NOT_SET = 0x00
    NONE = 0x01
    KRB5 = 0x02
    LINE = 0x03
    ENABLE = 0x04
    LOCAL = 0x05
    TACACSPLUS = 0x06
    GUEST = 0x08
    RADIUS = 0x10
    KRB4 = 0x11
    RCMD = 0x20


class AuthorStatus(IntEnum):
    PASS_ADD = 0x01
    PASS_REPL = 0x02
    FAIL = 0x10
    ERROR = 0x11
    FOLLOW = 0x21


class AcctStatus(IntEnum):
    SUCCESS = 0x01
    ERROR = 0x02
    FOLLOW = 0x21


class AcctFlag(IntFlag):
    START = 0x02
    STOP = 0x04
    WATCHDOG = 0x08


REPLY_FLAG_NOECHO = 0x01  # TAC_PLUS_REPLY_FLAG_NOECHO
CONTINUE_FLAG_ABORT = 0x01  # TAC_PLUS_CONTINUE_FLAG_ABORT


# --- helpers ---------------------------------------------------------------------------------


def _text(value: str | bytes) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def _u8(name: str, value: int) -> int:
    if not 0 <= value <= 0xFF:
        raise BodyError(f"{name} {value} does not fit one octet")
    return int(value)


def _field(name: str, value: bytes, limit: int) -> bytes:
    if len(value) > limit:
        raise BodyError(f"{name} is {len(value)} octets, the limit is {limit}")
    return value


def _check_args(args: Sequence[bytes]) -> None:
    if len(args) > 0xFF:
        raise BodyError(f"{len(args)} arguments, the limit is 255")
    for arg in args:
        _field("argument", arg, 0xFF)  # sec. 6.1: at most 255 characters


class _Reader:
    """A cursor over a body that refuses to run past its end."""

    def __init__(self, raw: bytes) -> None:
        self._raw = raw
        self._at = 0

    def take(self, count: int) -> bytes:
        end = self._at + count
        if end > len(self._raw):
            raise BodyError("body is shorter than its length fields say")
        chunk = self._raw[self._at : end]
        self._at = end
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def finish(self) -> None:
        if self._at != len(self._raw):
            raise BodyError("body is longer than its length fields say")


def split_argument(arg: bytes) -> tuple[bytes, bytes, bytes]:
    """Split an argument-value pair at its first separator (RFC 8907 sec. 6.1).

    Returns (name, separator, value); the separator is ``=`` for a mandatory argument and
    ``*`` for an optional one. The name never contains a separator and the value may.
    """
    if not 2 <= len(arg) <= 0xFF:
        raise BodyError("an argument-value string is 2 to 255 octets")
    cut = min((i for i in (arg.find(b"="), arg.find(b"*")) if i >= 0), default=-1)
    if cut < 1:
        raise BodyError("an argument needs a non-empty name and a separator")
    return arg[:cut], arg[cut : cut + 1], arg[cut + 1 :]


# --- authentication (sec. 5) -----------------------------------------------------------------


@dataclass(frozen=True)
class AuthenStart:
    """RFC 8907 sec. 5.1."""

    action: int
    priv_lvl: int
    authen_type: int
    authen_service: int
    user: bytes = b""
    port: bytes = b""
    rem_addr: bytes = b""
    data: bytes = b""

    def encode(self) -> bytes:
        lens = (
            _field("user", self.user, 0xFF),
            _field("port", self.port, 0xFF),
            _field("rem_addr", self.rem_addr, 0xFF),
            _field("data", self.data, 0xFF),
        )
        head = struct.pack(
            ">8B",
            _u8("action", self.action),
            _u8("priv_lvl", self.priv_lvl),
            _u8("authen_type", self.authen_type),
            _u8("authen_service", self.authen_service),
            *(len(v) for v in lens[:3]),
            len(lens[3]),
        )
        return head + b"".join(lens)

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        r = _Reader(raw)
        action, priv, atype, service = r.take(4)
        user_len, port_len, rem_len, data_len = r.take(4)
        user, port, rem, data = (
            r.take(user_len),
            r.take(port_len),
            r.take(rem_len),
            r.take(data_len),
        )
        r.finish()
        return cls(action, priv, atype, service, user, port, rem, data)


@dataclass(frozen=True)
class AuthenReply:
    """RFC 8907 sec. 5.2."""

    status: int
    flags: int = 0
    server_msg: bytes = b""
    data: bytes = b""

    @property
    def noecho(self) -> bool:
        return bool(self.flags & REPLY_FLAG_NOECHO)

    def encode(self) -> bytes:
        msg = _field("server_msg", self.server_msg, 0xFFFF)
        data = _field("data", self.data, 0xFFFF)
        head = struct.pack(
            ">BBHH", _u8("status", self.status), _u8("flags", self.flags), len(msg), len(data)
        )
        return head + msg + data

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        r = _Reader(raw)
        status, flags = r.take(2)
        msg_len, data_len = r.u16(), r.u16()
        msg, data = r.take(msg_len), r.take(data_len)
        r.finish()
        return cls(status, flags, msg, data)


@dataclass(frozen=True)
class AuthenContinue:
    """RFC 8907 sec. 5.3, with erratum 7754: user_msg_len is the length of user_msg."""

    user_msg: bytes = b""
    data: bytes = b""
    flags: int = 0

    @property
    def abort(self) -> bool:
        return bool(self.flags & CONTINUE_FLAG_ABORT)

    def encode(self) -> bytes:
        msg = _field("user_msg", self.user_msg, 0xFFFF)
        data = _field("data", self.data, 0xFFFF)
        return struct.pack(">HHB", len(msg), len(data), _u8("flags", self.flags)) + msg + data

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        r = _Reader(raw)
        msg_len, data_len = r.u16(), r.u16()
        flags = r.u8()
        msg, data = r.take(msg_len), r.take(data_len)
        r.finish()
        return cls(msg, data, flags)


# --- authorization (sec. 6) ------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorRequest:
    """RFC 8907 sec. 6.1, with erratum 7754: rem_addr_len is the length of rem_addr."""

    authen_method: int
    priv_lvl: int
    authen_type: int
    authen_service: int
    user: bytes = b""
    port: bytes = b""
    rem_addr: bytes = b""
    args: tuple[bytes, ...] = ()

    def encode(self) -> bytes:
        _check_args(self.args)
        head = struct.pack(
            ">8B",
            _u8("authen_method", self.authen_method),
            _u8("priv_lvl", self.priv_lvl),
            _u8("authen_type", self.authen_type),
            _u8("authen_service", self.authen_service),
            len(_field("user", self.user, 0xFF)),
            len(_field("port", self.port, 0xFF)),
            len(_field("rem_addr", self.rem_addr, 0xFF)),
            len(self.args),
        )
        lens = bytes(len(a) for a in self.args)
        return head + lens + self.user + self.port + self.rem_addr + b"".join(self.args)

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        r = _Reader(raw)
        method, priv, atype, service = r.take(4)
        user_len, port_len, rem_len, arg_cnt = r.take(4)
        arg_lens = r.take(arg_cnt)
        user, port, rem = r.take(user_len), r.take(port_len), r.take(rem_len)
        args = tuple(r.take(n) for n in arg_lens)
        r.finish()
        return cls(method, priv, atype, service, user, port, rem, args)


@dataclass(frozen=True)
class AuthorReply:
    """RFC 8907 sec. 6.2."""

    status: int
    server_msg: bytes = b""
    data: bytes = b""
    args: tuple[bytes, ...] = ()

    def encode(self) -> bytes:
        _check_args(self.args)
        msg = _field("server_msg", self.server_msg, 0xFFFF)
        data = _field("data", self.data, 0xFFFF)
        head = struct.pack(">BBHH", _u8("status", self.status), len(self.args), len(msg), len(data))
        return head + bytes(len(a) for a in self.args) + msg + data + b"".join(self.args)

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        r = _Reader(raw)
        status, arg_cnt = r.take(2)
        msg_len, data_len = r.u16(), r.u16()
        arg_lens = r.take(arg_cnt)
        msg, data = r.take(msg_len), r.take(data_len)
        args = tuple(r.take(n) for n in arg_lens)
        r.finish()
        return cls(status, msg, data, args)


# --- accounting (sec. 7) ---------------------------------------------------------------------


@dataclass(frozen=True)
class AcctRequest:
    """RFC 8907 sec. 7.1; the other fields have the semantics of sections 5 and 6."""

    flags: int
    authen_method: int
    priv_lvl: int
    authen_type: int
    authen_service: int
    user: bytes = b""
    port: bytes = b""
    rem_addr: bytes = b""
    args: tuple[bytes, ...] = ()

    @property
    def flags_valid(self) -> bool:
        """False for the INVALID rows of Table 2 (sec. 7.2): a server MUST answer ERROR."""
        start = bool(self.flags & AcctFlag.START)
        stop = bool(self.flags & AcctFlag.STOP)
        watchdog = bool(self.flags & AcctFlag.WATCHDOG)
        if stop and (start or watchdog):
            return False  # sec. 7.2: START and STOP are exclusive, STOP never goes with WATCHDOG
        return start or stop or watchdog

    def encode(self) -> bytes:
        _check_args(self.args)
        head = struct.pack(
            ">9B",
            _u8("flags", self.flags),
            _u8("authen_method", self.authen_method),
            _u8("priv_lvl", self.priv_lvl),
            _u8("authen_type", self.authen_type),
            _u8("authen_service", self.authen_service),
            len(_field("user", self.user, 0xFF)),
            len(_field("port", self.port, 0xFF)),
            len(_field("rem_addr", self.rem_addr, 0xFF)),
            len(self.args),
        )
        lens = bytes(len(a) for a in self.args)
        return head + lens + self.user + self.port + self.rem_addr + b"".join(self.args)

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        r = _Reader(raw)
        flags, method, priv, atype, service = r.take(5)
        user_len, port_len, rem_len, arg_cnt = r.take(4)
        arg_lens = r.take(arg_cnt)
        user, port, rem = r.take(user_len), r.take(port_len), r.take(rem_len)
        args = tuple(r.take(n) for n in arg_lens)
        r.finish()
        return cls(flags, method, priv, atype, service, user, port, rem, args)


@dataclass(frozen=True)
class AcctReply:
    """RFC 8907 sec. 7.2 (the status octet follows the two lengths)."""

    status: int
    server_msg: bytes = b""
    data: bytes = b""

    def encode(self) -> bytes:
        msg = _field("server_msg", self.server_msg, 0xFFFF)
        data = _field("data", self.data, 0xFFFF)
        return struct.pack(">HHB", len(msg), len(data), _u8("status", self.status)) + msg + data

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        r = _Reader(raw)
        msg_len, data_len = r.u16(), r.u16()
        status = r.u8()
        msg, data = r.take(msg_len), r.take(data_len)
        r.finish()
        return cls(status, msg, data)


# --- request builders (the roadmap rows) -----------------------------------------------------


def authenticate_start(
    user: str | bytes,
    port: str | bytes,
    rem_addr: str | bytes = b"",
    *,
    action: int = AuthenAction.LOGIN,
    authen_type: int = AuthenType.ASCII,
    service: int = AuthenService.LOGIN,
    priv_lvl: int = 1,
    data: bytes = b"",
) -> AuthenStart:
    """Build the authentication START body of RFC 8907 sec. 5.1; ``encode()`` puts it on the wire."""
    return AuthenStart(
        int(action), priv_lvl, int(authen_type), int(service), _text(user), _text(port),
        _text(rem_addr), data,
    )  # fmt: skip


def authorize_command(
    user: str | bytes,
    cmd: str | bytes,
    args: Sequence[str | bytes] = (),
    *,
    port: str | bytes = b"",
    rem_addr: str | bytes = b"",
    priv_lvl: int = 1,
    authen_method: int = AuthenMethod.TACACSPLUS,
    authen_type: int = AuthenType.ASCII,
    authen_service: int = AuthenService.LOGIN,
) -> AuthorRequest:
    """Build a command-based shell authorization REQUEST (RFC 8907 sec. 6.1 and 8.2).

    The arguments are ``service=shell``, ``cmd=<cmd>`` and one ``cmd-arg=`` per element of
    ``args``, in order, since cmd-arg is order dependent (sec. 8.2).
    """
    pairs = [b"service=shell", b"cmd=" + _text(cmd)]
    pairs += [b"cmd-arg=" + _text(a) for a in args]
    return AuthorRequest(
        int(authen_method), priv_lvl, int(authen_type), int(authen_service),
        _text(user), _text(port), _text(rem_addr), tuple(pairs),
    )  # fmt: skip


def account_command(
    user: str | bytes,
    cmd: str | bytes,
    task_id: int | str,
    *,
    flags: int = AcctFlag.START,
    args: Sequence[str | bytes] = (),
    port: str | bytes = b"",
    rem_addr: str | bytes = b"",
    priv_lvl: int = 1,
    authen_method: int = AuthenMethod.TACACSPLUS,
    authen_type: int = AuthenType.ASCII,
    authen_service: int = AuthenService.LOGIN,
) -> AcctRequest:
    """Build a command accounting REQUEST (RFC 8907 sec. 7.1 and 8.3).

    ``task_id`` comes first because sec. 8.3 says accounting arguments MUST precede the
    authorization ones; ``service=shell`` and ``cmd`` follow, then each ``cmd-arg``.
    """
    pairs = [b"task_id=" + _text(str(task_id)), b"service=shell", b"cmd=" + _text(cmd)]
    pairs += [b"cmd-arg=" + _text(a) for a in args]
    return AcctRequest(
        int(flags), int(authen_method), priv_lvl, int(authen_type), int(authen_service),
        _text(user), _text(port), _text(rem_addr), tuple(pairs),
    )  # fmt: skip
