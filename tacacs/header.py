"""TACACS+ header, flags, session and length discipline (RFC 8907 sec. 4.1).

The codec decodes and encodes the 12-octet header. Policy (refusing the unencrypted flag
outside RFC 9887, who may send which sequence number) lives in ``check_header`` and in the
callers, never in ``decode_header``, so a server can still read a bad packet in order to
answer it with an error packet.
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass
from enum import IntEnum

__all__ = [
    "DEFAULT_MAX_LENGTH",
    "FLAG_SINGLE_CONNECT",
    "FLAG_UNENCRYPTED",
    "HEADER_LENGTH",
    "MAJOR_VERSION",
    "MINOR_VERSION_DEFAULT",
    "MINOR_VERSION_ONE",
    "Header",
    "HeaderError",
    "PacketType",
    "check_header",
    "decode_header",
    "encode_header",
    "new_session_id",
]

HEADER_LENGTH = 12
MAJOR_VERSION = 0xC  # TAC_PLUS_MAJOR_VER, RFC 8907 sec. 4.1
MINOR_VERSION_DEFAULT = 0x0
MINOR_VERSION_ONE = 0x1
FLAG_UNENCRYPTED = 0x01  # TAC_PLUS_UNENCRYPTED_FLAG
FLAG_SINGLE_CONNECT = 0x04  # TAC_PLUS_SINGLE_CONNECT_FLAG
_DEFINED_FLAGS = FLAG_UNENCRYPTED | FLAG_SINGLE_CONNECT
_FORMAT = ">BBBBII"
# RFC 8907 sec. 4.1: "The recommended maximum packet size is 2^(16)."
DEFAULT_MAX_LENGTH = 1 << 16


class HeaderError(ValueError):
    """A header that cannot be decoded, encoded or accepted."""


class PacketType(IntEnum):
    AUTHEN = 0x01
    AUTHOR = 0x02
    ACCT = 0x03


@dataclass(frozen=True)
class Header:
    """The twelve header octets. ``type`` is the raw octet when it is not a known PacketType."""

    major: int
    minor: int
    type: int
    seq_no: int
    flags: int
    session_id: int
    length: int

    @property
    def version_byte(self) -> int:
        return (self.major << 4) | self.minor

    @property
    def unencrypted(self) -> bool:
        return bool(self.flags & FLAG_UNENCRYPTED)

    @property
    def single_connect(self) -> bool:
        return bool(self.flags & FLAG_SINGLE_CONNECT)


def new_session_id() -> int:
    """A session id from a cryptographically strong source (RFC 8907 sec. 4.1, RFC 4086)."""
    return secrets.randbits(32)


def decode_header(raw: bytes) -> Header:
    """Decode the 12-octet header of RFC 8907 sec. 4.1; bytes after the twelfth are ignored.

    Unknown flag bits are read and ignored, as the section requires; they do not appear in
    the result. An unknown packet type or version is not an error here, see ``check_header``.
    """
    if len(raw) < HEADER_LENGTH:
        raise HeaderError(f"header needs {HEADER_LENGTH} octets, got {len(raw)}")
    version, ptype, seq_no, flags, session_id, length = struct.unpack_from(_FORMAT, raw)
    kind: int
    try:
        kind = PacketType(ptype)
    except ValueError:
        kind = ptype
    return Header(
        major=version >> 4,
        minor=version & 0x0F,
        type=kind,
        seq_no=seq_no,
        flags=flags & _DEFINED_FLAGS,
        session_id=session_id,
        length=length,
    )


def encode_header(header: Header) -> bytes:
    """Encode a header to exactly 12 octets (RFC 8907 sec. 4.1); only the defined flags are written."""
    for name, value, limit in (
        ("major", header.major, 0x0F),
        ("minor", header.minor, 0x0F),
        ("type", header.type, 0xFF),
        ("seq_no", header.seq_no, 0xFF),
        ("flags", header.flags, 0xFF),
        ("session_id", header.session_id, 0xFFFFFFFF),
        ("length", header.length, 0xFFFFFFFF),
    ):
        if not 0 <= value <= limit:
            raise HeaderError(f"{name} {value} does not fit its field")
    return struct.pack(
        _FORMAT,
        header.version_byte,
        int(header.type),
        header.seq_no,
        header.flags & _DEFINED_FLAGS,
        header.session_id,
        header.length,
    )


def check_header(
    header: Header, *, from_client: bool, max_length: int = DEFAULT_MAX_LENGTH
) -> None:
    """Refuse a header that RFC 8907 sec. 4.1 does not allow; raise HeaderError.

    Checks the major version, the minor version (0 or 1), the packet type, the sequence
    number (never zero; clients send odd, servers even) and the length against
    ``max_length``, which the section says an implementation MUST let the operator control.
    The unencrypted flag is not judged here: RFC 9887 sec. 4 requires it over TLS.
    """
    if header.major != MAJOR_VERSION:
        raise HeaderError(f"unsupported major version {header.major:#x}")
    if header.minor not in (MINOR_VERSION_DEFAULT, MINOR_VERSION_ONE):
        raise HeaderError(f"unsupported minor version {header.minor}")
    if not isinstance(header.type, PacketType):
        raise HeaderError(f"unknown packet type {header.type:#x}")
    if header.seq_no == 0:
        raise HeaderError("sequence number 0 is not valid")
    if (header.seq_no % 2 == 1) != from_client:
        who = "client" if from_client else "server"
        raise HeaderError(f"sequence number {header.seq_no} is the wrong parity for a {who}")
    if header.length > max_length:
        raise HeaderError(f"body length {header.length} exceeds the limit {max_length}")
