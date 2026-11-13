"""PAD based body obfuscation (RFC 8907 sec. 4.5).

Over TLS the obfuscation is obsolete: RFC 9887 sec. 4 says peers MUST NOT use it and the
unencrypted flag is set on every packet. Both functions therefore refuse a header whose
unencrypted flag is set. The secret is never included in an error message.
"""

from __future__ import annotations

import hashlib
import struct

from .header import DEFAULT_MAX_LENGTH, Header

__all__ = [
    "ObfuscationError",
    "deobfuscate",
    "obfuscate",
    "pseudo_pad",
]


class ObfuscationError(ValueError):
    """The obfuscation was refused: empty secret, cleartext flag, or an oversize body."""


def _md5(data: bytes) -> bytes:
    # MD5 is the algorithm RFC 8907 sec. 4.5 names (RFC 1321); this is not a security use.
    return hashlib.md5(data, usedforsecurity=False).digest()


def pseudo_pad(session_id: int, key: bytes, version: int, seq_no: int, length: int) -> bytes:
    """The pad of RFC 8907 sec. 4.5: MD5_1 || MD5_2 ... truncated to ``length`` octets.

    MD5_1 = MD5(session_id, key, version, seq_no); MD5_n appends MD5_(n-1) to that input.
    """
    if not key:
        raise ObfuscationError("the shared secret must not be empty")
    if length > DEFAULT_MAX_LENGTH:
        raise ObfuscationError(f"refusing to build a pad of {length} octets")
    prefix = struct.pack(">I", session_id) + key + bytes([version, seq_no])
    pad = b""
    block = b""
    while len(pad) < length:
        block = _md5(prefix + block)
        pad += block
    return pad[:length]


def _xor(body: bytes, header: Header, key: bytes) -> bytes:
    if header.unencrypted:
        raise ObfuscationError("the unencrypted flag is set: the body is not obfuscated")
    if not key:
        raise ObfuscationError("the shared secret must not be empty")
    if not body:
        return b""
    pad = pseudo_pad(header.session_id, key, header.version_byte, header.seq_no, len(body))
    return bytes(a ^ b for a, b in zip(body, pad, strict=True))


def obfuscate(body: bytes, header: Header, key: bytes) -> bytes:
    """XOR ``body`` with the pad for ``header`` (RFC 8907 sec. 4.5, RFC 9887 sec. 4).

    Refused when the header carries the unencrypted flag, which is also the TLS case.
    """
    return _xor(body, header, key)


def deobfuscate(body: bytes, header: Header, key: bytes) -> bytes:
    """Reverse ``obfuscate``; the same XOR, named separately (RFC 8907 sec. 4.5, RFC 9887 sec. 4).

    The caller must still sum the field lengths against ``header.length`` (sec. 4.5): a
    wrong secret shows up there, which the ``body`` decoders enforce.
    """
    return _xor(body, header, key)
