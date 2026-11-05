"""TACACS+ header, flags, session and length discipline (RFC 8907).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Header = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "decode_header",
    "encode_header",
]


def decode_header(raw: bytes) -> Header:
    """Pending behaviour defined by RFC 8907.

    Not implemented yet. See the ``header.decode_header()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_header() is not implemented: RFC 8907")


def encode_header(header: Header) -> bytes:
    """Pending behaviour defined by RFC 8907.

    Not implemented yet. See the ``header.encode_header()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode_header() is not implemented: RFC 8907")
