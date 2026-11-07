"""PAD based body obfuscation and the version quirks around it (RFC 8907).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "deobfuscate",
    "obfuscate",
]


def obfuscate(body: bytes, key: bytes, session_id: bytes) -> bytes:
    """Pending behaviour defined by RFC 8907 sec. 4.5, RFC 9887 sec. 4.

    Not implemented yet. See the ``obfuscation.obfuscate()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("obfuscate() is not implemented: RFC 8907 sec. 4.5, RFC 9887 sec. 4")


def deobfuscate(body: bytes, key: bytes, session_id: bytes) -> bytes:
    """Pending behaviour defined by RFC 8907 sec. 4.5, RFC 9887 sec. 4.

    Not implemented yet. See the ``obfuscation.deobfuscate()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError(
        "deobfuscate() is not implemented: RFC 8907 sec. 4.5, RFC 9887 sec. 4"
    )
