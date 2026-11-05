"""the asyncio client with reconnect and timeout policy.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    AuthResult = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "login",
]


async def login(server: str, secret: bytes, user: str) -> AuthResult:
    """Pending behaviour defined by RFC 8907.

    Not implemented yet. See the ``client.login()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("login() is not implemented: RFC 8907")
