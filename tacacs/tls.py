"""the TLS 1.3 transport (RFC 9887).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Connection = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "connect_tls",
]


async def connect_tls(server: str, context: ssl.SSLContext) -> Connection:
    """Pending behaviour defined by RFC 9887.

    Not implemented yet. See the ``tls.connect_tls()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("connect_tls() is not implemented: RFC 9887")
