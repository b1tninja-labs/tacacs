"""authentication, authorization and accounting bodies (RFC 8907).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Packet = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "account_command",
    "authenticate_start",
    "authorize_command",
]


def authenticate_start(user: str, port: str, service: str) -> Packet:
    """Pending behaviour defined by RFC 8907.

    Not implemented yet. See the ``body.authenticate_start()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("authenticate_start() is not implemented: RFC 8907")


def authorize_command(user: str, cmd: str, args: dict) -> Packet:
    """Pending behaviour defined by RFC 8907.

    Not implemented yet. See the ``body.authorize_command()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("authorize_command() is not implemented: RFC 8907")


def account_command(user: str, cmd: str, task_id: int) -> Packet:
    """Pending behaviour defined by RFC 8907.

    Not implemented yet. See the ``body.account_command()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("account_command() is not implemented: RFC 8907")
