"""Sessions on a connection: sequence numbers, Single Connection Mode, and session completion.

Pure state, no sockets and no clock (RFC 8907 sec. 4.1, 4.3, 4.4, 5.4.3). A client or server
feeds every header it sends or receives to a ``Connection``; the connection refuses what the RFC
forbids and says whether the TCP connection may carry another session or must close.

Three readings are this module's and are listed in ROADMAP.md as rows:

* RFC 8907 sec. 4.1 says the sequence number "must never wrap, i.e., if the sequence number
  2^(8)-1 is ever reached, that session must terminate and be restarted with a sequence number of
  1". ``Sequencer`` takes "reached" to mean "would have to be sent": the client never sends 255,
  and ``SequenceExhausted`` tells it to end the session and start a new one with a new session id.
* "The client MUST NOT send a second packet on a connection until single-connect status has been
  established" (sec. 4.3) is applied to starting another *session*; a CONTINUE answers a REPLY and
  so cannot precede it.
* Single Connection Mode is established when the client's first packet carries the flag and the
  server's first reply carries it too. A server flag the client never asked for establishes
  nothing here, because the client "may ignore the flag" (sec. 4.3).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .body import AcctStatus, AuthenStatus, AuthorStatus
from .header import Header, PacketType

__all__ = [
    "MAX_SEQ",
    "Connection",
    "ReplyKind",
    "SequenceExhausted",
    "Sequencer",
    "SessionError",
    "classify_reply",
]

MAX_SEQ = 255
"""RFC 8907 sec. 4.1: 2^8-1. It is never sent; reaching it ends the session."""

_COMPLETED_REMEMBERED = 1024
"""How many finished session ids a connection remembers to refuse reuse. A bound, not an RFC number."""


class SessionError(ValueError):
    """A packet that the session or connection rules of RFC 8907 sec. 4 do not allow."""


class SequenceExhausted(SessionError):  # noqa: N818 - states a condition, not a failure
    """The next sequence number would be 255: terminate this session and restart with number 1."""


class ReplyKind(enum.Enum):
    """What a reply status means for the session (RFC 8907 sec. 4.4, 5.4.3, 6.2, 7.2)."""

    PASS = enum.auto()  # processing completed; apply the result
    FAIL = enum.auto()  # processing completed; the answer is no
    ERROR = enum.auto()  # did not complete: behave as if the server could not be reached
    MORE = enum.auto()  # authentication continues: GETDATA, GETUSER or GETPASS
    RESTART = enum.auto()  # authentication restarts with a new START, new session id, seq 1


def classify_reply(packet_type: int, status: int) -> ReplyKind:
    """Map a reply status to what the client must do (RFC 8907 sec. 4.4 and 5.4.3).

    PASS and FAIL complete the session and the client applies the result; ERROR completes it
    without a result and the client "MUST behave as if the server could not be connected to"
    (sec. 4.4 para 3). ``FOLLOW`` is deprecated and is FAIL (sec. 5.4.3 para 3; the authorization
    and accounting FOLLOW defer to it, sec. 6.2 and 7.2). An unknown status is a ``SessionError``
    rather than a guess: nothing in the RFC says what to do with it. RESTART needs a client that
    implements it; one that does not "MUST process the response as if the status was FAIL"
    (sec. 5.4.3 para 6), which is that client's one-line fallback, not this function's.
    """
    try:
        if packet_type == PacketType.AUTHEN:
            authen = AuthenStatus(status)
            return {
                AuthenStatus.PASS: ReplyKind.PASS,
                AuthenStatus.FAIL: ReplyKind.FAIL,
                AuthenStatus.FOLLOW: ReplyKind.FAIL,
                AuthenStatus.ERROR: ReplyKind.ERROR,
                AuthenStatus.RESTART: ReplyKind.RESTART,
                AuthenStatus.GETDATA: ReplyKind.MORE,
                AuthenStatus.GETUSER: ReplyKind.MORE,
                AuthenStatus.GETPASS: ReplyKind.MORE,
            }[authen]
        if packet_type == PacketType.AUTHOR:
            author = AuthorStatus(status)
            return {
                AuthorStatus.PASS_ADD: ReplyKind.PASS,
                AuthorStatus.PASS_REPL: ReplyKind.PASS,
                AuthorStatus.FAIL: ReplyKind.FAIL,
                AuthorStatus.FOLLOW: ReplyKind.FAIL,
                AuthorStatus.ERROR: ReplyKind.ERROR,
            }[author]
        if packet_type == PacketType.ACCT:
            acct = AcctStatus(status)
            return {
                AcctStatus.SUCCESS: ReplyKind.PASS,
                AcctStatus.ERROR: ReplyKind.ERROR,
                AcctStatus.FOLLOW: ReplyKind.ERROR,
            }[acct]
    except ValueError as error:
        raise SessionError(
            f"unknown status {status:#x} for packet type {packet_type:#x}"
        ) from error
    raise SessionError(f"unknown packet type {packet_type:#x}")


@dataclass(slots=True)
class Sequencer:
    """The sequence numbers of one session, seen from one end (RFC 8907 sec. 4.1).

    The first packet of a session has number 1, each following packet one more, clients send odd
    numbers and servers even ones. ``send`` returns the number for the next outgoing packet;
    ``receive`` checks an incoming one against the one expected.
    """

    client: bool
    _last: int = field(default=0, init=False)

    def _next(self) -> int:
        return self._last + 1

    def send(self) -> int:
        number = self._next()
        if self.client != (number % 2 == 1):
            raise SessionError("it is not this end's turn to send")
        if number >= MAX_SEQ:
            raise SequenceExhausted(
                f"sequence number {number} would be sent: end the session and restart at 1"
            )
        self._last = number
        return number

    def receive(self, number: int) -> None:
        expected = self._next()
        if number == MAX_SEQ:
            raise SessionError("sequence number 255 is never valid: the session must restart")
        if number != expected or self.client == (number % 2 == 1):
            raise SessionError(f"expected sequence number {expected}, got {number}")
        self._last = number


@dataclass(slots=True)
class _Session:
    sequencer: Sequencer
    complete: bool = False


class Connection:
    """The sessions on one TCP (or TLS) connection and the Single Connection Mode state.

    Drive it with ``sent`` and ``received`` for every header, each with the packet's ``kind`` once
    a reply has been decoded (``classify_reply``), and read ``single_connect``, ``accepting`` and
    ``must_close``. It holds no timer: closing an idle single-connection socket "after a specific
    period of inactivity" (sec. 4.3 para 7) is the caller's.
    """

    def __init__(self, *, client: bool) -> None:
        self.client = client
        self._sessions: dict[int, _Session] = {}
        self._finished: list[int] = []
        self._first_client_flag: bool | None = None
        self.single_connect: bool | None = None
        """``None`` until the first two packets have been seen, then whether the mode holds."""
        self.accepting = True
        """False once an ERROR due to connection trouble ended new sessions (sec. 4.4 para 6)."""
        self._packets = 0
        self._poisoned = False

    @property
    def packets(self) -> int:
        """How many packets this connection has carried, both directions."""
        return self._packets

    @property
    def active(self) -> int:
        return sum(1 for s in self._sessions.values() if not s.complete)

    @property
    def must_close(self) -> bool:
        """The TCP connection has to be closed now (sec. 4.3 para 6, sec. 4.4 para 6)."""
        if self.active:
            return False
        if self._poisoned:
            return True
        return self._packets >= 2 and self.single_connect is False

    def can_start_session(self) -> bool:
        """Whether a client may start another session on this connection right now."""
        if not self.accepting or self.must_close:
            return False
        if not self._sessions:
            return True
        return self.single_connect is True

    def _session(self, session_id: int, *, creating: bool) -> _Session:
        found = self._sessions.get(session_id)
        if found is not None:
            return found
        if not creating:
            raise SessionError(f"packet for unknown session {session_id:#010x}")
        if session_id in self._finished:
            raise SessionError(f"session id {session_id:#010x} was already used on this connection")
        if not self.accepting:
            raise SessionError("this connection accepts no new sessions (sec. 4.4)")
        if self._sessions and self.single_connect is not True:
            raise SessionError("a second session needs Single Connection Mode (sec. 4.3)")
        session = _Session(Sequencer(client=self.client))
        self._sessions[session_id] = session
        return session

    def _note_flags(self, header: Header, *, from_client: bool) -> None:
        # The flag matters only in the first two packets of the connection (sec. 4.3 para 5).
        if self._packets == 0 and from_client:
            self._first_client_flag = header.single_connect
        elif self._packets == 1 and not from_client:
            self.single_connect = bool(self._first_client_flag and header.single_connect)
        self._packets += 1

    def sent(self, header: Header) -> None:
        """Record a packet this end sends. Raises ``SessionError`` if it may not be sent."""
        session = self._session(header.session_id, creating=self.client and header.seq_no == 1)
        if session.complete:
            raise SessionError("the session is complete")
        number = session.sequencer.send()
        if number != header.seq_no:
            raise SessionError(f"header seq_no {header.seq_no} is not the next number {number}")
        self._note_flags(header, from_client=self.client)

    def received(self, header: Header) -> None:
        """Record a packet from the peer. Raises ``SessionError`` if the peer broke a rule."""
        creating = (not self.client) and header.seq_no == 1
        session = self._session(header.session_id, creating=creating)
        if session.complete:
            raise SessionError("a packet arrived for a completed session")
        session.sequencer.receive(header.seq_no)
        self._note_flags(header, from_client=not self.client)

    def complete(self, session_id: int, kind: ReplyKind, *, connection_error: bool = False) -> None:
        """End a session with the reply kind that ended it (``PASS``, ``FAIL``, ``ERROR``, ``RESTART``).

        ``connection_error`` marks an ERROR caused by the connection itself, for example an
        incorrect secret (sec. 4.4 para 6): then no new session is accepted, sessions already
        established may finish, and ``must_close`` turns true once none is left.
        """
        if kind is ReplyKind.MORE:
            raise SessionError("a reply that asks for more input does not complete a session")
        session = self._session(session_id, creating=False)
        session.complete = True
        self._finished.append(session_id)
        del self._finished[:-_COMPLETED_REMEMBERED]
        if connection_error and self.single_connect:
            self.accepting = False
            self._poisoned = True
        elif connection_error:
            self._poisoned = True
