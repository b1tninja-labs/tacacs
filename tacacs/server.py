"""A TACACS+ server with a shared secret per client and pluggable policy (RFC 8907).

This is a test-fixture server, not production AAA: it speaks the obfuscated TCP form (RFC 8907
sec. 4.5) with one secret per client address, follows the session rules of ``session`` and
answers through a ``Policy``. It refuses the unencrypted flag (sec. 4.1: MUST NOT be used in
production) unless the operator allows it. ``serve`` and ``start_server`` take an optional
``ssl.SSLContext`` for TACACS+ over TLS 1.3 (RFC 9887): the same session rules, no obfuscation and
no per-client secret, and every packet must carry the unencrypted flag (sec. 4).

``SecretStore`` carries the sec. 10.5.1 requirements that concern a server: a dedicated secret may
be defined for each client, secrets never appear in ``repr`` or in the warnings, the server can
warn when secrets are shared between clients or shorter than 16 characters, and secrets of at
least 32 characters are accepted.
"""

# ruff: noqa: ARG002 - the Policy interface passes the client to every hook, a fixture ignores it

from __future__ import annotations

import asyncio
import ipaddress
import logging
import ssl
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field

from . import header as hdr
from .body import (
    AcctReply,
    AcctRequest,
    AcctStatus,
    AuthenContinue,
    AuthenReply,
    AuthenStart,
    AuthenStatus,
    AuthorReply,
    AuthorRequest,
    AuthorStatus,
    BodyError,
)
from .header import FLAG_SINGLE_CONNECT, FLAG_UNENCRYPTED, Header, HeaderError, PacketType
from .obfuscation import ObfuscationError, deobfuscate, obfuscate
from .session import Connection, ReplyKind, SessionError, classify_reply

__all__ = [
    "MIN_SECRET_LENGTH",
    "Policy",
    "SecretStore",
    "StaticPolicy",
    "handle_connection",
    "serve",
    "start_server",
]

log = logging.getLogger(__name__)

MIN_SECRET_LENGTH = 16
"""RFC 8907 sec. 10.5.1: administrators SHOULD configure at least 16 characters."""

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class SecretStore:
    """Shared secrets by client address or network (RFC 8907 sec. 4.5, 10.5.1).

    A client is an address or a CIDR network; the most specific match wins, and an address with no
    match has no secret, so the server cannot talk to it at all (there is no default secret). The
    secret is never shown: ``repr`` and ``warnings`` name clients, not secrets.
    """

    def __init__(self, secrets: Mapping[str, bytes] | None = None) -> None:
        self._secrets: dict[Network, bytes] = {}
        for client, secret in (secrets or {}).items():
            self.add(client, secret)

    def __repr__(self) -> str:
        return f"SecretStore(clients={[str(n) for n in self._secrets]})"

    def add(self, client: str, secret: bytes) -> None:
        if not isinstance(secret, bytes | bytearray) or not secret:
            raise ValueError("a shared secret must be non-empty bytes")
        self._secrets[ipaddress.ip_network(client, strict=False)] = bytes(secret)

    def lookup(self, address: str | Address) -> bytes | None:
        """The secret of the most specific network containing ``address``, or ``None``."""
        ip = ipaddress.ip_address(address)
        best: tuple[int, bytes] | None = None
        for network, secret in self._secrets.items():
            if ip.version != network.version or ip not in network:
                continue
            if best is None or network.prefixlen > best[0]:
                best = (network.prefixlen, secret)
        return best[1] if best else None

    def warnings(self) -> list[str]:
        """Sec. 10.5.1 SHOULDs: secrets shared by several clients, and secrets under 16 characters."""
        out = []
        by_secret: dict[bytes, list[str]] = {}
        for network, secret in self._secrets.items():
            by_secret.setdefault(secret, []).append(str(network))
            if len(secret) < MIN_SECRET_LENGTH:
                out.append(
                    f"the secret for {network} is shorter than {MIN_SECRET_LENGTH} characters"
                )
        out += [
            "clients share one secret: " + ", ".join(sorted(clients))
            for clients in by_secret.values()
            if len(clients) > 1
        ]
        return out


class Policy(ABC):
    """What the server decides. Subclass it; ``secrets`` says which clients may talk and how."""

    secrets: SecretStore
    allow_single_connect: bool = True
    allow_unencrypted: bool = False

    @abstractmethod
    def authen_start(self, client: str, start: AuthenStart, state: dict) -> AuthenReply:
        """Answer a START. ``state`` is a dict kept for this session's later CONTINUEs."""

    @abstractmethod
    def authen_continue(self, client: str, cont: AuthenContinue, state: dict) -> AuthenReply:
        """Answer a CONTINUE (an abort never reaches here)."""

    @abstractmethod
    def authorize(self, client: str, request: AuthorRequest) -> AuthorReply:
        """Answer an authorization REQUEST."""

    @abstractmethod
    def account(self, client: str, request: AcctRequest) -> AcctReply:
        """Answer an accounting REQUEST whose flags were valid."""


@dataclass
class StaticPolicy(Policy):
    """A fixture policy: ASCII login against a user table, authorize what ``allowed`` lists."""

    secrets: SecretStore
    users: dict[bytes, bytes] = field(default_factory=dict)
    allowed: frozenset[bytes] = frozenset()
    allow_single_connect: bool = True
    allow_unencrypted: bool = False
    accounted: list[AcctRequest] = field(default_factory=list)

    def authen_start(self, client: str, start: AuthenStart, state: dict) -> AuthenReply:
        if start.user:
            state["user"] = start.user
            return AuthenReply(AuthenStatus.GETPASS, flags=1, server_msg=b"Password: ")
        return AuthenReply(AuthenStatus.GETUSER, server_msg=b"Username: ")

    def authen_continue(self, client: str, cont: AuthenContinue, state: dict) -> AuthenReply:
        if "user" not in state:
            state["user"] = cont.user_msg
            return AuthenReply(AuthenStatus.GETPASS, flags=1, server_msg=b"Password: ")
        known = self.users.get(state["user"])
        ok = known is not None and known == cont.user_msg
        return AuthenReply(AuthenStatus.PASS if ok else AuthenStatus.FAIL)

    def authorize(self, client: str, request: AuthorRequest) -> AuthorReply:
        command = next((a[4:] for a in request.args if a.startswith(b"cmd=")), b"")
        if command in self.allowed:
            return AuthorReply(AuthorStatus.PASS_ADD)
        return AuthorReply(AuthorStatus.FAIL, server_msg=b"not permitted")

    def account(self, client: str, request: AcctRequest) -> AcctReply:
        self.accounted.append(request)
        return AcctReply(AcctStatus.SUCCESS)


def _error_reply(packet_type: int) -> tuple[bytes, ReplyKind]:
    if packet_type == PacketType.AUTHEN:
        return AuthenReply(AuthenStatus.ERROR).encode(), ReplyKind.ERROR
    if packet_type == PacketType.AUTHOR:
        return AuthorReply(AuthorStatus.ERROR).encode(), ReplyKind.ERROR
    return AcctReply(AcctStatus.ERROR).encode(), ReplyKind.ERROR


def _answer(
    policy: Policy, client: str, header: Header, body: bytes, state: dict
) -> tuple[bytes, ReplyKind]:
    """Decode ``body`` for ``header``; return the encoded reply body and what it means.

    Raises ``BodyError`` for a malformed body.
    """
    if header.type == PacketType.AUTHEN:
        if header.seq_no == 1:
            reply = policy.authen_start(client, AuthenStart.decode(body), state)
        else:
            cont = AuthenContinue.decode(body)
            if cont.abort:  # sec. 5.4.3: the client ended the session; nothing is owed but a close
                reply = AuthenReply(AuthenStatus.FAIL)
            else:
                reply = policy.authen_continue(client, cont, state)
        return reply.encode(), classify_reply(PacketType.AUTHEN, reply.status)
    if header.type == PacketType.AUTHOR:
        author = policy.authorize(client, AuthorRequest.decode(body))
        return author.encode(), classify_reply(PacketType.AUTHOR, author.status)
    request = AcctRequest.decode(body)
    if not request.flags_valid:  # sec. 7.2 Table 2: a server MUST answer ERROR
        return AcctReply(AcctStatus.ERROR).encode(), ReplyKind.ERROR
    acct = policy.account(client, request)
    return acct.encode(), classify_reply(PacketType.ACCT, acct.status)


async def handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    policy: Policy,
    *,
    tls: bool = False,
) -> None:
    """Serve one connection until the session rules or the peer end it.

    With ``tls`` the stream is already a TLS 1.3 channel (RFC 9887): bodies are never obfuscated,
    the client needs no shared secret, and a packet without the unencrypted flag is answered with
    the ERROR status for its type, flag set, after which the session ends (sec. 4 para 5).
    """
    peer = writer.get_extra_info("peername")
    client = peer[0] if peer else ""
    secret = None if tls else (policy.secrets.lookup(client) if client else None)
    connection = Connection(client=False)
    states: dict[int, dict] = {}
    try:
        if (
            secret is None and not tls
        ):  # no secret, no conversation (sec. 10.5.1: a secret for each client)
            return
        while not connection.must_close:
            header = hdr.decode_header(await reader.readexactly(hdr.HEADER_LENGTH))
            hdr.check_header(header, from_client=True)
            if header.unencrypted and not policy.allow_unencrypted and not tls:
                return
            body = await reader.readexactly(header.length)
            if tls and not header.unencrypted:  # RFC 9887 sec. 4 para 5
                answer, _ = _error_reply(header.type)
                reply = Header(
                    header.major, header.minor, header.type, header.seq_no + 1,
                    FLAG_UNENCRYPTED, header.session_id, len(answer),
                )  # fmt: skip
                writer.write(hdr.encode_header(reply) + answer)
                await writer.drain()
                return
            first = connection.packets == 0
            connection.received(header)
            state = states.setdefault(header.session_id, {})
            broken = False
            try:
                plain = (
                    body
                    if header.unencrypted or secret is None
                    else deobfuscate(body, header, secret)
                )
                answer, kind = _answer(policy, client, header, plain, state)
            except (BodyError, ObfuscationError):
                # A body whose lengths do not add up is what a wrong secret looks like (sec. 4.5).
                (answer, kind), broken = _error_reply(header.type), True
            flags = FLAG_UNENCRYPTED if tls else header.flags & FLAG_UNENCRYPTED
            if first and header.single_connect and policy.allow_single_connect and not broken:
                flags |= FLAG_SINGLE_CONNECT
            reply = Header(
                header.major, header.minor, header.type, header.seq_no + 1, flags,
                header.session_id, len(answer),
            )  # fmt: skip
            connection.sent(reply)
            out = (
                answer if reply.unencrypted or secret is None else obfuscate(answer, reply, secret)
            )
            writer.write(hdr.encode_header(reply) + out)
            await writer.drain()
            if kind is not ReplyKind.MORE:
                connection.complete(header.session_id, kind, connection_error=broken)
                states.pop(header.session_id, None)
    except (asyncio.IncompleteReadError, ConnectionError, HeaderError, SessionError):
        pass  # the peer left, or broke a rule: the connection ends, nothing is answered
    finally:
        writer.close()


async def start_server(
    host: str, port: int, policy: Policy, *, ssl_context: ssl.SSLContext | None = None
) -> asyncio.Server:
    """Start listening and return the ``asyncio.Server``; ``port`` 0 picks a free one.

    With ``ssl_context`` the listener is TACACS+ over TLS (RFC 9887). The context must be TLS 1.3
    only (sec. 3.2: earlier versions MUST NOT be used); anything lower is refused here.
    """
    if ssl_context is not None and (
        ssl_context.minimum_version != ssl.TLSVersion.TLSv1_3
        or ssl_context.maximum_version == ssl.TLSVersion.TLSv1_2
    ):
        raise ValueError("a TACACS+ TLS listener needs minimum_version TLS 1.3 (RFC 9887 sec. 3.2)")
    if ssl_context is None:
        for warning in policy.secrets.warnings():
            log.warning("%s", warning)

    async def on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await handle_connection(reader, writer, policy, tls=ssl_context is not None)

    return await asyncio.start_server(on_connect, host, port, ssl=ssl_context)


async def serve(
    host: str, port: int, policy: Policy, *, ssl_context: ssl.SSLContext | None = None
) -> None:
    """Run a TACACS+ server on ``host``:``port`` until cancelled (RFC 8907 sec. 4).

    Every client needs a secret in ``policy.secrets`` (sec. 4.5, 10.5.1); a connection from an
    address without one is closed unanswered. Sec. 10.5.1 warnings are logged at start. With
    ``ssl_context`` it serves TACACS+ over TLS 1.3 instead (RFC 9887), where no secret is used.
    """
    server = await start_server(host, port, policy, ssl_context=ssl_context)
    async with server:
        await server.serve_forever()
