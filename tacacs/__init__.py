"""tacacs -- TACACS+ authentication, authorization and accounting.

Every switch and router in a network operates area runs TACACS+ for device administration,
and Python has no client and no server.
"""

from __future__ import annotations

from . import apps, body, cli, client, header, model, obfuscation, server, tls
from .body import account_command, authenticate_start, authorize_command
from .client import login
from .header import decode_header, encode_header
from .obfuscation import deobfuscate, obfuscate
from .server import serve
from .tls import connect_tls

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "account_command",
    "apps",
    "authenticate_start",
    "authorize_command",
    "body",
    "cli",
    "client",
    "connect_tls",
    "decode_header",
    "deobfuscate",
    "encode_header",
    "header",
    "login",
    "model",
    "obfuscate",
    "obfuscation",
    "serve",
    "server",
    "tls",
]
