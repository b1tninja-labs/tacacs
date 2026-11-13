"""Generate the obfuscation pad vector used by tests/test_obfuscation.py.

Independent of the tacacs package on purpose: it re-derives RFC 8907 sec. 4.5 with hashlib.
The vector is self-generated, not a vendor capture (the RFC has no packet vector); cross-check
it once against tac_plus or tac_plus-ng and record the run in docs/ when a binary is at hand.
"""

import hashlib
import struct

session_id, key, version, seq_no, length = 0x0BADCAFE, b"tac_plus_key", 0xC0, 1, 40
prefix = struct.pack(">I", session_id) + key + bytes([version, seq_no])
md5_1 = hashlib.md5(prefix, usedforsecurity=False).digest()
md5_2 = hashlib.md5(prefix + md5_1, usedforsecurity=False).digest()
md5_3 = hashlib.md5(prefix + md5_2, usedforsecurity=False).digest()
print((md5_1 + md5_2 + md5_3)[:length].hex())
