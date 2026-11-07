# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation tacacs could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `header.decode_header()` | RFC 8907 sec. 4.1 | `[ ]` | `tests/test_obligations.py::test_decode_header` (to be written) | M1 |
| `header.encode_header()` | RFC 8907 sec. 4.1 | `[ ]` | `tests/test_obligations.py::test_encode_header` (to be written) | M1 |
| `obfuscation.obfuscate()` | RFC 8907 sec. 4.5, RFC 9887 sec. 4 | `[ ]` | `tests/test_obligations.py::test_obfuscate` (to be written) | M1 |
| `obfuscation.deobfuscate()` | RFC 8907 sec. 4.5, RFC 9887 sec. 4 | `[ ]` | `tests/test_obligations.py::test_deobfuscate` (to be written) | M1 |
| `body.authenticate_start()` | RFC 8907 sec. 5.1 | `[ ]` | `tests/test_obligations.py::test_authenticate_start` (to be written) | M1 |
| `body.authorize_command()` | RFC 8907 sec. 6.1 | `[ ]` | `tests/test_obligations.py::test_authorize_command` (to be written) | M1 |
| `body.account_command()` | RFC 8907 sec. 7.1 | `[ ]` | `tests/test_obligations.py::test_account_command` (to be written) | M1 |
| `client.login()` | RFC 8907 | `[ ]` | `tests/test_obligations.py::test_login` (to be written) | M2 |
| `server.serve()` | RFC 8907 | `[ ]` | `tests/test_obligations.py::test_serve` (to be written) | M3 |
| `tls.connect_tls()` | RFC 9887 sec. 3 | `[ ]` | `tests/test_obligations.py::test_connect_tls` (to be written) | M4 |

## 2. Milestones

- M1 header, obfuscation and body codec with captured vendor traffic as vectors
- M2 client: authentication, then authorization and accounting
- M3 server with pluggable policy for tests
- M4 RFC 9887 TLS transport
- M5 RFC 9950 aligned configuration surface
- M6 publication: 0.1.0 with hardware interop notes

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 8907 is Informational: it documents what vendors ship, and the deviations are real. Interoperability tests must be against hardware, not only against this specification.
- RFC 8907 verified erratum 7754 (Technical), sec. 5.1, 5.3 and 6.1: rem_addr_len is the length of the rem_addr field, not the port field, and in sec. 5.3 user_msg_len is the length of user_msg. Write the length checks against the corrected text.
- RFC 9887 updates RFC 8907, and its sec. 4 obsoletes the sec. 4.5 obfuscation for TLS: peers MUST NOT obfuscate over TLS, a client MUST set TAC_PLUS_UNENCRYPTED_FLAG on every packet, and a packet without it ends the session.
- RFC 9887 and RFC 9950 (which obsoletes RFC 9105) have no errata on file as of the 2026-10-29 errata feed (rfclib, read 2026-11-06): implementations, not errata, are the open question. Re-check at the M1 freeze.
- pytacs exists on PyPI (2025.11.27) but its scope was not established during this survey. Verify it before assuming the field is empty.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| RADIUS, which pyrad covers | `[no]` | a named document requires it |
| an AAA policy engine: decisions are the operator's, this carries them | `[no]` | a named document requires it |
| the historic RFC 1492 protocol | `[no]` | a named document requires it |

## 5. Open questions

- verify the scope of pytacs before assuming the field is empty
- which vendor deviations become conformance fixtures
- M5 names an RFC 9950 configuration surface, but no api row sits on it (the model module has none): add a row, or drop the rung

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
