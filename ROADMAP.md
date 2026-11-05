# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation tacacs could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `header.decode_header()` | RFC 8907 | `[ ]` | `tests/test_obligations.py::decode_header` |
| `header.encode_header()` | RFC 8907 | `[ ]` | `tests/test_obligations.py::encode_header` |
| `obfuscation.obfuscate()` | RFC 8907 | `[ ]` | `tests/test_obligations.py::obfuscate` |
| `obfuscation.deobfuscate()` | RFC 8907 | `[ ]` | `tests/test_obligations.py::deobfuscate` |
| `body.authenticate_start()` | RFC 8907 | `[ ]` | `tests/test_obligations.py::authenticate_start` |
| `body.authorize_command()` | RFC 8907 | `[ ]` | `tests/test_obligations.py::authorize_command` |
| `body.account_command()` | RFC 8907 | `[ ]` | `tests/test_obligations.py::account_command` |
| `client.login()` | RFC 8907 | `[ ]` | `tests/test_obligations.py::login` |
| `server.serve()` | RFC 8907 | `[ ]` | `tests/test_obligations.py::serve` |
| `tls.connect_tls()` | RFC 9887 | `[ ]` | `tests/test_obligations.py::connect_tls` |

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
- RFC 9887 and RFC 9950 are recent enough that implementations, not errata, are the open question: re-check both before M1.
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

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
