# tacacs

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

tacacs -- TACACS+ authentication, authorization and accounting

Every switch and router in a network operates area runs TACACS+ for device administration, and Python has no client and no server. What is more, the protocol is being actively standardised right now: RFC 9887 (2025-12) defines TACACS+ over TLS 1.3, replacing the plaintext transport with an authenticated one, and RFC 9950 (2026-03) adds a YANG data model. Both are younger than most feature branches, and neither has an implementation anywhere outside vendor firmware. The name is free: tacacs and rfc8907 are absent from PyPI as of 2026-11-05.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| pyrad | 2.6.0 | 2026-10-18 | RADIUS, a different protocol with a different job |
| tacacs, rfc8907 | - | - | absent from PyPI (2026-11-05) |
| vendor SDKs | - | - | none: network gear is a client of the protocol, not a Python library |

What this project intends to add:

- a real client for automation: login, authorize a command, and account for what ran
- a server usable in tests, so a network team can assert on authorization decisions
- the PAD obfuscation layer done correctly, since it is the part every home-grown parser gets wrong
- the RFC 9887 TLS transport with the right identity and negotiation rules
- a configuration shape that mirrors the RFC 9950 YANG model instead of inventing one

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 8907 | Informational | 2020-09 | the protocol as deployed: header, authentication, authorization, accounting |
| RFC 9887 | Proposed Standard | 2025-12 | TACACS+ over TLS 1.3, the transport that fixes the plaintext problem |
| RFC 9950 | Proposed Standard | 2026-03 | YANG data model for configuration and state |
| RFC 1492 | Informational (Historic) | 1993-07 | the original TACACS, named only so nobody confuses the three |

### Errata watch

- RFC 8907 is Informational: it documents what vendors ship, and the deviations are real. Interoperability tests must be against hardware, not only against this specification.
- RFC 8907 verified erratum 7754 (Technical), sec. 5.1, 5.3 and 6.1: rem_addr_len is the length of the rem_addr field, not the port field, and in sec. 5.3 user_msg_len is the length of user_msg. Write the length checks against the corrected text.
- RFC 9887 updates RFC 8907, and its sec. 4 obsoletes the sec. 4.5 obfuscation for TLS: peers MUST NOT obfuscate over TLS, a client MUST set TAC_PLUS_UNENCRYPTED_FLAG on every packet, and a packet without it ends the session.
- RFC 9887 and RFC 9950 (which obsoletes RFC 9105) have no errata on file as of the 2026-10-29 errata feed (rfclib, read 2026-11-06): implementations, not errata, are the open question. Re-check at the M1 freeze.
- pytacs exists on PyPI (2025.11.27) but its scope was not established during this survey. Verify it before assuming the field is empty.

## Module layout

| Module | Responsibility |
|---|---|
| `header` | TACACS+ header, flags, session and length discipline (RFC 8907) |
| `obfuscation` | PAD based body obfuscation and the version quirks around it (RFC 8907) |
| `body` | authentication, authorization and accounting bodies (RFC 8907) |
| `client` | the asyncio client with reconnect and timeout policy |
| `server` | the server with pluggable identity and policy backends |
| `tls` | the TLS 1.3 transport (RFC 9887) |
| `model` | configuration and state mirroring the data model (RFC 9950) |

## What it does not do

- RADIUS, which pyrad covers
- an AAA policy engine: decisions are the operator's, this carries them
- the historic RFC 1492 protocol


## Install

```bash
git clone https://github.com/b1tninja/tacacs.git
cd tacacs
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy tacacs
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
