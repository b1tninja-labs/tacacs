# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 8907 | Informational; updated by RFC 9887; 1 verified erratum (7754) | 2020-09 | 2026-11-13 |
| RFC 9887 | Proposed Standard; updates RFC 8907 | 2025-12 | 2026-11-13 |
| RFC 9950 | Proposed Standard; obsoletes RFC 9105 | 2026-03 | 2026-11-13 |
| RFC 1321 | Informational (MD5, the obfuscation hash); updated by RFC 6151; 5 verified errata | 1992-04 | 2026-11-13 (info only) |
| RFC 4086 | BCP 106 (randomness, session_id); 3 verified errata | 2005-06 | 2026-11-13 (info only) |
| RFC 8446 | Proposed Standard (TLS 1.3); **obsoleted by RFC 9846** per rfclib, though RFC 9887 cites it | 2018-08 | 2026-11-13 (info only) |
| RFC 1492 | Informational (describes the original TACACS, not a standard; never marked Historic) | 1993-07 | 2026-11-13 |

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
