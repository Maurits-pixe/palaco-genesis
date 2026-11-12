# WNRA-05M — Numeric boundary regression candidate

**Scope:** local Python/Node simulated anchor fixtures only; no production contract, no independent custodian or signing authority.

Parent: WNRA-05L DRAFT PR #314 at `ba3f5f583796658d11c42e25f76efa09c4979565`. The pre-existing 17-case negative corpus remains intact.

The WNRA-05M test method in `test_windows_anchor_error_codes.py` adds 14 cases: `-0`, `0`, `-1`, `1`, `2`, `9007199254740990`, `9007199254740991`, `9007199254740992`, `9007199254740993`, `-9007199254740992`, `1.0`, `1e0`, `true`, `null`.

The Python and Node parsers are executed against identical raw JSON bytes. For invalid numeric values, exact expected local diagnostic codes are asserted. For safe positive integer values, both parsers are expected to parse into a **DENY-only** test fixture; this is not admission, verification or authority. A Node subprocess returning anything but `DENY`/`NOT_EXECUTED` must fail.

Expected tests must execute on native Windows via the already-watched `test_windows_anchor_error_codes.py` path in `.github/workflows/orcheastra-windows-metadata.yml`. New SHA-specific CI evidence is required before calling this PASS. If Windows CI is absent, failed, or stale, status is NOT VERIFIED.

**AI TRIAS:** no runtime or protocol promotion; GO-13 HOLD / AUTHORIZATION DENY. **AI ORACLE:** exact test results must come from new Windows logs; previous run cannot verify this change. **AI MENTOR:** favor limited numerical boundaries over broad error-code renaming; follow-up for lexical precision only with separate review.

No merge, release, issuance, or activation is authorized.
