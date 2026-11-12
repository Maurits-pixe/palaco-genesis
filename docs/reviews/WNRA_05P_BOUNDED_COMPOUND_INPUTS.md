# WNRA-05P — bounded raw requests and compound negative fixtures

**Status:** DRAFT TEST CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.

Parent WNRA-05O DRAFT PR #317, base commit `b6dbed95af1c6c3bfd5a72e79655754d3e973999`. This test-only change adds matching Python and Node input guards before UTF-8 decoding: `MAX_TEST_REQUEST_BYTES = 64 * 1024` and local `REQUEST_TOO_LARGE` rejection. It also rejects integer tokens longer than 16 decimal digits before unbounded Python `int` or JavaScript `BigInt` conversion. The 16-digit limit is strictly a preflight optimization; 16-digit numbers outside ±(2^53−1) remain rejected after numeric comparison.

## New fixtures and expected outcomes

- A **64 KiB exactly** canonical JSON test request should parse in each test parser; its only Node result remains `DENY` / `NOT_EXECUTED`.
- A **64 KiB + 1 byte** request, even when accompanied by a UTF-8 BOM or malformed UTF-8, is denied as `REQUEST_TOO_LARGE` by both parsers.
- 5,000-digit positive and negative decimal integers are rejected as `UNSAFE_INTEGER` before conversion.
- Combined negative cases include BOM plus negative zero; invalid UTF-8 plus negative zero; duplicate `sequence` plus an unsafe integer; nested duplicate JSON plus long unsafe numeric token. Both parsers must reject; diagnostic codes may differ for compounded cases where parser precedence differs.
- The previous 17 shared-deny fixtures, 14 numeric boundary fixtures, 20 adversarial numeric fixtures, three canonical vectors and Node raw-byte tests must remain passing.

## Critical scope limits

64 KiB is a **local fixture-profile cap**, not a PALACO canonical wire protocol size or universal memory bound. Only maximum *input length* is bounded; this does not establish constant memory use, hard CPU budgets, process isolation, DOS resistance or a trustworthy production admission service. The Node subprocess in the test harness has a 45-second timeout but this is not a production runtime deadline. Exact-head native Windows CI is required for a PASS claim.

TRIAS: test-only with no authority promotion. ORACLE: separate prior evidence from exact-new-head test logs and report failures honestly. MENTOR: avoid promising general parser completeness or zero resource exhaustion.

**No merge, release, issuance, activation, enrollment or GO-13 change.**