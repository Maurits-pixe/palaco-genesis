# WNRA-05R — subprocess isolation and bounded observation

**Status:** DRAFT TEST CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.

Parent WNRA-05Q PR #319 at `6cab97267b9fa400e2454b34261a96c5d12c2444`. This change is restricted to Windows regression tests and the GitHub Actions workflow. It does **not** change runtime parsers, identity, authorization, admission, release or protocol canon.

## Added tests

- `verification/provenance/test_windows_anchor_process_isolation.py`: run Python and Node local parsers in independent subprocesses. Each child checks a canonical fixture (`DENY_ONLY`) and oversized input (`REQUEST_TOO_LARGE`), and must report `authorization=DENY`, `independent_verification=NOT_EXECUTED`.
- Python worker reports `tracemalloc` **peak Python-tracked allocations**. Node worker reports one `process.memoryUsage().rss` **resident-memory snapshot**. These numbers use different methods, are not peak RSS parity and **must not be compared as equivalent metrics**.
- Stall/termination tests launch deliberately idle Python and Node children, assert their subprocess timeout, kill/reap them, and assert a nonzero exit. This verifies only a controlled local test-harness interruption, **not** security sandboxing or OS-level resource quotas.
- The subprocess functional tests use a 12-second Python harness timeout, idle-child probes use 0.3-second timeout and 5-second cleanup, and Windows CI runs with the existing workflow job-wide timeout.

## Evidence and limitations

A child process being separate does not imply a restricted token, Windows Job Object, containment against descendants, CPU/memory governance, or production isolation. No enforceable RSS cap or memory quota is configured. This candidate only records instrumentation and tests forced interruption. Any production sandbox requires a separate architecture review and privileged Windows implementation, not a test-only script.

The Windows workflow now watches and executes the new file. PASS requires exact-head native Windows logs including `WNRA05R_MEMORY`, both `WNRA05R_TIMEOUT` records, prior fixture suites and completed CI jobs. No merge, issuance, activation, or GO-13 transition.

**TRIAS:** deny and governance unchanged. **ORACLE:** exact-head Windows evidence required; do not extrapolate from prior SHA. **MENTOR:** treat tracked-heap and RSS separately, then review Windows Job Objects and OS policy in an independent future design candidate.
