# WNRA-05Q — bounded workload observations

**Status:** DRAFT TEST CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.

Parent WNRA-05P DRAFT PR #318, exact base SHA `5d8ef31603abf757cd24e86c6134fe3d7c65aa09`. No production parser changes or protocol canon changes.

The cross-runtime Python/Node test `BoundedWorkloadObservations.test_cross_runtime_bounded_repeated_workloads` performs nine workloads: canonical fixture, exactly 64 KiB canonical fixture, 64 KiB+1 rejection, UTF-8 BOM plus negative-zero, 5,000-digit integer, 2 MiB raw bytes, 8 MiB raw bytes, 2 MiB plus invalid UTF-8, and oversize malformed nested JSON. The first five are repeated 16 times each; the four larger cases run once. Total: **84 parser attempts per runtime**, all pinned to local DENY-only or rejection outcomes. The cases are generated independently in Python and Node from the same short descriptors, avoiding huge JSON IPC payloads.

Node executes in a subprocess with a **25-second test timeout**. Python execution duration and Node internal duration are logged for diagnostic observation, without asserting a performance service level. A successfully parsed canonical fixture is still only `DENY_ONLY` with no authority. A 64 KiB+1 request and the multi-MB requests must produce `REQUEST_TOO_LARGE` before decoding. This is a deterministic regression workload, **not** a memory usage bound, a CPU quota, a denial-of-service certification, or evidence of arbitrary JSON parser equivalence.

Exact-head native Windows CI must show the nine `WNRA05Q_CASE` lines, the Python unittest `... ok`, and the preceding WNRA-05H/05M/05O/05P regressions passing. Prior run evidence remains tied to PR #318 and cannot be substituted for WNRA-05Q CI.

**TRIAS:** test-only, no authorization or release. **ORACLE:** record only observed exact-commit Windows outcomes. **MENTOR:** consider process isolation / real resource measurement separately, not as silently implied by this test harness.

**No merge, deployment, issuance, signing, enrollment, or GO-13 transition.**