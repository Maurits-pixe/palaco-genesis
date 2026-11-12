# WNRA-05W — least-privilege Windows handle transfer and process rights

**Status:** DRAFT TEST CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.

Parent: WNRA-05V PR #324 at head `09b548fe00f853be53591d588a951f53f4d810fb`. Only the already-watched `verification/provenance/test_windows_anchor_suspended_job_launch.py` fixture changes; the native Windows workflow executes that test file without a workflow edit.

## Narrow regressions

1. **Access-mask reduction before transfer.** `DuplicateHandle` produces an inheritable event handle with only `EVENT_MODIFY_STATE`; `STARTUPINFOEXW` includes exactly the restricted handle in `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. The suspended worker is added to the Job Object before resumption. The worker must successfully call `SetEvent` on that handle but must get `WAIT_FAILED` from `WaitForSingleObject`, which requires `SYNCHRONIZE` rights. It must not receive the unlisted original event handle. The test checks all three outcomes and logs `WNRA05W_RIGHTS`.
2. **Query-only process handle.** A suspended worker is assigned to the Job Object before resumption. The test obtains `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` and verifies `TerminateProcess` on **that restricted handle** fails with Win32 error 5 (`ERROR_ACCESS_DENIED`) while the worker remains active. Closing the Job Object then terminates the worker as intended. The test logs `WNRA05W_PROCESS`.

These tests demonstrate OS access-mask enforcement for the named fixtures, **not** an inability of the privileged test controller to terminate processes using its existing full-access handles. They do not provide a complete secure launcher, a restricted token, an untrusted process sandbox, a general handle escrow protocol or a cryptographic authorization service. Separate threat modeling, access-control review, and native Windows CI would be required before production adoption.

Exact-head native Windows CI must show both `WNRA05W_RIGHTS` and `WNRA05W_PROCESS` and passing WNRA-05T/U/V tests. No claim of PASS without run and job evidence. Any failed attempt is preserved as a counterexample and corrected on a new head, without relaxing prior invariants.

**TRIAS:** no authority transition; GO-13 HOLD. **ORACLE:** evidence scoped to exact SHA and runner. **MENTOR:** preserve least privilege; do not generalize these two named rights to all Windows object types.
