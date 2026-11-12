# WNRA-05V — explicit handle allowlist and Job Object breakaway refusal

**Status:** DRAFT TEST CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.

Parent WNRA-05U DRAFT PR #323 at `d27878bf3a90b85b98bed46e44c7b93423dae0e4`. All changes are limited to `verification/provenance/test_windows_anchor_suspended_job_launch.py`, already registered in the native Windows CI workflow.

## New Windows-native local test cases

1. **Explicit allowlist.** The test creates two deliberately inheritable event handles in the parent. Using `STARTUPINFOEXW` and the `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` attribute, it allows exactly one in `CreateProcessW` with `bInheritHandles=True` and `CREATE_SUSPENDED`. After assigning the worker to a kill-on-close Job Object and resuming, the child calls `GetHandleInformation` on both numeric handle values. The expected observation is `allowed_inherited=true` and `unlisted_inherited=false`. All attribute-list allocations and handles are cleaned up. This is a **single controlled fixture**, not a universal or production-ready handle allowlist.
2. **Explicit breakaway attempt.** The test confirms `JOB_OBJECT_LIMIT_BREAKAWAY_OK` and `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` are absent from the configured Job Object flags, suspends and assigns the worker before resuming, and attempts `CREATE_BREAKAWAY_FROM_JOB` in a new child. The expected Windows result is error 5 (`ACCESS_DENIED`); a successful breakaway is forbidden. Both cases require the job's kill-on-close worker termination and `authorization=DENY`.

## Boundaries and review gates

Neither test deploys a production launcher, establishes comprehensive handle hygiene across token types or mitigations, certifies hostile-process containment, or guarantees that all possible breakaway mechanisms are blocked. The handle-list case deliberately enables inheritance but restricts it to a single listed event; it must not be confused with the earlier WNRA-05U `bInheritHandles=False` case. OS process/token security and CPU quotas remain outside scope.

Fresh exact-head native Windows CI must show `WNRA05V_ALLOWLIST` and `WNRA05V_BREAKAWAY` plus existing WNRA-05T/U regressions. If CI reports a failure, preserve the failure and repair on a new head. No merge, release, issuance, production admission, or authority escalation.

**TRIAS:** HOLD and DENY unchanged. **ORACLE:** only exact-head Windows observations prove named cases. **MENTOR:** defer general-purpose launcher hardening to separate threat-model and code-review gates.
