# WNRA-06P — restricting SID initialization policy matrix

**DRAFT TEST ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent WNRA-06O DRAFT PR #343 at exact SHA `b071ee6973f9fa2c4bdf10e16a3a2471a33e8354`.

## Scope

WNRA-06N and 06O verified that both Python and Windows `cmd.exe` reach exit markers `37` and `53` with the Low-integrity baseline containing **no restricting SID**, but neither reaches the markers with a user or BUILTIN\\Users restricting SID. The earlier BUILTIN\\Users token could open several required files, so read/execute rights to those files alone do not explain `0xC0000022`.

WNRA-06P adds two **new restricting SID configurations** to the same controlled fixture:
- `authenticated_users` = `S-1-5-11`
- `everyone` = `S-1-1-0`

The existing `user` and `builtin_users` tests stay unchanged. All four restricted variants retain `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`, Low Integrity RID 4096, at least one restricting SID and no increased enabled privileges. The additional SID variations alter **only the restricting SID used to produce the test token**; the test does not grant or elevate a privilege, loosen an ACL or change production policy.

For each new policy, the test performs read/execute `CreateFileW` probes for both executable files and executes `os._exit(37|53)` in Python and `cmd.exe /d /c exit /b 37|53` in Windows cmd. It verifies the created child PID, image identity, actual Low-integrity restricted token, Job assignment before resume, process wait and fail-closed cleanup using existing test fixtures. Two existing `low_only` positive marker tests remain required from WNRA-06N and WNRA-06O; the new matrix does not weaken their expectations.

## Evidence contract

- `WNRA06P_ACCESS`: four executable/policy combinations, each with both read and execute decisions and Win32 codes.
- `WNRA06P_ENTRY`: eight process launches, independently recording reached markers, nonmatching exits, denied creations or timeouts.
- `WNRA06P_SUMMARY`: `sid_only_variation=true`, `no_privilege_grants=true`, `root_cause=UNKNOWN` and `authorization=DENY`.
- All rows must come from the exact-head native Windows workflow. A CI PASS means test evidence collection and invariants worked, **not** that restricted-SID execution succeeded.

## Interpretation boundary

If an additional restricting SID allows a worker to reach user code, that only demonstrates a difference between the tested token membership policies under a test runner; it is **not** security equivalence or authorization to adopt that SID. If every variant is blocked, no exact loader object or denial reason is identified. The test does not capture actual loader access-denied events, API-set resolution, ACL ACEs or a kernel call stack; it cannot prove a loader root cause.

**TRIAS:** GO-13 HOLD / DENY. **ORACLE:** exact commit/run/job evidence. **MENTOR:** a separately reviewed security policy and independent process-specific telemetry are required before considering an actual access-policy change.

No merge, activation, deployment, release, issuance, signing or enrollment.
