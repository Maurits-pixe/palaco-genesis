# WNRA-06A — low-integrity process creation and Windows Job Object, local feasibility

**DRAFT TEST-ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent WNRA-05Z PR #328, exact base `f9ba31d067e25a1a4f7f205b7f9c54c919d51ab0`.

## Attempted Windows-native test

The new test file `verification/provenance/test_windows_anchor_low_token_job_launch.py` reuses the previously verified `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` and `SetTokenInformation(TokenIntegrityLevel: LOW / RID 4096)` local fixture. It calls `CreateProcessAsUserW` with that token, `CREATE_SUSPENDED | CREATE_NO_WINDOW`, and `bInheritHandles=False`. If creation succeeds: verify still-suspended process, assign to a kill-on-close Job Object, query `IsProcessInJob`, open and inspect the child's real primary token, require Low integrity and enabled-privilege count not above controller, then resume. Verify process remains alive after resumption and that closing the job terminates it. All process, thread and token handles are cleaned up on success and failure.

If **Windows refuses process creation** with access denied (5), privilege not held (1314) or bad token type (1349), the test **records a fail-closed blocked feasibility outcome** and requires no process or thread handles and no resume. This outcome may be a passing negative test but **must not be described as successful low-integrity process launch**. Any other API error is a test failure. Both outcomes keep `authorization=DENY`.

## Important limitations

- This is a Windows CI-local experimental worker under a Job Object, **not** a secure production sandbox, application service or identity authority.
- The test temporarily uses Windows token APIs from the privileged test controller. It neither grants authority to the test worker nor creates an authorized PALACO session.
- Only a single Python sleep worker is considered. No claims for hostile code, secure token assignment across process trees, network/resource containment, AppContainer, restricted SIDs, kernel mitigations or production process quotas.
- A successful start cannot be claimed from a CI PASS if logs show `WNRA06A_CREATE blocked=true`; it requires `WNRA06A_LAUNCH low_integrity_worker=true` on exact-head native Windows CI.
- No release, merge, activation, signing, enrollment, or GO-13 transition.

## Evidence gate

The native Windows workflow watches and executes the new file. Capture the named launch or blocked log line and all previously required 05T–05Z regression results with the exact head SHA, run and job ID. Retain any red runs as counterevidence.

**TRIAS:** GO-13 HOLD and AUTHORIZATION DENY. **ORACLE:** distinguish successful launch from safe denial. **MENTOR:** before production, review privilege broker, token access-mask management, Job Object inheritance and full process threat model.
