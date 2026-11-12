# WNRA-06C — restricted-SID access diagnostics (two policy variants)

**DRAFT TEST-ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent WNRA-06B DRAFT PR #330 at exact head `c95dc902cb292c39e7cc3ee38b991790594536a7`.

## Evidence-driven motivation

WNRA-06B confirmed the token with restricted current-user SID, Low integrity and reduced privileges, and verified creation of a suspended worker with this token. After resumption, the worker exited with NTSTATUS `0xC0000022` (`STATUS_ACCESS_DENIED`); successful Python worker execution was **not** demonstrated. The precise denying ACL or loader resource was not independently located.

## New Windows-native comparative test

The fixture `verification/provenance/test_windows_anchor_restricted_sid_access_diagnostics.py` tests two separately scoped `CreateRestrictedToken` SID configurations without changing any machine, file, or directory ACL:

- `user`: the current user's SID, matching WNRA-06B's restricting-SID experiment.
- `builtin_users`: the standard BUILTIN\\Users group SID `S-1-5-32-545`, a different restricting SID intended to assess whether the broader Users group ACEs available to the token change loader/runtime access. This is **not** a general-purpose or approved production access-control policy.

Each variant creates a restricted primary token with `DISABLE_MAX_PRIVILEGE`, assigns Low integrity RID 4096, verifies `IsTokenRestricted`, nonzero `TokenRestrictedSids`, and no increase in enabled privileges. It attempts `CreateProcessAsUserW(CREATE_SUSPENDED)`, assigns the process to a kill-on-close Job Object before resuming, queries the actual child's restricted and Low-integrity token, and records exactly one of three results:

- `create_blocked`: Windows rejected process creation; no child handles or resume.
- `runtime_blocked`: a created process exited nonzero shortly after resumption. This is **not** successful worker execution.
- `worker_live_then_job_terminated`: worker remained alive after resumption, and the Job Object closed and terminated it; only this result supports a working fixture.

An unexpected clean early exit or unrecognized Win32 error fails the test. The comparison is diagnostic: even a working BUILTIN\\Users variant does not by itself prove which specific ACL rejected the user-SID variant. All tokens, SIDs and process handles are cleaned up in `finally`.

## Scope limitations

No ACL changes, new file permissions, deployment, network access, interactive desktop access, token broker, AppContainer, production sandbox, independent proof root, signing or authorization. A group-SID configuration may permit more resource access and requires separate threat modeling before considering actual product integration.

## Evidence requirements

Exact-head native Windows CI must emit **both** `WNRA06C_DIAGNOSTIC variant=user` and `variant=builtin_users`, including explicit result strings and `authorization=DENY`. All earlier WNRA-06A and 06B regression tests remain required. Report the observed results literally, never equate CI PASS with successful runtime execution for every variant. Preserve red attempts as counterevidence.

**TRIAS:** GO-13 HOLD / AUTHORIZATION DENY. **ORACLE:** Windows job + commit bound observations. **MENTOR:** future ACL source tracing or a constrained runtime policy needs separate design and review. No merge, production activation, issuance, enrollment, or release.
