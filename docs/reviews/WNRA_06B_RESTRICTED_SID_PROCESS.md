# WNRA-06B — restricted-SID token and low-integrity Job Object process

**DRAFT TEST CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.**

Parent: WNRA-06A PR #329, exact base commit `2255ceed78fb54398d1d89780dc4005a447ba021`.

## Implemented local Windows checks

The new test file `verification/provenance/test_windows_anchor_restricted_sid_worker.py` extends the token-object and suspended worker fixtures. It obtains the **current user's token SID** from `GetTokenInformation(TokenUser)`, passes one SID in `SidsToRestrict` to `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`, sets Low integrity (RID 4096) and verifies `IsTokenRestricted=true`, `TokenRestrictedSids` count ≥1, Low integrity, and no increase in enabled privileges. This is materially different from WNRA-05Z, where `IsTokenRestricted=0` was observed because only privileges were disabled.

A separate Windows-native test attempts `CreateProcessAsUserW` using the restricted-SID Low-integrity token with `CREATE_SUSPENDED`. If creation succeeds, it must assign to the kill-on-close Job Object *before* resumption; prove `IsProcessInJob`, inspect the **actual child's token** for Low integrity and restricted SIDs, ensure enabled privileges do not increase, then resume, observe a live worker, and verify job-close termination.

If Windows denies process creation with `ERROR_ACCESS_DENIED`, `ERROR_PRIVILEGE_NOT_HELD`, `ERROR_BAD_TOKEN_TYPE`, or `ERROR_BAD_IMPERSONATION_LEVEL`, that outcome is **BLOCKED/FAIL-CLOSED**. The test accepts that outcome only with no returned process/thread handles and no resume. A passing negative test is **not a successful restricted-SID process-launch demonstration**; only `WNRA06B_LAUNCH` in exact-head Windows logs supports that claim.

## Boundaries and threats

Restricting to the current-user SID may prevent reading resources that depend solely on broader group ACEs; this may itself prevent launching the Python executable on some runners. It is intentionally a narrow access-check experiment, **not** a generally approved production token policy. Restricted SIDs do not replace AppContainer, network sandboxing, file-system allowlists, restricted desktop, image/path validation, an external token broker, signed code provenance or threat-based mitigation policies.

One Python sleep worker is the only process payload used. No PALACO identity, issuer, artifact trust, anchor signing or production authorization is granted. No merge, deploy, release or enrollment.

## Required exact-head evidence

The Windows CI workflow watches and executes the new fixture. Require `WNRA06B_TOKEN` with `restricted_flag=true`, plus either `WNRA06B_LAUNCH` **or** `WNRA06B_CREATE blocked=true`, alongside previous WNRA-06A and 05Z tests. Record the distinct outcome accurately. Any red run remains preserved and must be fixed on a new commit.

**TRIAS:** HOLD / DENY. **ORACLE:** commit + run + job bound evidence, do not generalize. **MENTOR:** restricted-SID production policy and access graph require separate privilege broker and hostile-worker threat modeling.
