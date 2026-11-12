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

The Windows CI workflow watches and executes the new fixture. Require `WNRA06B_TOKEN` with `restricted_flag=true`, plus one of `WNRA06B_LAUNCH`, `WNRA06B_CREATE blocked=true`, or `WNRA06B_RUNTIME blocked=true`, alongside previous WNRA-06A and 05Z tests. Record the distinct outcome accurately. Any red run remains preserved and must be fixed on a new commit.

**TRIAS:** HOLD / DENY. **ORACLE:** commit + run + job bound evidence, do not generalize. **MENTOR:** restricted-SID production policy and access graph require separate privilege broker and hostile-worker threat modeling.

## First Windows counterexample and revised outcome taxonomy

Head `3ff37ab17c64cb214c3094003602ecf9d69c3eaf` failed native Windows run `43177609895` / job `131045554985`. Token-object verification **PASSED** (`restricted_sid_count=1`, `restricted_flag=true`, Low integrity RID 4096, enabled privileges 4→1); the restricted-SID process was created, assigned and its child token inspected, but after `ResumeThread` the test worker exited before the required half-second live observation. The red assertion `0 != WAIT_TIMEOUT` is retained. This may indicate the restricted SID could not access Python or loader resources, but that root cause is **not independently established** by this run.

The correction recognizes an additional distinct outcome: `WNRA06B_RUNTIME blocked=true` reports a post-resume nonzero exit code, a created process and verified restricted token, without asserting successful worker execution. A clean early exit remains an error; the long-lived worker path still requires demonstrated liveness and job-close termination. Neither a blocked CreateProcess nor blocked runtime may be described as successful restricted-SID program execution. CI must be re-run at the new exact head.
