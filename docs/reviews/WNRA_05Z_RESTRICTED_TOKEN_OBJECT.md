# WNRA-05Z — restricted Windows token and low integrity, token-object only

**DRAFT TEST CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.**

Parent: WNRA-05Y PR #327 at exact SHA `f975a277d1449c91f5a2d83ec7126ffef103d8b4`.

## Scope

The new native Windows fixture `verification/provenance/test_windows_anchor_restricted_token.py` tests two Windows access-token object operations. The GitHub Actions Windows workflow now watches and executes this file.

1. Obtain the test controller's process token with `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT` for this controlled token-object operation; call `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` to remove/disable unnecessary privileges; set the returned token object's mandatory integrity label to **Low (S-1-16-4096)** using `ConvertStringSidToSidW` and `SetTokenInformation(TokenIntegrityLevel)`. Observe the resulting integrity RID against the controller and count enabled privileges. Require low RID = 4096, below the controller, and no increased number of enabled privileges.
2. Duplicate the reduced token into a **query-only handle** and attempt `SetTokenInformation(TokenIntegrityLevel)`. Windows must refuse the edit with Win32 error 5 (`ERROR_ACCESS_DENIED`). All created token and SID handles are explicitly freed, even on failure.

The `IsTokenRestricted` flag is **observed but not assumed** to equal a particular value: `DISABLE_MAX_PRIVILEGE` is a distinct capability reduction from restricted-SID policy. Reduced enabled-privilege counts are only a coarse metric and do not prove absence of every dangerous token capability.

## Non-goals and significant security limitations

This fixture **does not create or run any worker process using the reduced token**. The token stays local to the native CI test controller and is closed after inspection. It proves neither that a worker can be reliably launched under that token nor that a Job Object can enforce that token's semantics on process descendants. There is no `CreateProcessAsUserW`, `CreateProcessWithTokenW`, `STARTUPINFOEX` token substitution, AppContainer, alternate desktop, network policy, secure broker, security descriptor hardening, denial-of-service guarantee, independent attestation, release or production use.

The earlier WNRA-05Y negative pre-resume guard remains deliberately separate. Do not call this a production sandbox or claim job-bound low-integrity execution. Applying restricted tokens to an actual suspended worker needs its own threat model, handle-custody and process-creation review.

## Exact-head evidence requirements

Native Windows CI must show both `WNRA05Z_RESTRICTED` and `WNRA05Z_QUERY_ONLY`, plus both `unittest ... ok` outcomes and unchanged prior WNRA-05Y tests. Any Windows failure must be preserved as a counterexample and fixed on a new commit; no PASS claim is permitted on a failed exact head.

**TRIAS:** GO-13 HOLD / AUTHORIZATION DENY. **ORACLE:** bind observations to commit and Windows job IDs. **MENTOR:** assess a future restricted-token process launcher only through separate architecture and authorization gates.

**No merge, production activation, release, signing, issuance, or enrollment.**

## First native Windows counterexample

Head `d60ff56e003393f0d5931ff81d570f73ce1aa976`, Windows run `43165143298`, job `131005155266` **FAILED** the low-integrity operation with `SetTokenInformation` Win32 error 5 because the source token had only `TOKEN_QUERY | TOKEN_DUPLICATE`; its derived restricted token lacked the access needed for label adjustment. The query-only negative test passed. A new commit explicitly opens the **source** with `TOKEN_ADJUST_DEFAULT` for the isolated controller operation. This is not an expansion of worker authority; no worker process is launched. A new exact-head Windows run is required. The failed run remains part of the evidence history.
