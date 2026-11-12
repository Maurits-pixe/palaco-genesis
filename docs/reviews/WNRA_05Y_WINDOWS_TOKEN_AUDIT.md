# WNRA-05Y — Windows token audit and pre-resume DENY gate

**DRAFT TEST-ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent: WNRA-05X DRAFT PR #326 at exact base commit `f13433bf9d1496fd7a7453d49bcb375d0bfe38b9`. This candidate adds `verification/provenance/test_windows_anchor_token_audit.py` and registers it in the native Windows workflow. No production launcher, user identity service, signing root, token elevation, issuance, release or deployment.

## Threat and observation

A Windows Job Object, restricted handle rights, and `CREATE_SUSPENDED` **do not automatically reduce** an access token's integrity label, elevation or privilege set. The existing test launcher calls `CreateProcessW` in the test controller's security context. This suite therefore distinguishes *observing the token* from *enforcing a new restricted token*.

The two tests use `OpenProcessToken(TOKEN_QUERY)` and `GetTokenInformation` to inspect the controller and a suspended child **before `ResumeThread`**. Observations cover `TokenIntegrityLevel` (integrity RID), `TokenElevation` (elevated flag), `TokenPrivileges` (privilege count), and `IsTokenRestricted`. The first test expects the child to have the same observed attributes as its controller and checks that no child marker executes. The absolute values are diagnostics, **not** policy constants.

A second test models a deliberately stricter admission policy: **child integrity must be strictly lower than parent integrity**. Because this fixture's ordinary process launch does not implement token restriction, the policy must **DENY before resume** and close the Job Object; no child marker may appear. This is a *negative policy demonstration*, not evidence that the suite created a low-integrity process.

## Scope and remaining work

- Only a test-controller and its native Windows worker are exercised. Restricted token creation (`CreateRestrictedToken`), low integrity SIDs, restricted privileges, AppContainer, mitigations, ACL hardening, identity binding and threat-based sandbox policy remain **UNIMPLEMENTED**.
- Token *privilege count* equality is not proof of equivalent privilege content or access-control semantics. Audit counts and flags do not guarantee general security isolation.
- The test does not resume an untrusted child when the required lower integrity is unavailable. All token, Job Object, thread and process handles are closed on failure.
- CI PASS means only that these named Windows-native observations and the negative pre-resume policy ran on the exact commit.

## Verification requirements

The native Windows workflow must emit both `WNRA05Y_TOKEN` and `WNRA05Y_POLICY`, the observations line `WNRA05Y_OBSERVATION`, and tests `... ok`. The existing WNRA-05T/U/V/W/X regressions remain required. Any failed run is recorded and corrected on a new commit; prior-run evidence cannot certify a newer SHA.

**TRIAS:** GO-13 HOLD / AUTHORIZATION DENY. **ORACLE:** evidence-bound to exact-head Windows CI. **MENTOR:** a restricted-token launcher requires separate architecture, code review, threat model and explicit authorization before production use.

**No merge, release, activation, issuance or enrollment.**

## Exact-head Windows counterexample and corrected legacy oracle

The first WNRA-05Y head `137cba911ba0794fa305acf49597716847f47499` triggered Windows run `43162755431` (job `130997530942`). Both new WNRA-05Y tests **PASSED**, including token parity and DENY-before-resume. The overall Windows job **FAILED** because an earlier WNRA-05U test observed `UNEXPECTED_INHERIT` using only `GetHandleInformation` with a parent process's numeric event-handle value. Windows handle values are **process-local**; a reused numeric value can denote an unrelated object. The legacy assertion therefore did not prove event inheritance. The correction makes the test worker attempt `SetEvent` with that numeric value, publishes a complete marker, and requires the **original parent event to remain unsignaled** after the attempt. It preserves the security invariant without equating numeric validity with object identity. A new exact-head Windows run is mandatory; the red run remains preserved.

## Additional Windows counterexample and object-identity correction

The subsequent head `06eee97db06468d49d9a092e5613dd1682006af5` initially **FAILED** run `43162982397` on an unrelated earlier SQLite lease concurrency test (`[3,3]` rather than `[0,3]`) before reaching token tests. Retrying the same head (Windows job `130998494284`) reached the full suite: both WNRA-05Y tests **PASSED** again, but three WNRA-05V/W/X tests failed because they likewise equated `GetHandleInformation` success on a numeric parent handle value with inheritance. A separate child handle can legitimately reuse the same number. The corrected tests now validate **actual parent event state** after child operations: allowed events must signal, unlisted events must remain unsignaled, EVENT_MODIFY_STATE-only events must remain signaled after an attempted unlisted wait, and SYNCHRONIZE-only events must remain unsignaled after attempted mutation. The original failures remain documented, and a new exact-head Windows CI pass is required. No underlying production code or token security configuration is changed.
