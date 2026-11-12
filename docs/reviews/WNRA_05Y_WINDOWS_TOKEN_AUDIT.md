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
