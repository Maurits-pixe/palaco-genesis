# WNRA-05J — raw UTF-8 BOM predecoder diagnostic correction

**Status:** IMPLEMENTED TEST CANDIDATE / DRAFT REVIEW. Not a wire standard or authorization.

## Lineage and scope

- Parent: WNRA-05I DRAFT PR #311 at `0faade65c5f8882590c3b416b40943f9840643af`.
- Prior WNRA-05H native Windows evidence remains frozen: run `43003652663`, job `130465653469`; 17 negative cases rejected, 7 matching / 10 differing local labels.
- This revision changes only a **test-only Node fixture parser**, its exact-code expectation and an explicit regression test. It does not change a governed runtime parser, protocol, authorization, issuance, trust root, or release gate.

## Narrow correction

1. Inspect the original Buffer for leading bytes `EF BB BF` **before** `TextDecoder('utf-8', { fatal: true })`, emitting local `UTF8_BOM`.
2. Retain the post-decode BOM guard as defense in depth.
3. Pin the `utf8-bom` shared-negative case in `test_windows_anchor_error_codes.py` to Python `UTF8_BOM` / Node `UTF8_BOM`.
4. Add a Node test that asserts that exact error, and checks a canonical vector still returns `authorization: DENY`, `independent_verification: NOT_EXECUTED`.
5. Leave all other 16 negative-case expected codes, shared corpus fixtures, and old evidence unchanged.

## Expected and verifiable outcomes

- Target local matrix: 17/17 negative cases rejected, **8 matching / 9 differing** diagnostic labels. This count is a prediction until exact-head CI.
- Canonical vectors must remain local DENY, never acceptance/issuance.
- Verify `.github/workflows/orcheastra-windows-metadata.yml` on the exact new head; capture Windows run and job IDs and log lines for the explicit BOM test and 17-case exact-code comparison.
- Any absent/failed Windows run means CI **NOT VERIFIED**, not PASS.

## AI TRIAS / ORACLE / MENTOR review lenses

- **TRIAS:** Change is contained to diagnostic handling in a local test fixture. GO-13 HOLD; AUTHORIZATION DENY; no merge, release, activation.
- **ORACLE:** Prior WNRA-05H native Windows evidence applies only to the prior SHA. New assertions require new exact-head Windows evidence; even PASS cannot imply protocol-code canon.
- **MENTOR:** Raw-byte inspection makes the rejection reason legible without changing the fail-closed outcome. Do not normalize the remaining nine local code differences without a justified contract.

**Next valid transition:** exact-head native Windows CI → evidence review, then optional human protocol-governance review for any publicly canonical error-code semantics.
