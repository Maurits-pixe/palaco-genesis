# WNRA-05K — nine remaining local diagnostic differences

**Disposition:** AI REVIEW DRAFT / REVIEW-ONLY / GO-13 HOLD / AUTHORIZATION DENY.

## Exact evidence and lineage

- Repository: `Maurits-pixe/palaco-genesis`.
- Parent WNRA-05J DRAFT PR #312, head `13c9eb21ccfd37996eabe65cc7cb9d62cda6e13a`.
- Exact-parent GitHub Actions: PALACO CI `43006215813`, Citadel A1 `43006215772`, SBOM Evidence Candidate `43006215710`, and ORCHEASTRA Windows metadata regression `43006215920`: all completed `success`.
- Windows job `130474229608`, Windows Server 2025, exercised ten Node fixture tests (10/10 PASS), including WNRA-05J exact raw BOM diagnostic, and Python exact-code comparison (PASS). Its job log prints all 17 shared-negative case IDs with `authorization=DENY`.
- Evidence applies to the **parent SHA only**. This document-only child is a fresh review candidate. Do not reuse parent CI as exact-child CI.
- Primary files at the parent SHA: `verification/provenance/test_windows_anchor_error_codes.py`, `test_windows_anchor_raw_bytes_node.cjs`, `windows_test_anchor_raw_bytes.py`, `WNRA_05F_SHARED_DENY_CORPUS.json`.
- WNRA-05I review remains historically correct for its earlier 7/10 result; WNRA-05J explicitly changed only the BOM diagnostic, yielding 8 equal / 9 differing in the observed Windows job.

## Remaining nine mismatches — case-specific boundaries

| Case | Observed Python | Observed Node | Local classification | Decision and caveat |
| --- | --- | --- | --- | --- |
| `nested-duplicate` | `DUPLICATE_KEY` | `INVALID_JSON_SCOPE` | Duplicate check vs flat-scope rejection | **RETAIN.** Node's scope rejection must not be described as nested-duplicate detection. |
| `float` | `FRACTION_OR_EXPONENT` | `NONCANONICAL_TEST_BYTES` | Token classification vs canonical-byte check | **RETAIN.** Both reject; no accepted fractional sequence. |
| `exponent` | `FRACTION_OR_EXPONENT` | `NONCANONICAL_TEST_BYTES` | Token classification vs canonical-byte check | **RETAIN.** Both reject; no general numeric grammar equivalence inferred. |
| `negative-zero` | `NEGATIVE_ZERO` | `INVALID_SEQUENCE` | Negative-zero lexical vs numeric semantic check | **RETAIN, WATCH.** Node loses the lexical minus-sign distinction in this fixture; no acceptance or positive sequence claim. |
| `unsafe-number` | `UNSAFE_INTEGER` | `INVALID_SEQUENCE` | Integer safety vs generic sequence validation | **RETAIN, WATCH.** Rejects the tested magnitude; does not prove uniform arbitrary-size numeric handling. |
| `boolean-sequence` | `INVALID_SEQUENCE_TYPE` | `INVALID_SEQUENCE` | Type specificity vs generic sequence validation | **RETAIN.** The named Boolean input is rejected by both. |
| `null-sequence` | `INVALID_SEQUENCE_TYPE` | `INVALID_SEQUENCE` | Type specificity vs generic sequence validation | **RETAIN.** The named null input is rejected by both. |
| `leading-space` | `NONCANONICAL_TEST_BYTES` | `INVALID_JSON_SCOPE` | Canonical whitespace vs strict first-character scope | **RETAIN.** Do not infer that Node has a general whitespace-normalization policy. |
| `array-scope` | `SCHEMA_MISMATCH` | `INVALID_JSON_SCOPE` | JSON shape parsing vs flat-only matcher | **RETAIN.** Both reject the test array; no nested or general JSON support claimed. |

The nine differences are **local diagnostic labels**, not canonical protocol error codes. Retaining a mismatch is not an approval of the full parser design. All cited observed cases are rejected; no code-equality requirement follows from the current fixture-only contract.

## Bounded conclusions

1. **Observed on parent Windows run:** the nine named mismatches persist, all 17 shared negatives are rejected, and the BOM case now agrees as `UTF8_BOM`.
2. **Not observed / NOT EXECUTED:** production parser behavior, public wire interoperability, independent cryptographic verification, authorized admission, issuance, activation, and equivalence for arbitrary JSON.
3. **No silent canon promotion:** `RETAIN` means 'do not rename codes without a contract', not 'all diagnostic differences are constitutionally approved'.
4. **Potential future targeted hardening:** If protocol governance later requires lexical precision for negative-zero/unsafe-number, define a new independent contract, specify acceptable code semantics, and run new negative/positive regression cases on a new head. That action is **not** authorized by this review.
5. Do not rewrite frozen WNRA-05I/05J records or fold this draft into a release decision.

## AI review by three lenses (not independent human sign-off)

- **TRIAS:** The review preserves fixture-domain scope and GO-13 HOLD. It creates no authority or public-code canon; no merge, release, runtime, or admission.
- **ORACLE:** Claims 8 equal / 9 different and 17/17 DENY are bound to parent exact SHA and Windows job; deeper parser equivalence is UNKNOWN and not tested.
- **MENTOR:** Keep the nine labels local with explicit caveats; avoid broad refactoring. If needed, prioritize a separate lexical numeric review specifically for `negative-zero` and `unsafe-number` rather than altering all nine labels.

**Next valid transition:** review-only candidate → confirm any child CI outcome → human governance decision if a public error-code contract is required. Otherwise retain existing local diagnostics and preserve HOLD/DENY.
