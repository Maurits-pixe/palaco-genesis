# WNRA-05G — denial taxonomy review (DERIVED, non-canonical)

Status: **REVIEW CANDIDATE ONLY**. This document compares the two local, test-only parsers in `palaco-genesis` after WNRA-05F. It does **not** define a wire protocol, independent verifier, trust root, or entitlement.

## Frozen input and source references

- Baseline WNRA-05F head `100f361d016db824f7e69841269fa0e1c78b71ac`; stacked DRAFT PR #308.
- Corpus: `verification/provenance/WNRA_05F_SHARED_DENY_CORPUS.json`, profile `WNRA-05F-SHARED-NEGATIVE-v0.1` (17 cases).
- Python: `verification/provenance/windows_test_anchor_raw_bytes.py`; Node: `verification/provenance/test_windows_anchor_raw_bytes_node.cjs`.
- Native Windows run **43002258626**, job **130461003350**, passed both shared-corpus rejection tests. This run proves **reject vs. accept** behavior only, not individual rejection labels.
- The matrix below is **DERIVED by static reading of source**, and is **NOT EXECUTED as an exact-code assertion**. If code changes, regenerate and re-review.

## Per-case expected local error labels — static analysis, not observed per-case logs

| Fixture ID | Python label (derived) | Node label (derived) | Same? |
| --- | --- | --- | --- |
| duplicate-key | DUPLICATE_KEY | DUPLICATE_KEY | YES |
| nested-duplicate | DUPLICATE_KEY | INVALID_JSON_SCOPE | NO |
| float | FRACTION_OR_EXPONENT | NONCANONICAL_TEST_BYTES | NO |
| exponent | FRACTION_OR_EXPONENT | NONCANONICAL_TEST_BYTES | NO |
| negative-zero | NEGATIVE_ZERO | NONCANONICAL_TEST_BYTES | NO |
| unsafe-number | UNSAFE_INTEGER | INVALID_SEQUENCE | NO |
| boolean-sequence | INVALID_SEQUENCE_TYPE | INVALID_SEQUENCE | NO |
| null-sequence | INVALID_SEQUENCE_TYPE | INVALID_SEQUENCE | NO |
| unknown-field | SCHEMA_MISMATCH | SCHEMA_MISMATCH | YES |
| missing-field | SCHEMA_MISMATCH | SCHEMA_MISMATCH | YES |
| surrogate | INVALID_UNICODE_SCALAR | INVALID_UNICODE_SCALAR | YES |
| unicode-literal | NONCANONICAL_TEST_BYTES | NONCANONICAL_TEST_BYTES | YES |
| leading-space | NONCANONICAL_TEST_BYTES | INVALID_JSON_SCOPE | NO |
| trailing-newline | NONCANONICAL_TEST_BYTES | NONCANONICAL_TEST_BYTES | YES |
| utf8-bom | UTF8_BOM | UTF8_BOM | YES |
| invalid-utf8 | INVALID_UTF8 | INVALID_UTF8 | YES |
| array-scope | SCHEMA_MISMATCH | INVALID_JSON_SCOPE | NO |

**Summary:** 8 matching / 9 nonmatching labels **derived**, not code-parity verified. All 17 inputs were rejected by both implementations on the named Windows run; classification labels were not logged by that test.

## Review disposition

1. **RETAIN:** shared fail-closed invariant (reject all malformed inputs) already demonstrated for this corpus on native Windows.
2. **DO NOT NORMALIZE AUTOMATICALLY:** Python uses `json.loads` with hooks, Node uses a deliberately flat token matcher. Differences reflect parser shape and order of checks, not proof of equivalence for arbitrary JSON.
3. **DO NOT PROMOTE:** these labels are local fixture diagnostics, not canonical error codes or externally observable protocol behavior.
4. **REQUIRES NEW TEST SLICE:** if exact-code parity is needed, first add an executable result-capture matrix with isolated parser entry points, explicit expected labels and native Windows evidence. Treat any unexpected acceptance as BLOCKED; explain intentional label differences rather than papering them over.

## AI triad review

- **TRIAS:** Both adapters remain local-only; constitutional authorization and GO-13 stay HOLD. No runtime activation.
- **ORACLE:** Distinguish the observed all-DENY Windows result from the derived label assignments. The per-label matrix is not a CI claim.
- **MENTOR:** Maintain a single case-ID vocabulary and small diagnostic categories; defer harmonizing parser internals pending an approved protocol rationale.

**Decision:** REVIEW DRAFT / SOURCE-ANALYZED / ERROR-CODE PARITY NOT EXECUTED / AUTHORIZATION DENY.

Next valid transition: review this matrix, then (if the project needs it) create a separate executable exact-code comparison candidate with independent evidence.
