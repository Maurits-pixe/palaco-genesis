# WNRA-05I — disposition of ten observed local parser diagnostic differences

**Status:** AI REVIEW DRAFT; not a wire protocol or security certification. This is an append-only disposition on the WNRA-05H exact-code comparison, not a silent rewrite of WNRA-05G or WNRA-05H.

## Evidence boundary

- Base exact commit: `87bcad42b61570d2e6f799fba33267477ee46cf0`, DRAFT PR #310.
- Windows workflow run `43003652663`, job `130465653469`: all 17 negative shared cases rejected, exact Python/Node error-code test passed; 4/4 workflows success.
- Executable mapping: `verification/provenance/test_windows_anchor_error_codes.py`; input corpus `WNRA_05F_SHARED_DENY_CORPUS.json`.
- **Observed fixture behavior:** 7 equal / 10 different diagnostic labels. **No authority granted.**
- This decision table is an AI review recommendation, **not** a human governance decision or proof of generalized parser equivalence.

## Classification and disposition

| Case | Python / Node observed | Difference class | Proposed disposition | Additional requirement |
| --- | --- | --- | --- | --- |
| nested-duplicate | DUPLICATE_KEY / INVALID_JSON_SCOPE | Nested structure vs flat parser | RETAIN as local | Guard both against acceptance; never interpret Node scope error as proof of nested duplicate detection |
| float | FRACTION_OR_EXPONENT / NONCANONICAL_TEST_BYTES | Number token vs canonical representation | RETAIN as local | Keep exact-byte rejection on both |
| exponent | FRACTION_OR_EXPONENT / NONCANONICAL_TEST_BYTES | Number token vs canonical representation | RETAIN as local | Keep exact-byte rejection on both |
| negative-zero | NEGATIVE_ZERO / INVALID_SEQUENCE | Numeric sign/semantic validation order | RETAIN as local | Prevent an accepted zero sequence; exact code only diagnostic |
| unsafe-number | UNSAFE_INTEGER / INVALID_SEQUENCE | Numeric precision vs safe-range validation | RETAIN as local | Reject unsafe numeric magnitudes in both |
| boolean-sequence | INVALID_SEQUENCE_TYPE / INVALID_SEQUENCE | Type predicate naming | RETAIN as local | Reject boolean despite Python bool/integer subtype |
| null-sequence | INVALID_SEQUENCE_TYPE / INVALID_SEQUENCE | Type predicate naming | RETAIN as local | Reject null consistently |
| leading-space | NONCANONICAL_TEST_BYTES / INVALID_JSON_SCOPE | Whole JSON parser vs flat scope matcher | RETAIN as local | Reject noncanonical prefix bytes, not silently trim |
| utf8-bom | UTF8_BOM / NONCANONICAL_TEST_BYTES | Decoder BOM preprocessing | REVIEW FOLLOW-UP | Consider explicit raw-byte BOM precheck **before** Node TextDecoder to improve diagnostics; separately test regression; no acceptance today |
| array-scope | SCHEMA_MISMATCH / INVALID_JSON_SCOPE | Parsed shape vs flat parser scope | RETAIN as local | Reject non-object scope in both |

**Disposition count:** 9 RETAIN / 1 REVIEW FOLLOW-UP. None requires error-code equality for the currently proven local fail-closed invariant.

## Why the BOM deserves attention

Node's default TextDecoder behavior may remove a leading BOM before the subsequent string check. The existing canonical-byte comparison still rejects the affected raw bytes in the tested fixture. This is **not an observed authorization bypass**; it is a diagnostic mismatch and an opportunity to make a deliberate byte-order check explicit. A proposed follow-up must preserve the WNRA-05H baseline and create new test evidence, including a positive canonical vector and negative BOM input, on native Windows.

## Contract-level decision boundary

1. **DENY parity is required** for the named local fixture corpus, and was observed.
2. **Diagnostic-code parity is not required** absent a separately approved canonical wire contract. Do not publish these codes as public API semantics.
3. **No general equivalence claim:** Node's flat parser rejects nested structures at scope; Python parses nested structures before schema evaluation.
4. **No security upgrade from CI:** Windows tests demonstrate only named cases and runtime environment. They do not supply independent custodian, signature, governed trust root, or issuance permit.
5. **No silent mutation:** Any change to BOM handling or parsing creates a new candidate/head and demands exact-head CI and code-matrix review.

## AI TRIAS / ORACLE / MENTOR

- **TRIAS:** All ten differences may remain diagnostic-only under the existing local fixture contract; release, protocol canon, and GO-13 stay blocked.
- **ORACLE:** 17/17 DENY and the 10 exact-code differences are supported by the WNRA-05H Windows job; general parser equivalence and production runtime are NOT EXECUTED.
- **MENTOR:** Preserve the working test matrix; prioritize one small BOM byte-check candidate if diagnostic precision is valuable, and refrain from mass-renaming codes without wire requirements.

**Disposition:** REVIEW DRAFT / EVIDENCE-BASED LOCAL DECISION PROPOSAL / GO-13 HOLD / AUTHORIZATION DENY.

**Next valid transition:** WNRA-05J BOM-predecoder narrow test candidate (optional), then fresh exact-head Windows CI and human protocol-governance review if canonical codes are ever desired.
