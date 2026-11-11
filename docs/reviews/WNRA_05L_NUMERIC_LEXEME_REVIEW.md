# WNRA-05L — numeric lexeme review: negative zero and unsafe integer

**Status:** AI REVIEW DRAFT / ANALYSIS ONLY / GO-13 HOLD / AUTHORIZATION DENY.

## Baseline and evidence

- Repository `Maurits-pixe/palaco-genesis`; parent WNRA-05K DRAFT PR #313 at `10b30c0883148125b6abcbda9edc86d6ee2e1fa9`.
- Parent WNRA-05K document-only runs: PALACO CI `43007317950`, Citadel A1 `43007317968`, SBOM `43007318002`, all `success`. No new native Windows execution was triggered by WNRA-05K documentation.
- Last observed native Windows test evidence is WNRA-05J PR #312 head `13c9eb21ccfd37996eabe65cc7cb9d62cda6e13a`, run `43006215920`, job `130474229608`; 17/17 shared negative cases DENY. Numeric outputs: `negative-zero` Python `NEGATIVE_ZERO`, Node `INVALID_SEQUENCE`; `unsafe-number` Python `UNSAFE_INTEGER`, Node `INVALID_SEQUENCE`.
- Source review at parent SHA: `windows_test_anchor_raw_bytes.py`, `test_windows_anchor_raw_bytes_node.cjs`, `WNRA_05F_SHARED_DENY_CORPUS.json`. No new runtime experiment or arbitrary-input parser proof is claimed in this document.

## Lexical vs numeric behavior

| Test input in `sequence` | Python test parser | Node test parser | Observed result |
| --- | --- | --- | --- |
| `-0` | `json.loads(..., parse_int=_integer)` passes original token `-0`; `_integer` raises `NEGATIVE_ZERO` before numeric conversion | Flat regex captures `-0`, then `JSON.parse` converts to JS negative zero; `Number.isSafeInteger(-0)` is true but `values.sequence <= 0` is true, so generic `INVALID_SEQUENCE` | Both DENY, diagnostic labels different |
| `9007199254740993` | `_integer` converts to arbitrary-precision Python `int`, then `abs(value) > 2**53 - 1` raises `UNSAFE_INTEGER` | Regex captures the digits; `JSON.parse` converts to JavaScript Number before safety validation. Precision may be lost. `Number.isSafeInteger(values.sequence)` is false for this magnitude, so generic `INVALID_SEQUENCE` | Both DENY, diagnostic labels different |

The lexical token information is accessible in Node as `match[2]` **before** `JSON.parse`; its current handler intentionally does not implement token-specific numeric diagnostics. The difference is therefore a diagnostic granularity and parsing-order issue, not an observed admission bypass. A future change must not infer that all potentially lossy conversions have been covered by the current 17-case corpus.

## Scope decision

1. **RETAIN current local codes.** The named negative samples are rejected on both engines. Do not equate diagnostic label differences with accepted state.
2. **No code patch in WNRA-05L.** This is a focused source-and-evidence review, not a new lexical policy or canonical wire error contract.
3. **If exact numeric-error labels later become a requirement:** propose a separate test-only candidate that performs raw token checks before `JSON.parse` in Node, preserves the 17 existing negative fixtures, adds boundary vectors near `2**53 - 1`, and confirms all three positive canonical vectors still yield `DENY` with no independent verification. That candidate needs new exact-head native Windows CI.
4. **No silent expansion:** This review does not certify correctness for signed zero in other fields, non-decimal literals, arbitrary numbers, nested JSON, real admission, signature validation or production runtime.
5. **No authority transition:** neither equal numeric codes nor CI success grants issuing, admission, activation, merge or release permission.

## AI TRIAS / ORACLE / MENTOR (single-assistant review lenses)

- **TRIAS:** Local test fixture boundaries remain explicit; code is unchanged, GO-13 HOLD and AUTHORIZATION DENY persist.
- **ORACLE:** Both numeric cases have named exact-code Windows logs on WNRA-05J; the mechanism follows directly from the two source parsers. Generalized safety and cross-runtime equivalence are NOT EXECUTED.
- **MENTOR:** Avoid widening the fix. If human protocol governance actually needs code parity, prioritize a separate pre-conversion numeric-token candidate with explicit boundary tests and Windows CI; otherwise stop the diagnostic harmonization here.

**Next valid transition:** review candidate → evaluate exact-head documentation CI. Any future numeric lexical implementation requires an independently scoped change and fresh Windows evidence, while GO-13 remains HOLD.
