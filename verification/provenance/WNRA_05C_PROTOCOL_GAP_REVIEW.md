# WNRA-05C — Anchor serialization protocol gap review

**Classification:** DERIVED REVIEW / NOT CANON / NOT A WIRE STANDARD.  
**Review baseline:** `Maurits-pixe/palaco-genesis`, WNRA-05B head `05a055c1c9be4316a322725d7170eafe8b9d9d24` (DRAFT PR #304), stacked on WNRA-05A #303, WNRA-04Z #302 and WNRA-04Y #301.  
**Governance:** GO-13 HOLD; production authorization DENY.  
**Evidence stage:** Source-level protocol gap review only. No external custodian, trust root or independently signed response is deployed.

## Current behavior and exact evidence

- `windows_test_anchor_adapter.py` constructs a locally controlled request-binding digest with Python `json.dumps(payload, sort_keys=True, separators=(",", ":"))` followed by UTF-8 and SHA-256. This is a **test implementation choice**, not approved canonical serialization.
- `WNRA_05A_ANCHOR_VECTORS.json` stores three fixed request vectors, expected canonical text and SHA-256; `test_windows_anchor_canonical_vectors.py` checks those exact fixtures.
- `test_windows_anchor_vectors_node.cjs` separately implements ASCII-escaped JSON string encoding and sorted object keys, checking the same three vectors and selected malformed examples. Cross-language agreement for those three inputs does **not** establish universal interoperability.
- `make_simulated_response` returns `SIMULATED-NOT-A-SIGNATURE:<digest>`. The token is **not cryptographic**, is locally produced, and is expressly not an external attestation.
- `SimulatedAnchorAdapter` keeps request IDs and sequence numbers only in process memory. Restart, other machines and concurrent actors are not covered by that replay state.

## Blocking protocol decisions (all UNRESOLVED)

| ID | Area | Gap or concrete ambiguity | Required rule/evidence before canon review |
| --- | --- | --- | --- |
| P01 | Canonical object scope | The mock hashes a request dictionary, not an independently specified signed response envelope or governed record. | Versioned request, record and response schemas; explicit bytes over which each digest and signature applies; domain-separated algorithm identifiers. |
| P02 | Duplicate JSON keys | A permissive JSON decoder may silently retain one of two identical keys. | Reject duplicate field names at the byte parser boundary; negative vectors with differing first/last values. |
| P03 | Unknown/missing fields | Python dataclass binding rejects some shapes, but a real wire decoder might ignore unknown fields. | Closed vs extensible schema decision; exact mandatory-field checks, typed null rejection and version negotiation. |
| P04 | Numeric ambiguity | Python and JS disagree in general on some number representations, signed zero, exponents, large integers and precision. Node's mock explicitly accepts only safe integers. | Formal integer range, leading-zero/negative-zero ban, exponent/float policy and exact textual representation. |
| P05 | Unicode normalization | Visually equivalent composed/decomposed strings can hash differently. Current three vectors cover only one accented example. | Specify whether NFC is required or prohibited; how to reject invalid scalar values, lone surrogates and noncharacters. |
| P06 | String escaping | `ensure_ascii` escaping and JS UTF-16 code units can diverge for supplementary code points; slash, control and escaped-key spellings also need cross-runtime proof. | Explicit Unicode scalar/JSON escape rules and bilingual golden vectors including astral symbols and controls. |
| P07 | Key sorting | Python Unicode code-point ordering and JS UTF-16 ordering diverge for some non-BMP field names. | Fix permitted key alphabet (prefer ASCII schema identifiers) and byte-wise ordering, or adopt an audited canonical JSON standard. |
| P08 | Digest design | No domain separation, typed hash label, schema identifier binding or digest downgrade policy beyond the test payload. | Exact algorithm suite, prefix construction, digest length and anti-downgrade constraints, with independent vectors. |
| P09 | Replay and time | Mock replay state is ephemeral and there is no trusted timestamp or cross-process monotonic clock source. | Independent persistent per-domain monotonic index, freshness policy, trustable time source and rollback/fork evidence. |
| P10 | Trust and rotation | `mock_key_trusted` is a caller-provided boolean; no key enrollment, signature verification, revocation or rotation. | Governed external trust root and operator separation, signed key rollovers, revocation checks, audit and recovery process. |
| P11 | Error semantics | Malformed/timeout/denied response maps to a mock DENY observation, but real API's transport and retry/idempotency are undefined. | Fail-closed wire error taxonomy, retries without duplicate issuance, authenticated status and audit correlation. |
| P12 | Deployment ownership | CI can self-generate the bytes and the mock response; it cannot prove custodian independence. | Named independent operator, custody separation evidence, environment-specific endpoints, human authorization gate. |

Any one of P01–P12 prevents promoting the current test encoding to CANONICAL or VERIFIED independent provenance.

## Required negative and boundary fixture matrix

These examples are **review requirements**, not tests claimed as executed in this PR.

| Fixture | Input condition | Expected provisional outcome |
| --- | --- | --- |
| N01 | Two `request_id` keys in one JSON object, values conflict | Reject before binding; DENY |
| N02 | Unknown field added or mandatory field omitted | Reject until schema policy is decided; DENY |
| N03 | `sequence` as `1.0`, `1e0`, `-0`, `9007199254740993` or boolean | Reject ambiguous/out-of-range typing; DENY |
| N04 | Composed `é` versus `e` plus combining acute | Do not equate without an explicit normalization policy; DENY for mismatch |
| N05 | Astral symbol, lone surrogate, escaped slash/control sequence | Verify exact independently fixed bytes; reject invalid Unicode |
| N06 | Mixed-case/unknown schema key, non-ASCII key, same-looking confusable identifier | Reject out-of-schema keys |
| N07 | Same record in two fixture domains or with another source commit | Different bound digest; cross-domain reuse DENY |
| N08 | Missing/corrupted response signature, unknown key or revoked key | DENY regardless of local digest match |
| N09 | Restart, concurrency, offline and machine switch with repeated request ID or sequence | Persistent remote replay policy required; otherwise DENY |
| N10 | Mutated record bytes preserving superficially similar JSON object | Do not accept by parsing alone; bound bytes require exact proof |
| N11 | Stale `ACCEPTED` cached after revocation or policy change | DENY pending current independent verification |
| N12 | Valid Python + JS fixture results with no approved independent operator | Authorization DENY |

## Recommendation and scope control

1. **WNRA-05D (allowed test preparation):** add negative, byte-level parser fixtures for duplicate keys, Unicode edge cases and unsafe numeric spellings; preserve candidate heads. This is test-only and cannot authorize.
2. **Future schema proposal:** select a canonicalization standard or a strictly delimited custom encoding with independent language conformance evidence. Propose versioning and migration rules separately; do not silently reinterpret WNRA-04Y.
3. **Governed trust review:** require named operator, separation of duties, key provenance, rotation, persistence and audit before any independent verification claim.
4. **Authorization gate:** remain independent of the engineering CI gate and explicitly decided by the competent authority.

## TRIAS / ORACLE / MENTOR AI-review

- **TRIAS:** the derived Python/JS agreement cannot become constitutional protocol by accumulation of passing tests. P01, P09, P10 and P12 are critical authority blockers; GO-13 HOLD and authorization DENY remain.
- **ORACLE:** three vectors and the WNRA-05B candidate-head Windows CI support those **bounded** results only. Duplicate-key, Unicode-normalization, remote replay and real signature semantics are NOT EXECUTED.
- **MENTOR:** first implement negative raw-byte parser fixtures as WNRA-05D, keeping the current tests untouched. Prepare a separately reviewable schema decision record after those results. No merge/release is requested.

**Non-decision:** This review does not certify a protocol, appoint a custodian, change canon, validate an external runtime, merge a PR, or grant authority.
