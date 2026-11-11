# WNRA-04B — Controlled build source and immutable-byte contract (DRAFT)

**Date:** 2026-11-11 (Europe/Amsterdam)  
**Repository:** `Maurits-pixe/palaco-genesis`  
**Frozen test head:** `e03f86d10d594d3cbed22e6d83186967906e5187` (PR #277)  
**Status:** DESIGN ONLY / DRAFT / GO-13 HOLD / AUTHORIZATION DENY.  
**Excluded:** product runtime, repository merge, signing, release, production credentials, external build-root authority.

## 1. Observed evidence and limits

At PR #277 head, GitHub Actions concluded success for Windows metadata regression **42904135016**, PALACO CI **42904135368**, Citadel A1 **42904135022**, and SBOM candidate **42904135030**.

Native Windows job **130137555663** explicitly logged:
- `test_hardlink_into_fixture_does_not_establish_origin ... ok`, with a same-volume outside-root hardlink and returned `OUTSIDE_ORIGIN` bytes.
- `test_inplace_mutation_after_nt_open_changes_returned_bytes ... ok`, with `MODIFIED` bytes after `NtCreateFile` opened an earlier version.

Neither test was skipped. They are **PASS for reproducing two gaps**, NOT PASS for protection. The existing adapter is only a disposable fixture. `BuildRootTestAdapter.read_metadata` remains fail-closed.

## 2. Proposed trust boundaries

### Trusted producer boundary

Only a **controlled PALACO build worker** can mint a candidate `BuildSourceLease`. It must bind:
- `build_id`, `producer_identity`, `artifact_role`, `attempt_id`, `expiry` and explicit `revocation_state`;
- worker-owned root handle, volume/namespace and allowed leaf name;
- external evidence reference for the expected content digest, obtained from a separately authenticated producer event, never from untrusted file metadata alone.

The Windows test fixture class, user-provided paths, readable manifests and successful CI runs **must not mint** production authority.

### Source inspection boundary

The reader receives a worker-issued, short-lived **opaque handle capability**, not arbitrary root path strings. The worker must:
1. Deny root or leaf reparse points; retain handle-relative single-component opening.
2. Bind volume/file identity and capture metadata from the **opened handle**.
3. Treat hardlink count and path location as *diagnostics only*; neither proves origin.
4. Read with strict size limits into a worker-controlled immutable byte buffer, or copy to a new file with a create-new/atomic staging contract, prohibiting untrusted writers from modifying the staged object.
5. Compute SHA-256 on the exact bytes consumed, and compare in constant-time with an independently trusted, pinned expected digest; fail closed on missing digest, mismatch, expired lease or unsupported source.
6. Recheck revocation/lease binding at the governed handoff. Store results as evidence, **not** as authorization.

**Important:** A hash of bytes freshly read from an attacker-controlled file without a separately trusted expectation cannot prove their origin. Checking a digest before and after a read alone cannot prevent a malicious in-place edit; snapshot/staging and producer binding are both needed.

### Output evidence boundary

Proposed `SourceReadEvidence v0` (non-canonical candidate):
```json
{
  "schema": "WNRA-04B/source-read-evidence-v0",
  "build_id": "<controlled-build-id>",
  "attempt_id": "<one-shot>",
  "root_capability_ref": "<non-secret-opaque-reference>",
  "producer_evidence_ref": "<authenticated-external-reference>",
  "file_identity": "<opened-handle-derived-identity>",
  "expected_sha256": "<trusted-64-hex-value>",
  "observed_sha256": "<computed-64-hex-value>",
  "byte_length": 0,
  "result": "HOLD"
}
```
The example is a contract illustration, **not an executed record**. `result` can be `MATCH_OBSERVED`, `MISMATCH`, `DENY` or `HOLD` in a future test implementation; it must not be mapped to `AUTHORIZED` without a separate authority gate.

## 3. Required failure behavior

| Case | Expected governed decision | Negative test |
| --- | --- | --- |
| Hardlink to outside-origin file, no producer proof | DENY | Existing PR #277 fixture; add enforcement test in next candidate |
| In-place write between NT open and read | DENY or trusted-snapshot-only | Existing PR #277 fixture; enforce pinned digest or immutable staging |
| Pinned expected digest mismatch | DENY | Change one byte after producer approval |
| Missing/forged producer evidence | DENY | Present syntactically valid but unauthenticated manifest |
| Lease expired, revoked or reused | DENY | Replay `attempt_id` and simulated clock boundary |
| Unsupported hardlink count / filesystem feature | DENY, not implicit PASS | Read-only or unknown volume behavior |
| Reparse root, junction child or NT namespace escape | DENY | Preserve earlier native test cases |
| Snapshot creation or read fails midway | DENY and cleanup | Inject failure; assert no partial artifact is accepted |
| Positive controlled immutable source | MATCH_OBSERVED only | Byte exact digest, identity, evidence reference |

No practical test should alter user-owned files; use disposable, controlled build fixtures. Skip counts and filesystem details must be explicit.

## 4. Minimal implementation slices (not yet authorized as production)

1. **Test-only digest enforcement** over a supplied expected SHA-256 pinned by the test harness, with negative mutation and missing-digest regressions. This validates byte identity only; it cannot self-assert origin.
2. **Trusted build-worker source lease proposal** with explicit issuer, ACL, volume and lifecycle review, then test-only simulated leases.
3. **Immutable staging discipline** with exclusive worker ownership and atomic staging, backed by native Windows adversarial tests.
4. **Evidence and governance binding** in a separately reviewed release/authorization candidate after human security review and relevant gates.

Do not implement a broad production `read_metadata` feature by simply switching the existing deny gate off.

## 5. Three-lens AI review

- **TRIAS:** capability issuance must be controlled by a separately authorized build worker; test evidence does not grant runtime authority. GO-13 and production DENY remain.
- **ORACLE:** both WNRA-04 limitations were reproduced in native Windows CI with no skip for the two named tests. Producer proof, ACL safety, trusted digest origin and immutable staging remain NOT EXECUTED.
- **MENTOR:** the first buildable narrow slice is a test-only expected-digest comparator, with intentional wrong-digest, missing-digest and in-place mutation tests. It should remain stacked separately from this frozen design.

This is an **AI review using three lenses**, not three independent human reviewers. No release or approval is implied.

## 6. Next admissible transition

`WNRA-04B DRAFT design` → `separate DRAFT test-only digest enforcement candidate`, guarded by native Windows CI on its exact head and a review of what the expected digest does *not* attest. Everything beyond test-only experimentation remains **HOLD / DENY**, pending real governance and human authority.
