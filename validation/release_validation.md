# G9 Release Validation Record

**Status:** DRAFT TEMPLATE  
**PVC standard:** PVC-001  
**Purpose:** Record one formal G9 decision for one exact release candidate.  
**Scope:** This record does not authorize merge, deployment or runtime execution by itself.

## 1. Candidate identity

| Field | Value |
|---|---|
| Decision record ID | `UNSET` |
| Release candidate ID | `UNSET` |
| Proposed version | `UNSET` |
| Repository | `UNSET` |
| Source commit SHA | `UNSET` |
| PVC-001 revision | `UNSET` |
| Proposed tag | `UNSET` |
| Tag target SHA | `UNSET` |
| Artifact manifest reference | `UNSET` |
| Artifact digest(s) | `UNSET` |
| Validator revision | `UNSET` |

A mutable branch name is not sufficient candidate identity. The tag target and artifact digest remain observations until the decision is recorded.

## 2. Evidence completeness

Every row must identify the exact evidence reference, revision, method and timestamp. `UNSET`, stale, conflicting or unverifiable evidence cannot be treated as PASS.

| Gate | Result | Evidence reference(s) | Revision / digest | Reviewer | Freshness | Findings |
|---|---|---|---|---|---|---|
| G0 Scope & Identity | UNSET | UNSET | UNSET | UNSET | UNSET | UNSET |
| G1 SystemGraph Completeness | UNSET | UNSET | UNSET | UNSET | UNSET | UNSET |
| G2 Structural & Dependency Validity | UNSET | UNSET | UNSET | UNSET | UNSET | UNSET |
| G3 Planner & ExecutionPlan Conformance | UNSET | UNSET | UNSET | UNSET | UNSET | UNSET |
| G4 Kernel / Runtime Orchestration | UNSET | UNSET | UNSET | UNSET | UNSET | UNSET |
| G5 Event & Observability Integrity | UNSET | UNSET | UNSET | UNSET | UNSET | UNSET |
| G6 Architecture Compliance | UNSET | UNSET | UNSET | UNSET | UNSET | UNSET |
| G7 Integrated Core Alpha Validation | UNSET | UNSET | UNSET | UNSET | UNSET | UNSET |
| G8 Security Validation | UNSET | UNSET | UNSET | UNSET | UNSET | UNSET |

**Evidence completeness conclusion:** `UNSET`  
**Unresolved mandatory findings:** `UNSET`  
**Exceptions and scope limits:** `UNSET`

## 3. Release binding review

- Source commit, build inputs and artifact manifest reconcile: `UNSET`
- Artifact digest(s) are retained: `UNSET`
- PVC-001 and validator revisions are retained: `UNSET`
- G0–G8 all refer to the same candidate: `UNSET`
- Security and supply-chain evidence is complete for scope: `UNSET`
- Proposed tag resolves to the validated commit: `UNSET`

## 4. Decision authority

| Field | Value |
|---|---|
| Authority reference | `UNSET` |
| Mandate / policy reference | `UNSET` |
| Decision-maker identity | `UNSET` |
| Decision scope | `UNSET` |
| Decision time (UTC) | `UNSET` |
| Attribution / signature reference | `UNSET` |

A repository owner, CI actor, green check, reviewer label or verification result does not automatically constitute release authority. An unresolved authority reference forces HOLD.

## 5. G9 decision

**Outcome:** `UNSET`  
Allowed outcomes: `PASS`, `FAIL`, `HOLD`, `INCONCLUSIVE`.

**Rationale:** `UNSET`

G9 PASS may establish release eligibility or approval only within the recorded scope. It does not authorize runtime execution, merge or deployment.

## 6. GitHub tag and Release observation

Complete this section only after the G9 decision, if a release operator creates a tag or GitHub Release within the approved scope.

| Field | Value |
|---|---|
| Tag URL | `UNSET` |
| Release URL | `UNSET` |
| Resolved target SHA | `UNSET` |
| Created by | `UNSET` |
| Created at (UTC) | `UNSET` |
| Post-decision evidence reference | `UNSET` |

A tag or GitHub Release URL is evidence of a repository event. It is not proof that G9 passed and cannot retroactively create approval.

## 7. Append-only decision history

| Sequence | Event | Previous record / digest | New record / digest | Time | Actor | Evidence |
|---|---|---|---|---|---|---|
| 0 | Record created | N/A | UNSET | UNSET | UNSET | UNSET |

Subsequent corrections, re-evaluations, revocations or replacement candidates must append a new row and preserve this record. Earlier decisions, times and evidence are not overwritten.

## 8. Constitutional locks

- `CI PASS ≠ G9 PASS`
- `G9 PASS ≠ AUTOMATIC MERGE`
- `G9 PASS ≠ AUTOMATIC DEPLOYMENT`
- `G9 PASS ≠ RUNTIME AUTHORIZATION`
- missing mandatory evidence does not become PASS by inference;
- Quay history remains append-only;
- the exact spelling `VORM9EVIN9` is required in future PALACO additions.
