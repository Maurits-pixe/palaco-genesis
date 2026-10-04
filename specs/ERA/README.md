# ERA — Temporal Evidence and Authority

**Status:** Draft specification; not an implementation, certified clock, or
financial/exchange time authority.

ERA defines how temporal measurements become auditable evidence and how that
evidence may inform (but never create) decisions, authorizations, and execution.
It follows the invariant:

> TIME IS EVIDENCE, NOT AUTHORITY.

## Scope and prerequisites

The ERA ladder described here is:

1. ERA-001 — Temporal Evidence Infrastructure
2. ERA-002 — Canonical EDTR
3. ERA-003 — Seal and Proof
4. ERA-004 — Append-Only Temporal Registry
5. ERA-005 — Recovery and Continuity
6. ERA-006 — Clock Source Adapters
7. ERA-007 — Temporal Consensus and Byzantine Time Detection
8. [ERA-008 — Temporal Authority Boundary](#era-008--temporal-authority-boundary)
9. [ERA-009 — Temporal Commit and Revocation Race Control](#era-009--temporal-commit-and-revocation-race-control)

ERA-001 through ERA-007 are names and requirements supplied by the project
brief; this document does not claim that their specifications or mechanisms
already exist in this repository.

The proposed 4444 decimal digits after the second are a representation
requirement only. They do not establish physical clock resolution, accuracy, or
uncertainty. No implementation may present them as measured precision without
validated clock-source, synchronization, and uncertainty evidence.

## Shared temporal evidence rules

- Preserve UTC, the originating time zone and offset, clock source, sync state,
  uncertainty, provenance, and verification method where applicable.
- Keep event occurrence time distinct from receipt, processing, registry order,
  and commit order. A timestamp never substitutes for a sequence authority.
- Preserve every observation, including suspect or quarantined sources. A
  quarantine is a classification, not deletion.
- `UNKNOWN` is a valid result. Missing, conflicting, or unverified time must not
  be silently replaced with a local assumption.
- Corrections and recovery actions append linked records; they do not overwrite
  prior evidence.
- A seal or proof is evidence of integrity/provenance, not legal certification
  or permission to execute.

## ERA-008 — Temporal Authority Boundary

### Principle

**TIME MAY INFORM AUTHORITY. TIME SHALL NEVER CREATE AUTHORITY.**

The evidence path is:

```text
CLOCK → MEASUREMENT → ATTESTATION → EDTR → SEAL → PROOF
                                                     │
                                      AUTHORITY BOUNDARY
                                                     ↓
DECISION → AUTHORIZATION → EXECUTION COMMIT GATE → EXECUTION
```

The boundary means informational dependence, not delegated authority. Temporal
validity, provenance, decision validity, authorization validity, and
executability are separate properties. A valid timestamp or consensus result
does not establish any of the latter properties.

### Authorization and time conditions

An authorization is issued by an explicitly identified governance authority
and is bound to its subject, scope, provenance, validity interval, and
revocation state. Time-bounded authorization is evaluated as a condition on an
existing authorization; a clock cannot issue, renew, widen, or revive it.

Expiration and revocation are distinct, provenance-preserving transitions:

```text
ACTIVE ── time boundary reached ──→ EXPIRED
ACTIVE ── authorized event ───────→ REVOKED
```

Neither transition deletes the authorization or its history. An implementation
must not treat expiration as revocation or revocation as expiration.

### Execution preconditions

The commit gate must independently establish valid context, verified identity,
valid provenance, sufficient evidence, valid decision, active in-scope
authorization, satisfied time conditions, and clear revocation state. Failure,
conflict, or unknown status at any required check denies or safely holds the
commit; a timestamp alone never opens the gate.

### Invariants

- **ERA008-I01:** Time shall not create authority.
- **ERA008-I02:** Temporal evidence remains distinct from authorization.
- **ERA008-I03:** Expiration remains distinct from revocation.
- **ERA008-I04:** Missing or conflicting time is not silently resolved.
- **ERA008-I05:** Execution requires valid, in-scope authorization.
- **ERA008-I06:** Revocation ordered before commit prevents that commit.
- **ERA008-I07:** Temporal proof preserves provenance.
- **ERA008-I08:** Trust in a clock for measurement does not make it a
  constitutional authority.

## ERA-009 — Temporal Commit and Revocation Race Control

**Purpose:** define deterministic authorization-state evaluation and execution
commit behavior when authorization, revocation, expiry, retries, and execution
requests race.

### Authority and ordering model

ERA-009 consumes the authorization and provenance contracts defined by
governance. It does not grant authority or determine whether a revocation was
constitutionally authorized.

For each authorization, the registry must expose a durable, append-only
ordering of relevant state-changing events and commit outcomes. `observed_at`,
`issued_at`, message arrival time, and wall-clock timestamps are evidence, not
the linearization order. A timestamp comparison alone cannot resolve a race.

The registry/commit gate must provide an atomic serialization point for
revocation checks and execution commits (for example, a transaction or
equivalent per-authorization compare-and-append operation). If the system
cannot establish that ordering, the state is `UNKNOWN` or `CONFLICT` and
execution is denied or held for review.

### Authorization and attempt states

Authorization lifecycle:

```text
ACTIVE ── valid expiry condition ──→ EXPIRED
ACTIVE ── authorized revocation ──→ REVOKED
```

`EXPIRED` and `REVOKED` are terminal for that authorization. Reinstatement
requires a new authorization with new provenance; it cannot erase or reopen
the old one.

Execution-attempt lifecycle:

```text
RECEIVED → VALIDATING → COMMITTED
                   ├→ DENIED
                   └→ HELD (unknown/conflicting state)
```

`COMMITTED`, `DENIED`, and `HELD` are recorded outcomes. A held or denied
attempt is not a partial commit. Any later retry is a distinct event linked to
the original attempt.

### Commit protocol

The commit gate must, at its atomic serialization point:

1. Resolve the authorization and its complete ordered event history.
2. Verify identity, evidence, decision, provenance, scope, and authorization
   status.
3. Evaluate required time conditions using accepted temporal evidence and its
   uncertainty bounds; do not synthesize missing time.
4. Confirm no revocation or expiry transition precedes the commit in the
   authoritative event order.
5. Append the commit outcome and sequence atomically with the checks, or append
   a denial/hold outcome explaining the failed condition.

The commit's registry sequence is its ordering point. The commit record should
link the request/attempt ID, authorization ID, decision and evidence/proof
references, evaluated state, temporal condition result, actor/service, and
preceding registry position. It must not claim a precision or clock authority
that its source cannot substantiate.

### Race resolution

| Registry order | Required outcome |
| --- | --- |
| Revocation precedes the commit attempt's serialization point | Deny commit; preserve the authorization and revocation records. |
| Commit is atomically ordered before revocation | Record the commit; the later revocation blocks subsequent commits but does not rewrite history. |
| Expiry precedes the commit point, or its time condition is not verifiable | Deny or hold; preserve the expiry evidence and reason. |
| Ordering, revocation authority, or required time status is unknown/conflicting | Hold or deny; never infer the favorable order. |

Wall-clock labels may describe when events were observed, but cannot reverse
these registry-order outcomes. If later evidence reveals that an earlier
decision was wrong, append a correction/incident record and handle any
compensation through a separately authorized action; do not erase or rewrite a
completed commit.

### Replay, retry, and recovery

- Replayed event IDs and commit-attempt IDs must be detected. Reprocessing must
  not create a second execution commit for the same idempotency key.
- Retries must resolve current authorization state again; a previously
  successful check is not reusable after a revocation or expiry event.
- Recovery must verify log continuity, sequence integrity, and seal/proof
  links before resuming commits. Missing or forked history leaves the affected
  authorization in a fail-closed state.
- Replicas may not independently claim conflicting commit order. Reconciliation
  must preserve both histories as evidence and quarantine unresolved conflicts.
- Corrections, replay results, and recovery decisions are new linked events.

### Invariants

- **ERA009-I01:** A commit and its final authorization/revocation check share one
  atomic ordering point.
- **ERA009-I02:** Registry order, not wall-clock comparison, resolves a commit
  versus revocation race.
- **ERA009-I03:** A revocation ordered before commit prevents execution.
- **ERA009-I04:** A revocation ordered after commit cannot erase that commit but
  prevents later commits under the revoked authorization.
- **ERA009-I05:** Unknown, conflicting, or unverifiable required state fails
  closed.
- **ERA009-I06:** Replay is idempotent and preserves the original outcome.
- **ERA009-I07:** Corrections and recovery append records; they never rewrite
  prior evidence.
- **ERA009-I08:** Temporal evidence constrains commit eligibility but never
  creates authorization.

### Reference model status

`palaco-citadel::InMemoryCommitGate` is an initial process-local reference model
for registry ordering, revocation checks, and idempotent attempt replay. Its
mutex provides only in-process serialization; records are neither durable nor
replicated, and the model does not verify revocation authority, temporal
uncertainty, identity, decision validity, or cryptographic proofs. It is not
suitable for financial or exchange execution. A production implementation must
provide durable atomic storage and independently validated trust and recovery
controls before relying on this behavior.

## Open validation gates

Before using ERA as a financial, exchange, or official time reference, separate
work must establish the physical clock sources, achievable resolution and
uncertainty, synchronization and holdover behavior, key custody and rotation,
failure/recovery guarantees, applicable legal and exchange requirements, and
independent conformance evidence. This draft makes no claim that those gates
have been met.
