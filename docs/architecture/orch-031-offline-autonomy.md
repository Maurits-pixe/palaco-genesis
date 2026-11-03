# ORCH-031 — Offline Autonomy & Recovery

**Status:** DRAFT contract candidate  
**Goal:** maximal useful operation without internet while preserving constitutional authorization boundaries.  
**Authority:** none; no protected mutation, issuance, world-state change, or release is enabled.

## Autonomy principle

Offline is a normal operating mode, not an exceptional failure. ORCHEASTRA should allow local reading, search, reasoning, planning, drafting, diagnostics, and recoverable preparation without a network. The security system must never equate cached information with fresh authorization.

## Three autonomy classes

| Class | Examples | Offline contract |
| --- | --- | --- |
| Local read | cached project inventory, proof index, manuals, audit viewer | Allowed locally, label source timestamp and verification state |
| Local preparation | drafts, plans, simulations, queued proposals | Allowed only in isolated local state; cannot mutate authoritative records |
| Protected execution | issuing identity/authority, runtime command, commerce, worlds, release | HOLD until fresh trusted checks, unless a separately approved bounded offline capability is implemented |

## Data, storage and resilience requirements

1. Local-first readable project catalog and signed metadata snapshot with schema version.
2. Encrypted local durable draft store, per-actor partitioning, explicit retention/quotas.
3. Append-only local event outbox with idempotency key, sequence and content digest.
4. Crash-safe atomic checkpoints, replay detection and partial-write recovery.
5. Trust labels for each cached item: verified-at, stale, unverified, conflicting.
6. Offline search and deterministic, non-authoritative simulation without network calls.
7. Reconnection through authenticated, scope-bound reconciliation; never auto-execute queued intents.
8. Conflict detection, operator-visible diffs and explicit approval where constitutionally required.
9. Key rotation and device loss recovery; never store plaintext credentials in offline records.
10. Data export/import with provenance, integrity verification and consent boundaries.

## Temporal and revocation invariants

- A local wall clock is not sufficient to extend authority.
- Highest accepted trusted time and revocation epoch must be monotonic.
- EXPIRED and REVOKED must not be silently reversed by rollback or restore.
- Missing trusted time, changed policy version or unavailable revocation evidence => HOLD for protected execution.
- An offline queue is a list of **untrusted proposals**, not a deferred authorization.

## Recovery sequence

1. Detect disconnected mode; keep local read/draft surfaces working.
2. Enter read-only/staging posture for protected resources.
3. Journal local edits with integrity receipts and no authority claim.
4. On reconnection, authenticate actor and fetch current trusted time, policy, revocations and state.
5. Revalidate each staged intent against current context; reject duplicates and conflicts.
6. Ask the competent authority for any required approval.
7. Execute only through the governed online commit gate, then write proof receipts.
8. Reconcile local journal; preserve rejected entries for inspection, without silent deletion.

## Negative acceptance scenarios

- ORCH031-N01: network lost during draft save -> local draft recovers after restart.
- ORCH031-N02: network lost during protected execution -> HOLD, no partial unproven commit.
- ORCH031-N03: local clock rollback -> no renewed grant authority.
- ORCH031-N04: old snapshot restored -> no resurrection of revocation.
- ORCH031-N05: same queued intent replayed -> one accepted execution at most after authorization.
- ORCH031-N06: stale policy version -> HOLD pending revalidation.
- ORCH031-N07: conflicting offline edits -> explicit conflict; no silent overwrite.
- ORCH031-N08: device with wrong actor context -> no cross-actor draft disclosure.
- ORCH031-N09: altered local journal digest -> quarantine, no execution.
- ORCH031-N10: unavailable trust provider on reconnect -> HOLD protected actions.
- ORCH031-N11: interrupted reconciliation -> resumable and idempotent.
- ORCH031-N12: malformed cache -> local error state, not an authority claim.

## Implementation slices

- A: conservative action classifier with unit tests (**this PR**).
- B: durable encrypted local draft store and crash recovery (**not implemented**).
- C: append-only signed staging outbox and replay resistance (**not implemented**).
- D: authenticated online reconciliation and idempotent commit integration (**not implemented**).
- E: operator review UI with proof/audit receipts (**not implemented**).

`ORCH-031 = DRAFT / NO_OFFLINE_EXECUTION_AUTHORITY / HOLD_FOR_PRODUCTION`.
