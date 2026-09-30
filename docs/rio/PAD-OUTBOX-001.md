# PAD-OUTBOX-001 — Atomic event and delivery-intent contract

Status: SPECIFICATION COMPLETE — NOT EXECUTED

Base: PAD-SEC-001 at edda5129ccc3c2555416de84a751c494c5e87cf4

This contract defines the durable delivery-intent boundary between an immutable event stream and an external relay or consumer. It builds on the existing RIO event/replay invariants and PAD-SEC-001 authorization boundary.

No PostgreSQL outbox, dispatcher, worker, external transport, consumer, or exactly-once mechanism is implemented or executed by this contract.

## Boundary and authority

The canonical event stream records what happened in the PALACO domain. The durable outbox records an authorized intent to publish a specific immutable event to a specific destination. The outbox is the source of truth for queued delivery intent.

A worker, queue wake-up, transport callback, delivery receipt, or external acknowledgement is not authority. Dispatch does not equal execution, authorization, business success, or finality.

NOTIFY or an equivalent wake-up signal may reduce polling latency, but it is not durable evidence and must never be the only path by which an outbox item becomes visible.

## Atomic event and outbox commit

One transaction must bind the state mutation, immutable event append, and outbox insertion:

1. validate the current projection, optimistic revision, authorization scope, lifecycle, and idempotency fingerprint;
2. construct the canonical event envelope and next per-stream sequence;
3. append the event with its predecessor digest, event digest, provenance, and schema version;
4. update the current projection only when the candidate transition is valid;
5. insert exactly one outbox intent bound to the event ID, event digest, subject, stream, sequence, destination, and authorization scope;
6. commit all changes together.

Any validation, conflict, provenance, digest, authorization, or persistence failure must roll back the complete candidate. No projection, event, or outbox intent may remain as a partial success.

An external publication is deliberately outside this transaction. A committed outbox intent proves only that a delivery intent was durably staged.

## Canonical outbox envelope

Every outbox intent must preserve these fields, whether represented as columns or an equivalent versioned record:

| Field | Contract requirement |
| --- | --- |
| outbox_id | Stable unique identity for one delivery intent |
| event_id | Stable identity of the immutable source event |
| subject_id / stream_id | Subject and ordered event stream binding |
| message_schema_version | Explicit supported envelope version |
| destination | Explicit external destination, never inferred by a worker |
| payload_reference | Stable reference to canonical event bytes |
| payload_digest / event_digest | Digest binding the published bytes to the source event |
| correlation_id / causation_id | Traceable request and causal ancestry |
| sequence | Contiguous per-stream ordering value |
| authorization_scope_ref / purpose | Scope and purpose to revalidate before dispatch |
| provenance_source / record_locator | Non-blank origin and stable locator |
| available_at | Earliest eligible claim time |
| leased_by / lease_token / lease_until | Current lease owner, fencing token, and expiry |
| attempt_count / retry_after | Retry and backoff state |
| status | PENDING, CLAIMED, DISPATCHED, ACKNOWLEDGED, or terminal quarantine state |
| last_error | Attributable failure classification, never a replacement for history |
| created_at / updated_at / dispatched_at / acknowledged_at | Lifecycle timestamps |
| integrity_digest / predecessor_digest | Integrity and optional outbox-chain binding |

The canonical event payload and all identity, sequence, provenance, scope, and digest fields are immutable. Operational delivery metadata may transition only through the state machine below and must retain an attributable transition history.

## Idempotency and atomicity

The idempotency claim, current projection, immutable event, and pending outbox intent are one logical commit boundary.

- The idempotency fingerprint binds the subject, operation, canonical request material, authorization scope, and relevant version.
- An identical retry returns the original event/outbox receipt and creates no second lifecycle transition or delivery intent.
- Reusing an idempotency key with different canonical material is a conflict and is rejected without mutation.
- A duplicate event ID, outbox ID, sequence, or digest conflict is rejected without mutation.
- A failed transaction leaves the prior projection, event history, idempotency claim, and outbox state unchanged.

Idempotency prevents duplicate logical commits. It does not make an external transport exactly-once.

## Delivery state machine

The normal lifecycle is:

PENDING → CLAIMED → DISPATCHED → ACKNOWLEDGED

The defined transitions are:

| From | Event | To | Required rule |
| --- | --- | --- | --- |
| none | atomic commit | PENDING | Intent is durable and bound to one immutable event |
| PENDING | valid lease claim | CLAIMED | Lease, fencing token, worker, attempt, and expiry commit before publish |
| CLAIMED | verified transport acceptance | DISPATCHED | Set dispatched_at only after the response binds to the same intent, digest, destination, and current lease |
| DISPATCHED | verified destination acknowledgement | ACKNOWLEDGED | Acknowledgement binds to the same event and does not prove execution or finality |
| CLAIMED | lease expires without valid result | PENDING | Recoverable retry; history and attempt count are preserved |
| PENDING or CLAIMED | unsupported, malformed, unauthorized, or irreconcilable result | QUARANTINED | Fail closed; retain payload, reason, and provenance |
| retry policy exhausted | explicit governance decision | DEAD_LETTER | Terminal operational state; no deletion or historical rewrite |

There is no direct PENDING-to-ACKNOWLEDGED transition. Claim is not acknowledgement. A transport response without a matching intent, digest, destination, schema, and active lease cannot advance the state.

## Lease, publication, and acknowledgement protocol

The future relay must implement this sequence:

1. select an eligible PENDING item or a CLAIMED item whose lease has expired;
2. serialize the claim according to stream ordering and current PAD-SEC-001 authorization;
3. fence the row with leased_by, a fresh lease_token, lease_until, attempt_count, and status CLAIMED;
4. commit the lease before any external publication;
5. publish the exact canonical envelope outside the transaction;
6. verify that the result refers to the same outbox_id, event_id, event_digest, destination, schema, and current lease token;
7. advance to DISPATCHED only on verified transport acceptance;
8. advance to ACKNOWLEDGED only on a separately verified destination acknowledgement.

The common relational implementation may use row locking and skip-locked selection, such as FOR UPDATE SKIP LOCKED, but that statement is a future adapter requirement, not runtime evidence in this repository.

A stale worker, empty identity, wrong lease token, expired lease, wrong destination, substituted payload, or race-lost claim must fail closed. A stale worker may not acknowledge or overwrite a newer lease.

## Retry, recovery, and at-least-once delivery

External publication is at-least-once. A worker may crash after publication and before recording the result; a later lease holder may publish again. Consumers must therefore deduplicate by at least the pair consumer_id and event_id, and must validate the event digest and sequence before applying it.

The following rules apply:

- an unknown external result is not ACKNOWLEDGED;
- an unknown result remains unresolved or returns to retry eligibility after lease expiry;
- a retry cannot expand the original authorization scope, destination, purpose, or payload;
- backoff and retry limits are operational metadata, not permission;
- retry exhaustion leads to an attributable quarantine or dead-letter decision;
- dead-letter and quarantine preserve the original event, outbox intent, error, and provenance;
- correction is a new event and new outbox intent, never a rewrite of the old one.

At-least-once dispatch plus consumer deduplication is the contract. Exactly-once delivery is not claimed.

## Ordering, replay, and revocation

Ordering is guaranteed per stream, not globally:

- event sequence values are contiguous and predecessor-bound;
- a sequence gap, predecessor mismatch, unsupported schema, or missing provenance blocks application;
- a later event may not overtake an unresolved earlier event unless an explicit quarantine or hold decision records the boundary;
- replay reconstructs state and never performs external publication, execution, authorization, or repair;
- snapshots are accelerators only when bound to an exact sequence, head digest, state digest, and valid historical prefix;
- revocation remains effective through replay and snapshot recovery;
- after REVOKED, no new execution commit may be created from a queued item;
- a revocation or audit event may proceed only under its explicit event policy and must not revive authority.

The outbox does not convert a queued event into authority. A relay worker cannot grant scope, clear revocation, alter a sequence, or reinterpret an unknown result as success.

## Failure and quarantine boundary

The relay must fail closed for:

- unknown or unsupported message schema;
- missing or non-canonical payload;
- payload, event, predecessor, or integrity digest mismatch;
- missing or contradictory provenance;
- sequence gap or stream mismatch;
- expired, revoked, or scope-incompatible authorization;
- missing, expired, or mismatched lease;
- destination substitution;
- unverified external response;
- persistence failure.

Failure handling must not silently delete work, acknowledge an unknown result, mutate the canonical event, or create a second logical transition. A quarantine record is an operational outcome, not evidence that the event executed.

## Mandatory contract test matrix

The future adapter and independent review must cover at least:

| Case | Required result |
| --- | --- |
| Projection, event, or outbox insert fails within the transaction | Complete rollback; no partial commit |
| Identical idempotency retry | Original receipt; no second event or outbox row |
| Idempotency key reused with changed request | Conflict; no mutation |
| Event or outbox digest is substituted | DENY or QUARANTINED |
| Lease expires before publication result | Reclaimable PENDING; attempt history retained |
| Stale worker acknowledges after a new lease | DENY; newer lease remains authoritative |
| Publication succeeds but result is unknown | Not ACKNOWLEDGED; retry/reconciliation path |
| Duplicate external publication | Consumer deduplicates by consumer_id and event_id |
| Later sequence arrives before an unresolved predecessor | Hold or quarantine; no out-of-order application |
| Subject is revoked before a new execution commit | DENY; no new execution commit |
| Unsupported schema or missing provenance | Fail closed; no external publication |
| Retry attempts to change scope, purpose, destination, or payload | DENY; original intent preserved |
| Retry exhaustion | Attributable QUARANTINED or DEAD_LETTER; no deletion |
| Replay or snapshot restoration | Deterministic state only; no external side effect |

## Status boundary

This repository state defines a reviewable outbox, lease, retry, replay, and consumer-deduplication contract only. It does not prove atomic database transactions, row-lock behavior, crash recovery, lease fencing, transport delivery, consumer idempotency, authorization enforcement, or exactly-once delivery.

PAD-OUTBOX-001 remains SPECIFICATION COMPLETE — NOT EXECUTED. The next boundary is PAD-VER-001.
