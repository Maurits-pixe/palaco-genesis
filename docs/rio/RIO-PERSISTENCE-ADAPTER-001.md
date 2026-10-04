# RIO Persistence Adapter Boundary

Status: IMPLEMENTATION SCOPE — executable in-memory reference contract

## Purpose

GO-9B.4 makes the repository boundary explicit above the immutable event store.
The reference adapter accepts an optimistic stream revision and a caller-owned
idempotency key, then evaluates event append, deterministic projection replay and
pending outbox construction as one candidate commit.

## Implemented invariants

- The request must target the adapter's stream.
- The idempotency key must be non-empty after trimming.
- The expected sequence must equal the current replay head.
- The canonical request fingerprint binds stream, expected sequence, key and
  ordered event input material.
- An identical key and fingerprint returns the original receipt without adding
  another event or outbox record.
- Reusing a key with different canonical material is rejected.
- Event history remains append-only and is validated by the existing digest-chain
  and replay rules.
- A successful candidate creates one pending outbox record for each newly
  appended event.
- Candidate event history, replayed projection and outbox alignment are checked
  before the reference adapter swaps state.
- Event-store or outbox failure leaves the committed event and outbox histories
  unchanged.

The projection is derived state. It is not an authority, authorization decision,
execution permission, evidence status or proof. The outbox is the pending source
record for a future dispatcher; this layer does not claim delivery, exactly-once
semantics or consumer acknowledgement.

## Explicit non-claims

This boundary does not yet provide PostgreSQL runtime behavior, SQL migrations,
database isolation or concurrency observations, durable crash recovery, a
dispatcher, consumer deduplication, API authentication, deployment readiness or
production conformance. Those claims require the corresponding database runner,
raw and normalized observations, rollback probes, concurrency probes and outbox
delivery evidence.

The next persistence evidence boundaries remain:

PAD-MIG-001 → PAD-SEC-001 → PAD-OUTBOX-001 → PAD-VER-001

Constitutional boundary:

REQUEST != DECISION != AUTHORIZATION != EXECUTION

ACCESS != AUTHORIZATION

RIO != CONSTITUTION

RIO != AUTHORITY
