# RIO Event Persistence 001

Status: IMPLEMENTATION SCOPE — reference in-memory adapter

## Purpose

GO-9B.3 adds the first executable persistence boundary above the RIO session and conversation runtime. It records the lifecycle as an immutable event stream and reconstructs runtime state by deterministic replay.

The implementation is deliberately scoped to the RIO core crate. It does not claim PostgreSQL durability, production authentication, API readiness, web/mobile readiness or deployment.

## Canonical event types

The stream accepts only these typed payloads:

- SessionOpened
- ConversationOpened
- MessageAppended
- ConversationClosed
- SessionRevoked

Every event envelope carries:

- a stable event identifier;
- a stream identifier;
- a contiguous sequence;
- occurred-at and recorded-at timestamps as separate metadata;
- session and optional conversation identity;
- event provenance;
- typed payload;
- predecessor digest and event digest.

## Invariants

1. Sequence is the canonical ordering authority for one stream. Wall-clock timestamps are evidence metadata and never replace sequence ordering.
2. Event provenance must contain both a source and a stable record locator.
3. The digest commits to the canonical event fields, payload and predecessor digest.
4. A candidate append is replay-validated before the in-memory history changes.
5. A batch is atomic: a rejected candidate leaves the prior history untouched.
6. Identical retries using the same event identifier are idempotent. Reusing an event identifier with changed contents is rejected.
7. Replay is state reconstruction only. It never executes actions, invents events, repairs gaps or rewrites history.
8. Session revocation is terminal in reconstructed state. A revoked session cannot open a conversation or append a later message.
9. Snapshots are accelerators bound to an exact sequence, head digest and state digest. Snapshot validation cannot bypass the historical prefix.
10. A persistence-unavailable result is never returned as a successful commit.

## Scope boundary

RioEventStore is an in-memory reference adapter used to make the commit and replay semantics executable and testable. A later PostgreSQL adapter must preserve the same envelope, chain, idempotency, atomicity, replay and revocation invariants. Until that adapter exists and is verified, RIO persistence remains reference-runtime scope rather than production durability.
