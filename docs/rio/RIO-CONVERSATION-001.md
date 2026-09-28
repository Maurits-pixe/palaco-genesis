# RIO-CONVERSATION-001 — Conversation & Message Runtime Contract

**Status:** IMPLEMENTED ON DRAFT BRANCH — CI VERIFICATION REQUIRED  
**Scope:** `palaco-rio-core` conversation/message runtime  
**Constitutional role:** communication state only; no authority, authorization, decision, execution or proof is created by this layer.

## 1. Canonical boundary

RIO conversation processing follows:

```text
IDENTITY
  → SESSION
  → CONVERSATION
  → MESSAGE
  → CONTEXT / KNOWLEDGE / EVIDENCE
  → DECISION (when required)
  → AUTHORIZATION (when required)
  → EXECUTION (when separately authorized)
  → PROVENANCE / TRACE
```

The following invariants remain mandatory:

- `REQUEST != DECISION`
- `DECISION != AUTHORIZATION`
- `AUTHORIZATION != EXECUTION`
- `ACCESS != AUTHORIZATION`
- `RIO != CONSTITUTION`
- `RIO != AUTHORITY`
- conversation membership does not grant a capability
- message presence does not constitute evidence or proof

## 2. Conversation binding

Every `RioConversation` is bound at creation to:

- one `RioSessionId`
- one `IdentityHandle`
- one RIO surface
- one creation timestamp

A conversation may only open while the supplied session is active.

Every append operation revalidates the supplied session against the stored session ID, identity and surface. This prevents a second session from silently inheriting an existing conversation.

## 3. Message record

Every `RioMessage` contains:

- `RioMessageId`
- explicit `RioMessageRole`
- content
- `recorded_at`
- `ProvenanceRecord`

The initial roles are deliberately narrow:

- `Human`
- `Rio`

No role in this runtime represents constitutional authority.

## 4. Append-only history

Message storage is private to `RioConversation`. Consumers receive a read-only slice through `messages()`.

New records enter through `append()`, which validates:

1. active session
2. exact session binding
3. exact identity binding
4. exact surface binding
5. active conversation
6. non-empty content

Existing messages are not rewritten or deleted by session revocation or conversation closure.

## 5. Revocation

A revoked `RioSession` cannot:

- open a new conversation
- append to an existing conversation
- regain activity through conversation operations

Revocation therefore terminates future communication through that session instance while preserving prior records.

**REVOCATION != DELETION.**

## 6. Closure

`RioConversation::close()` is terminal for message append in that conversation instance. Closure does not delete existing messages and does not revoke the parent identity.

## 7. Persistence boundary

This GO defines in-memory runtime semantics only. It does **not** claim:

- durable event persistence
- PostgreSQL conformance
- distributed ordering
- cryptographic message signing
- production authentication
- API transport
- web/mobile production readiness
- end-to-end deployment

Those claims require separate evidence.

## 8. Verification targets

The implementation includes focused unit tests for:

- opening with an active session
- rejection of a revoked session at conversation creation
- append order preservation
- rejection after session revocation
- rejection of a different session
- rejection after conversation closure
- rejection of empty content

Repository CI must still establish formatting, clippy, test and architecture conformance for the exact PR head.

## 9. Next boundary — GO-9B.3

The next layer is **RIO Event Persistence**.

Its minimum contract is:

```text
SessionOpened
ConversationOpened
MessageAppended
ConversationClosed
SessionRevoked
    ↓
ordered immutable event envelope
    ↓
persistence adapter
    ↓
replay
    ↓
reconstructed runtime state
```

Required properties:

- no silent state change
- stable event identity
- sequence distinct from wall-clock timestamp
- provenance on every persisted event
- revocation survives replay
- old snapshots cannot resurrect revoked sessions
- replay must be deterministic for the same accepted event stream
- persistence failure must not be reported as successful commit

GO-9B.3 must remain an evidence/state layer. It must not turn persistence into authority or execution permission.
