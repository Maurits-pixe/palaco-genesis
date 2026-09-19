# BOTERHAM Monetary Journal — Sandbox v0.1

## Purpose

The **Monetary Journal** is the append-only audit layer for the BOTERHAM monetary sandbox. It reconstructs the lifecycle of monetary objects without changing balances and without granting authority.

Canonical trace:

**CURRENCY → WALLET → ACCOUNT → REWARD → LEDGER → REVERSAL**

## Contract

Every journal entry carries:

- monotonic sequence number;
- unique event ID;
- stable event type;
- caller-supplied UTC timestamp;
- aggregate reference;
- authorization reference;
- provenance reference;
- typed `MonetaryEvent` payload.

The journal rejects missing identity, timestamp, aggregate, authorization or provenance, and rejects duplicate event IDs.

## Constitutional separation

- **EVENT ≠ AUTHORIZATION**
- **JOURNAL ≠ LEDGER**
- **BALANCE ≠ DIRECT MUTATION**
- **PROVENANCE ≠ AUTHORITY**
- **SIGNATURE/AUTHENTICITY ≠ AUTHORIZATION**

The journal records an already-contextualized action. It does not authorize the action.

## Trace queries

The sandbox exposes read-only trace queries for:

- transaction ID;
- wallet ID;
- account ID;
- reward ID;
- currency ID.

The underlying entry collection is private. There is no public mutation or deletion API.

## Deterministic time

The journal accepts the timestamp as an explicit value rather than reading a wall clock internally. This keeps sandbox tests deterministic and leaves production time-source policy as an explicit architectural decision.

## Scope

This implementation is **sandbox-only**. It does not provide:

- production persistence;
- regulated financial custody;
- external settlement;
- blockchain issuance;
- legal classification;
- production compliance approval.

Those remain separate authorization and implementation gates.


## Event recording boundary

The `record` method is the named application boundary for appending a typed event. It delegates to the same validation path as `append`; it does not create or infer authorization. Callers must supply the authorization and provenance references explicitly.

This preserves the constitutional distinction between **recording an authorized action** and **authorizing an action**.
