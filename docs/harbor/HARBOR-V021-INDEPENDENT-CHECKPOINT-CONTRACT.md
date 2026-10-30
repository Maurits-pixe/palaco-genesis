# Harbor v0.21 — independent checkpoint evidence contract

## Purpose

The local floor journal and advisory writer lock protect a local append-only
adapter. They do not establish an independent anti-rollback authority. v0.21
makes the missing evidence states explicit before any future external floor is
used.

## Contract

An independent checkpoint adapter returns exactly one observation:

- **Candidate** — one structurally valid candidate plus a source identifier;
- **Missing** — no floor is available;
- **Conflicting** — incompatible floor observations were returned.

Source failures remain distinct:

- **Unavailable** — the source cannot be reached or opened;
- **Uncertain** — the read outcome is ambiguous;
- **Malformed** — the response cannot be decoded.

Only a structurally valid candidate becomes CandidateAccepted. That label means
it may proceed to signature, freshness, rollback, and governance checks. It is
not trusted evidence and never grants authority.

Every non-candidate outcome becomes Hold. There is no fallback to a local
journal floor.

## Evidence boundary

This slice provides no:

- network client or external checkpoint service;
- signer enrollment, key custody, HSM, or governance root;
- trusted time or rollback-resistant persistence;
- quorum, liveness, or availability guarantee;
- admission, authorization, execution, publication, release, merge, or
  activation.

The actual source must be independently governed and verified before this
contract can support a production decision.

## Verification

The tests cover:

- candidate structural acceptance without trust promotion;
- missing evidence without local fallback;
- conflicting evidence;
- unavailable, uncertain, and malformed source errors;
- invalid source identifiers and invalid anchor records.

The module is a reference boundary only; CI evidence remains separate from human
review and authority.
