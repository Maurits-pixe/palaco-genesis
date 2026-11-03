# ORCH-046 — Offline orphan recovery review contract

Status: **DRAFT / NON-EXECUTING / HOLD**. Stacked on ORCH-045 (#212).

## Purpose

Convert one read-only ORCH-045 observation into a deterministic, operator-reviewable classification. No cleanup, rename, quarantine, publication, private content access, identity change, or authority issuance is implemented.

## Review protocol

1. Inspect one marker sequence using ORCH-045; stop on any diagnostic error.
2. Obtain expected byte length, digest, and generation sequence from a separately trusted manifest. SHA-256 equality is not publisher authentication.
3. Call `prepare_recovery_review`, preserving the original diagnostic receipt.
4. All outcomes have `execution_allowed = false`. Even matching evidence is `MatchingPendingHold`, not permission to delete the pending marker.
5. A later distinct governed recovery operation must obtain fresh evidence and explicit authorized human decision; it must handle races, trusted time, provenance, atomicity, and crash-recovery before any mutation.

## Failure cases

Missing expected evidence, mismatches, malformed observations and mixed pending/published states all fail closed. There is no automatic promotion of a local inspection to a trusted, durable, authenticated publication.

## Evidence boundary

Unit tests exercise classification only. They do not prove power-loss resilience, malicious-writer safety, cryptographic signature validation, encrypted personal storage or 56-day endurance.

TRIAS: HOLD any mutation or authority. ORACLE: diagnostics and SHA-256 are unauthenticated. MENTOR: next candidate is a non-destructive recovery receipt and explicit approval interface, reviewed independently before implementing filesystem moves.
