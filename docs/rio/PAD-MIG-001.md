# PAD-MIG-001 — Versioned schema/migration contract

Status: SPECIFICATION COMPLETE — NOT EXECUTED

This artifact defines the first forward migration contract for the RIO verification-record boundary. It is derived from PAD-SQL-001 and PAD-RECORD-001 and is intentionally limited to deterministic schema, checksum, and migration-ledger rules.

Migration artifact: database/migrations/0001_pad_record_001.sql

Static SHA-256 of the migration artifact:

8611b0dccb825ca810f0ff6d6aeaca2f224d4c3491fd199cb260910a4e5d6d1c

The checksum above identifies the reviewed repository artifact. It is not evidence that a PostgreSQL database executed the migration.

## Schema boundary

The forward migration defines the following canonical record surfaces:

- rio_pad_schema_migrations: ordered migration ledger with lowercase SHA-256 checksums and predecessor binding.
- rio_verification_runs: run identity, contract/test-pack versions, environment and execution references, lifecycle status, counts, provenance, run digest, and optional previous-run binding.
- rio_verification_run_manifests and rio_verification_run_unresolved: run-owned manifest digests and unresolved items.
- rio_observations: canonical stdout/stderr bytes, exit status, observed and normalized values, provenance, and integrity digest.
- rio_evidence: closed evidence records bound to observations, execution references, closure metadata, provenance, and digests.
- rio_verifications: expected/observed/evidence digests, verifier and ruleset references, outcome, provenance, and integrity digest.

The schema preserves the PAD-RECORD-001 identity and provenance boundary: distinct run, test, execution, observation, evidence, and verification identifiers; canonical UTF-8 text; raw byte capture; and lowercase SHA-256 digest fields.

Multiple evidence rows may refer to one observation. A correction therefore remains append-only: it is a new evidence or verification record with new provenance and digest binding, never an UPDATE or DELETE of historical evidence.

## Deterministic forward protocol

A migration runner must load the exact reviewed file bytes and apply this protocol atomically:

1. Verify the trusted migration manifest and checksum. An unknown migration, checksum mismatch, or broken predecessor chain blocks execution.
2. Begin one database transaction.
3. Apply the exact forward migration and no inferred or generated statements.
4. Validate the expected tables, columns, keys, foreign keys, checks, and checksum format constraints.
5. Record the migration ID, version, artifact checksum, predecessor checksum, timestamp, and runner version in the migration ledger.
6. Commit only after all validation succeeds; otherwise roll back the complete transaction.

Migrations are monotonic and forward-only. There is no down migration that rewrites or deletes PAD records. Schema correction requires a new ordered migration and new records where record-level correction is needed.

## Invariants and enforcement boundary

The DDL enforces schema/version pins, non-nil identities, non-blank provenance and references, digest formats, lifecycle/count relationships, time ordering, foreign-key retention, and basic expected/observed outcome relations.

The following remain application/runtime validation requirements because they require values from multiple records or lifecycle context: observation and evidence digest equality; execution and test cross-binding; verification-to-run/evidence binding; SEALED closure over unresolved child rows; immutable record behavior; canonical serialization; and authorization of writers. Their existence in this contract is not runtime evidence.

## Explicit non-claims

This migration has not been executed against PostgreSQL. This repository state does not claim SQLx or database-runner behavior, isolation or crash-recovery behavior, authorization, roles/grants, mutation-denial enforcement, production deployment, dispatcher/outbox behavior, or conformance results. PAD-SEC-001 owns security and mutation-boundary enforcement; PAD-OUTBOX-001 and PAD-VER-001 remain later boundaries.

Next sequence: PAD-SEC-001 → PAD-OUTBOX-001 → PAD-VER-001.
