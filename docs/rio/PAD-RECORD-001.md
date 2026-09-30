# PAD-RECORD-001 — Canonical Verification-Run and Evidence Records

Status: IMPLEMENTATION SCOPE — in-memory/domain record contract

## Purpose

PAD-RECORD-001 defines the immutable record family between a verification
execution and any later persistence adapter. It keeps raw observation, closed
evidence, verification result and run closure distinct, deterministic and
cross-bound.

The implementation lives in the RIO core as a domain boundary. It is not a
database schema, PostgreSQL conformance result, authority engine or release
decision.

## Identity separation

The record family keeps these identities distinct:

- RUN_ID — verification run
- TEST_ID — declared test
- EXECUTION_ID — concrete execution
- OBSERVATION_ID — raw captured observation
- EVIDENCE_ID — closed evidence record
- VERIFICATION_ID — evaluation result

No identity is inferred from another identity.

## Record layers

### ObservationRecord

The raw observation retains:

- stdout bytes;
- stderr bytes;
- process exit status, when available;
- raw observed value;
- optional normalized value;
- capture timestamp;
- test and execution identity;
- provenance;
- canonical integrity digest.

Normalization is additive. It cannot replace or rewrite the raw observation.

### EvidenceRecord

Evidence closes one observation with:

- observation and execution references;
- copied capture time;
- closure time;
- observation digest;
- explicit closure reason;
- provenance;
- canonical integrity digest.

Evidence is not authority and closure is not proof of truth.

### VerificationRecord

Verification records preserve the separation between:

- expected-value digest;
- observed-value digest;
- evidence digest;
- verifier reference;
- ruleset reference;
- outcome: VERIFIED, MISMATCH or UNDETERMINED.

VERIFIED requires equal expected and observed digests. MISMATCH requires
different digests. UNDETERMINED remains explicit.

### VerificationRun

A run records:

- run schema/version;
- test-pack and contract-set identifiers and versions;
- environment, database, scope, execution and isolation references;
- monotone sequence and timestamps;
- lifecycle status;
- result/evidence counts;
- sorted manifest references;
- explicit unresolved items;
- optional previous-run identity and digest;
- provenance;
- run digest.

Lifecycle states are DEFINED, PREPARED, EXECUTING, COLLECTED, VERIFIED and
SEALED, with explicit exceptional states BLOCKED, REJECTED, UNDETERMINED and
MISMATCH.

## Invariants

- Schema and record version are checked explicitly.
- Required identifiers, references and provenance are non-empty.
- Every record has deterministic UTF-8 canonical bytes and a SHA-256 digest.
- Stored digests are revalidated before a record is accepted.
- Timestamp order is checked across capture, closure, verification and run bounds.
- Previous-run identity and digest must appear together.
- Run manifests and unresolved items are sorted and duplicate-free.
- A record set must bind run, test, execution, observation, evidence and result.
- Corrections require new records; E0 is immutable and no historical record is
  rewritten.

## Explicit non-claims

PAD-RECORD-001 does not claim that a run executed, that a toolchain was
available, that evidence is true, that a result is PALACO conformance, that an
outcome is authorization or that any action may execute. Missing command output
remains insufficient for verification, unblocking, authorization or
conformance.

No PostgreSQL runtime, SQL migration, database isolation observation, crash
recovery, signature verification, dispatcher delivery, production persistence,
deployment or operational conformance is implemented here.

The next boundaries remain:

PAD-MIG-001 → PAD-SEC-001 → PAD-OUTBOX-001 → PAD-VER-001
