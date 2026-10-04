# PAD-VER-001 — Deterministic verification and evidence-closure contract

Status: SPECIFICATION COMPLETE — NOT EXECUTED

Base: PAD-OUTBOX-001 at e9b9c2d175a20f913ca0e96fc7f229ea275331b2

This contract defines how PAD-SQL-001, PAD-MIG-001, PAD-SEC-001, and PAD-OUTBOX-001 may later be verified through deterministic execution evidence. It separates observation, evidence closure, verification, certification, and release.

No verification run, PostgreSQL execution, independent attestation, certificate, or conformance result is created by this document or by repository CI.

## Verification boundary

Verification evaluates a defined claim against a defined test pack, environment, implementation revision, expected result, observed result, and closed evidence. It does not create authority, repair history, or silently convert absence into success.

The verification object graph is:

TEST REQUIREMENT → EXPECTED MATERIAL → EXECUTION → OBSERVATION → EVIDENCE CLOSURE → VERIFICATION → RUN SEAL

Each edge must carry a stable identifier and be independently cross-bindable. A verifier must be able to reconstruct which implementation, command, fixture, environment, and evidence produced one result.

## Canonical record roles

| Record | Required meaning |
| --- | --- |
| Test requirement | Stable requirement and test identifier, version, scope, ordering, and required/optional classification |
| Expected material | Versioned canonical input, expected value or expected digest, command/fixture reference, and ruleset reference |
| Execution | One attempted invocation with run, execution, toolchain, revision, environment, authorization scope, and temporal identity |
| Observation | Raw stdout/stderr bytes, exit status, observed value, normalized value where applicable, timestamps, and provenance |
| Evidence closure | Immutable binding from observation to execution and test, observation digest, closure reason, provenance, and integrity digest |
| Verification | Independent comparison of expected, observed, and evidence digests with verifier identity, ruleset, outcome, and provenance |
| Run seal | Closed manifest of required records, unresolved items, counts, previous-run binding, final status, and run digest |

The PAD-MIG-001 schema fields expected_digest, observed_digest, evidence_digest, verifier_ref, ruleset_ref, outcome, provenance, and integrity_digest must retain these meanings.

## Deterministic canonicalization and digests

All compared material must use a versioned canonical serialization:

- canonical UTF-8 bytes with an explicit field order;
- no dependence on map iteration order, locale, platform newline conversion, or implicit whitespace;
- timestamps represented in canonical UTC form with sequence kept separate from wall-clock time;
- raw stdout and stderr preserved as bytes before any decoded or normalized representation;
- expected value, observed value, normalized value, and evidence closure kept distinct;
- SHA-256 digests represented as lowercase hexadecimal with a declared domain and schema version;
- the digest input, algorithm, version, and field list recorded in the manifest.

The verifier must recompute digests from the preserved source material. A stored digest without reconstructible canonical input is insufficient evidence.

Expected and observed digests are not interchangeable:

- expected_digest commits to the canonical expected material;
- observed_digest commits to the canonical observation result;
- evidence_digest commits to the closed evidence record and its observation binding;
- integrity_digest commits to the record envelope and provenance.

## Outcome semantics

The only semantic verification outcomes are VERIFIED, MISMATCH, and UNDETERMINED.

| Outcome | Meaning | Conformance effect |
| --- | --- | --- |
| VERIFIED | Required expected material, observation, evidence closure, provenance, digest recomputation, and independent verification all pass; comparable expected and observed material agree | May contribute to a complete run; never sufficient alone |
| MISMATCH | Complete, authentic, comparable expected and observed material differ under the declared ruleset | Fails the relevant requirement; no conformance |
| UNDETERMINED | Evidence is missing, blocked, not run, timed out, errored, unsupported, unverifiable, incomplete, contradictory, or independence is not established | No conformance; reason must be preserved |

EXPECTED ≠ OBSERVED yields MISMATCH only when both values are complete, authentic, comparable, and correctly bound. Missing observation is not MISMATCH. A blocked or not-run test is never VERIFIED.

Integrity, schema, provenance, identity, sequence, or evidence-closure failure must not be relabeled as a semantic mismatch. It is UNDETERMINED with a precise failure reason unless a separate security policy requires rejection or quarantine.

## Run and evidence lifecycle

The verification run lifecycle is:

DEFINED → PREPARED → EXECUTING → COLLECTED → VERIFIED / MISMATCH / UNDETERMINED → SEALED

BLOCKED and REJECTED are explicit terminal outcomes for a run that cannot proceed or is invalid.

A run may be SEALED only when:

- the exact implementation revision, test-pack version, contract set, environment, toolchain, and authorization scope are recorded;
- every required test has an execution result or an explicit blocked/not-run reason;
- every observed result has closed evidence, provenance, and recomputable digests;
- every verification record has an independent verifier identity and ruleset;
- expected, observed, evidence, run, and manifest digests cross-bind;
- no unresolved child record remains;
- counts, statuses, sequence values, timestamps, and previous-run binding validate;
- the final run digest and manifest are recorded atomically.

Sealing closes the evidence set. It does not make an incomplete or undetermined result successful.

## Evidence closure and immutability

Evidence closure requires, at minimum:

1. a stable run, test, execution, observation, and evidence identity;
2. the exact raw observation bytes and exit status;
3. the canonical observed and normalized values, when applicable;
4. execution sequence and captured timestamps;
5. source and stable record locator;
6. observation, evidence, and integrity digest recomputation;
7. a closure reason and closure timestamp;
8. binding to the expected material and declared ruleset.

Canonical observations and evidence are append-only. No UPDATE, DELETE, or historical digest rewrite may repair a result. A correction or new measurement creates a new run or new record with new provenance and an explicit relation to the earlier record. E0 remains immutable when E1 is added.

## Independent verifier boundary

The independent verifier must be distinct from the producer, fixture generator, executor, and system under test. Its identity, verifier implementation revision, ruleset version, dependency fingerprint, and independence attestation must be recorded.

The verifier may:

- read the declared expected material, observations, evidence, manifests, and event chain;
- recompute canonical encodings and digests;
- validate identity, provenance, sequence, temporal order, integrity, and cross-record binding;
- append a verification result and verifier receipt.

The verifier may not:

- mutate expected material, observations, evidence, manifests, execution records, or prior verification records;
- create or delete observations to make a comparison pass;
- rewrite a digest, seal, sequence, timestamp, or provenance locator;
- grant authorization, approve release, or declare unsupported claims true;
- be the sole party verifying its own generated evidence for a critical release.

Critical release requires independent, and where policy demands it dual, attestation. Verification is a bounded activity over a declared scope; it must terminate at that scope rather than create infinite meta-verification.

## Deterministic execution envelope

A future verification harness must record:

- machine-readable RUN_ID and execution identifiers;
- repository, branch, exact commit, base dependency, and workflow/configuration revision;
- toolchain identity and dependency lock state;
- exact commands and declared working directory;
- test and requirement identifiers in deterministic order;
- isolated environment and immutable fixture references;
- authorization and isolation scope;
- start/end/captured timestamps and event sequence;
- exit status, raw stdout/stderr, artifact references, and all relevant digests;
- blocked, skipped, timeout, error, and unsupported classifications without silent omission.

The harness must not use a successful process exit code as a substitute for semantic verification. A process can exit successfully while the formal result is MISMATCH or UNDETERMINED.

## Replay and certification sequence

The verification sequence is:

DECISION → REPLAY → REPLAY CERTIFICATE → INDEPENDENT VERIFICATION → VERIFICATION CERTIFICATE → RELEASE

Replay reconstructs state from immutable records and validates the declared chain. Replay does not execute actions, contact an external system, repair gaps, or grant authority. A replay certificate records what was reconstructed and from which head, sequence, snapshot, and digests.

A verification certificate is bounded to the exact test pack, implementation revision, environment, ruleset, and evidence manifest. It must not be generalized to an unverified implementation, environment, or deployment.

## Required denial and ambiguity rules

The future verifier and independent review must cover at least:

| Case | Required result |
| --- | --- |
| Expected material is absent or ambiguous | UNDETERMINED; no conformance |
| Observation is absent | UNDETERMINED, not MISMATCH |
| Observation exists without closed evidence | UNDETERMINED |
| Expected and observed values differ and are fully bound | MISMATCH; no conformance |
| Stored digest differs from recomputed digest | UNDETERMINED or rejection; no success |
| Evidence points to another run, test, execution, or observation | UNDETERMINED or rejection |
| Provenance, sequence, timestamp, or chain is invalid | UNDETERMINED or rejection |
| Test is blocked, skipped, not run, timed out, or unsupported | UNDETERMINED; never VERIFIED |
| Verifier is the producer or mutates the evidence basis | DENY independent verification |
| Replay encounters a gap or invalid snapshot | UNDETERMINED; no repair |
| Prior evidence must be corrected | Append E1/new records; preserve E0 |
| Required test set is incomplete at seal time | Run remains BLOCKED or UNDETERMINED; no SEALED conformance |
| One result is VERIFIED while another required result is MISMATCH | Overall conformance denied |
| One result is VERIFIED while another required result is UNDETERMINED | Overall conformance denied |

## Conformance boundary

Conformance may be considered only after all required tests for the declared contract set have complete expected material, authentic observations, closed evidence, valid provenance, independent verification, and a valid run seal. Any required MISMATCH, UNDETERMINED, BLOCKED, REJECTED, unsupported result, unresolved item, or missing attestation prevents conformance.

Green repository CI validates only the workflow checks it actually ran. It does not establish PAD runtime execution, PostgreSQL behavior, independent verification, production authorization, or conformance to this contract.

## Status boundary

This repository state defines the PAD-VER-001 verification and evidence-closure contract only. It contains no verification run, no new observation, no independent verifier result, no certificate, and no conformance claim.

PAD-VER-001 remains SPECIFICATION COMPLETE — NOT EXECUTED. Any future execution must create new append-only evidence in a separately authorized and observable environment.
