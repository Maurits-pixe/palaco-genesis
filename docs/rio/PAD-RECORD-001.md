# PAD-RECORD-001 — Append-only execution record and evidence handoff

Status: SPECIFICATION COMPLETE — TESTS IMPLEMENTED; NOT EXECUTED

Base: PAD-EXEC-001 at `f6b8d3b41a206b96fc89d1e35e54a8b080d2ec66`

PAD-RECORD-001 is the standalone record contract after PAD-EXEC-001. It defines the append-only record of declared execution state, completion, failure, uncertainty, evidence, provenance, and verification handoff.

This contract does not authorize execution, produce PAD-EXEC-COMMIT `ALLOW`, accept a first-effect handoff, release a process, create a first effect, access PostgreSQL, send a network request, mutate a fixture, authorize RUN 002, or establish conformance. Its harness tests are deterministic in-memory tests only.

## Gate sequence and constitutional boundary

The required order remains:

PAD-ENVGATE → PAD-AUTHGATE → EXEC-ENVELOPE → REVALIDATE → COMMIT → FIRST-EFFECT → EXEC → RECORD

PAD-RECORD-001 owns one bounded question:

Can the exact execution lifecycle be recorded as an append-only, provenance-bound chain while preserving the distinctions between authorization, release, effect, completion, evidence, verification, replay, failure, and uncertainty?

The record is a witness of a governed lifecycle, not the source of permission. A record may reference authorization, but it cannot create, extend, revive, or substitute for authorization. Evidence may support verification, but evidence does not become authorization by being stored.

The boundary is explicit:

`EXECUTION_RELEASED ≠ FIRST_EFFECT ≠ COMPLETION ≠ VERIFICATION`

`RECORD ≠ AUTHORIZATION`

`REPLAY ≠ NEW EXECUTION`

`EVIDENCE ≠ AUTHORITY`

`VERIFICATION ≠ FINALITY`

## Record identity and contract version

Every record must carry an immutable identity containing:

| Field | Requirement |
| --- | --- |
| `record_id` | Unique record identity; never reused |
| `run_id` | Exact attempted-run identity |
| `contract_version` | `PAD-RECORD-001` contract and schema version |
| `record_type` | Declared lifecycle or handoff record type |
| `sequence` | Monotonic append sequence within the record lineage |
| `idempotency_key` | Unique replay boundary bound to the exact run |
| `parent_record_id` | Immediate parent when the record is derived from another record |
| `previous_record_id` | Previous append-only record in the lineage |
| `previous_record_digest` | Exact digest of the previous record, when available |
| `record_digest` | Digest of the canonical current record bytes |

`record_id`, `run_id`, `contract_version`, `sequence`, and `idempotency_key` are not mutable labels. A changed identity or schema creates a new candidate record and does not overwrite the prior record.

## Required record content

The canonical record must bind at least:

- repository, implementation revision, base revision, workflow/configuration revision, and contract references;
- envelope identity and digest;
- authorization reference and digest, without treating the reference as a new authorization;
- revalidation reference and digest;
- commit decision reference and digest, including whether a gate-generated `ALLOW` existed;
- first-effect handoff reference and digest, including one-time consumption state;
- execution reference and exact lifecycle state;
- actor, target, subject, tenant, purpose, scope, allowed operations, and prohibited operations;
- environment, runtime, toolchain, service, endpoint, fixture, network, isolation, and secret references;
- input, output, resource, timeout, cancellation, and child-process boundaries;
- parent/previous lineage and sequence;
- trusted timestamps, observed timestamps, temporal sequence, and `trust_epoch`;
- evidence references, evidence state, readback state, integrity state, and missing/conflicting evidence reasons;
- failure, crash, replay, cancellation, timeout, late-effect, and uncertainty state;
- record authority basis, recorder identity, schema version, and append operation;
- next expected transition: recovery, verification, or closure.

Raw credentials, secret material, uncontrolled environment dumps, or unbounded personal data must not be recorded. Redaction must preserve material governance facts and be itself attributable.

## State model

The record must keep separate state dimensions. One field cannot silently stand in for another.

### Execution state

The execution state records what lifecycle boundary was observed:

`PREPARED → HANDOFF_ACCEPTED → EXECUTION_RELEASED → FIRST_EFFECT_OBSERVED → RUNNING → COMPLETED`

Failure, cancellation, timeout, revocation, or crash may branch from the relevant observed state. The model must never move backward by rewriting history. A crash before first effect is not equivalent to a crash after first effect.

### Completion state

Completion is a separate observation:

- `NOT_STARTED`;
- `IN_PROGRESS`;
- `COMPLETE`;
- `FAILED`;
- `UNKNOWN`.

`COMPLETE` means that the declared execution lifecycle reached an observed completion boundary. It does not prove that an external target reached the intended state.

### Verification state

Verification is independent and evidence-bound:

- `NOT_ATTEMPTED`;
- `PENDING`;
- `VERIFIED`;
- `UNVERIFIED`;
- `CONFLICTED`.

`VERIFIED` requires the declared evidence, provenance, scope, temporal, and independent-check conditions. A process exit code, stored record, or `COMPLETE` state alone cannot produce `VERIFIED`.

### Failure, crash, and uncertainty state

The record must preserve explicit reasons, including:

- crash before first effect;
- crash after first effect;
- ambiguous launch or ambiguous completion;
- timeout without proof of cancellation;
- late effect after timeout or cancellation;
- missing evidence;
- conflicting evidence;
- scope or revision drift;
- revocation or expiration;
- replay or duplicate submission;
- record-handoff failure;
- unknown completion or unknown verification.

Uncertainty is a state requiring reconstruction or human decision. It is never silently converted into `FAILED`, `SUCCEEDED`, `VERIFIED`, or authorization.

## Append-only chain and parent/previous record

Every new record must reference its immediate `parent_record_id` where it is derived from another lifecycle object, and its `previous_record_id` within the append-only chain. The previous record digest must be checked before append.

The append operation must be monotonic and durable:

1. load the exact previous record;
2. verify its identity, digest, sequence, and contract version;
3. verify that the new record preserves the immutable run, scope, authorization, and envelope bindings;
4. assign the next sequence and canonical bytes;
5. append without overwriting prior bytes;
6. read back the appended record and verify its identity and digest;
7. expose the next expected transition or an explicit hold state.

If the previous record is missing, corrupt, conflicting, or not readable after append, the result is `BLOCKED`, `UNVERIFIED`, or `CONFLICT` as applicable. No gap may be hidden by renumbering, replacement, or a new mutable summary.

## Record handoff

PAD-EXEC-001 hands the immutable execution lifecycle to PAD-RECORD-001 through an exact record reference and append boundary. The handoff must bind:

- `run_id`, envelope digest, authorization digest, revalidation digest, commit decision digest, and first-effect handoff digest;
- execution identity, command/target identity, scope, environment, service, isolation, and temporal references;
- parent/previous record identity and expected sequence;
- append destination, schema, capacity, integrity, write, and readback state;
- idempotency key and replay state;
- recorder identity and reason for the handoff.

The handoff does not authorize a new execution or a second effect. A duplicate handoff may return the same durable record reference, but it must not create a second execution, record lineage, target mutation, or evidence lineage.

## Evidence state and verification boundary

The record must distinguish:

- evidence absent;
- evidence present but incomplete;
- evidence complete and internally consistent;
- evidence conflicting across authoritative sources;
- evidence written but not readable after write;
- evidence readable but not independently verified;
- verification complete for the declared contract.

Missing evidence yields `UNVERIFIED` or `BLOCKED`. Conflicting evidence yields `CONFLICTED` or `CONFLICT`. Neither state may default to `VERIFIED`.

Evidence provenance must include source locator, source digest, observed time, recorder identity, schema/version, expected value, observed value, and any uncertainty. A hash identifies bytes; it does not by itself establish truth, authority, or conformance.

## Replay and idempotency

Replay identity is bound to at least:

`run_id + record_type + envelope_digest + execution_ref + idempotency_key + sequence`

For an exact replay, the system may return the existing durable record. It must not append a second record for the same idempotency identity or infer that a replay is a new execution. A changed scope, target, command, envelope, authority, or sequence is not an idempotent retry; it requires a new governed chain.

## Crash and uncertain lifecycle rules

The record must preserve the difference between:

| Event | Required record meaning |
| --- | --- |
| Crash before first effect | No first effect is claimed; recovery may remain uncertain about release/launch |
| Crash after first effect | First effect remains part of history; completion and outcome may be unknown |
| Crash after durable record append | Existing record is authoritative for the recorded boundary; response loss does not justify a duplicate |
| Timeout | Time boundary elapsed; cancellation and late effects require separate observation |
| Missing readback | Record durability is unverified; no closure or verification |
| Conflicting sources | Preserve both sources and enter conflict; do not choose silently |
| Recovery failure | Hold in uncertainty; do not relaunch, rewrite, or infer success |

Recovery may append observations and a new decision, but it may not rewrite a prior record from `UNKNOWN`, `CONFLICT`, `REVOKED`, `EXPIRED`, or `UNVERIFIED` to a favorable state without the declared evidence and authority path.

## Fail-closed record statuses

The record layer may use these outcomes:

- `RECORDED`: the exact record was durably appended and read back;
- `DUPLICATE`: an exact prior record or idempotency identity exists;
- `PENDING`: required lifecycle data is not complete;
- `BLOCKED`: append, readback, evidence, integrity, or source capability is unavailable;
- `UNVERIFIED`: a required record or evidence condition cannot be checked;
- `CONFLICT`: authoritative records disagree;
- `CRASH_AMBIGUOUS`: lifecycle boundary cannot be reconstructed;
- `EFFECT_OUTCOME_UNKNOWN`: an external effect may have occurred but outcome is unresolved;
- `REVOKED` / `EXPIRED`: the bound authority is no longer valid;
- `CLOSED`: the record contract is complete for its declared purpose, without implying authorization or finality.

Unknown, missing, replayed, stale, or client-supplied values never default to `RECORDED`, `CLOSED`, `VERIFIED`, or authorized.

## Required negative matrix

The record implementation and independent review must cover at least:

| Case | Required result |
| --- | --- |
| Record identity or contract version is missing | `BLOCKED` or `UNVERIFIED`; no append |
| Parent/previous record is missing or digest mismatched | `BLOCKED` or `CONFLICT`; preserve prior history |
| Scope, target, envelope, authorization, or revision drifts | `STALE`/`CONFLICT`; no silent update |
| Execution release is recorded without first effect | Preserve release only; do not claim effect |
| First effect is recorded without completion | Completion remains `IN_PROGRESS` or `UNKNOWN` |
| Completion is recorded without sufficient evidence | `UNVERIFIED`; not `VERIFIED` |
| Evidence is missing | `UNVERIFIED` or `BLOCKED` |
| Evidence conflicts | `CONFLICTED`/`CONFLICT`; never select silently |
| Crash before first effect | Preserve no-effect boundary and uncertainty |
| Crash after first effect | Preserve effect history; completion may remain unknown |
| Timeout or cancellation lacks target readback | `EFFECT_OUTCOME_UNKNOWN`; no assumed cancellation |
| Exact replay occurs | `DUPLICATE` or idempotent existing record; no second execution |
| Replay changes scope or target | New governed chain required; no idempotent reuse |
| Record readback fails | `BLOCKED`/`UNVERIFIED`; no closure |
| Record sink is not append-only | `BLOCKED`; no record handoff |
| Client supplies `verified=true`, `closed=true`, or an authority override | Ignore input; compute record state |
| Stored record is presented as authorization | `DENIED`; preserve boundary |

## Harness tests and evidence boundary

The required tests are specified in `verification/harness/PAD-RECORD-001-TESTS.md` and implemented in `crates/palaco-record/tests/pad_record_001.rs`.

They cover crash before and after first effect, replay/idempotency, scope drift, parent/previous handoff lineage, missing and conflicting evidence, and uncertain completion/verification. The test model is deterministic and in-memory. It performs no process launch, network operation, database access, fixture mutation, runtime handoff, authorization, or external observation.

Passing the harness tests proves only the tested contract model in the CI environment. It does not prove runtime behavior, PostgreSQL behavior, external truth, authority, conformance, or RUN 002 readiness.

## Current status and non-claims

PAD-RECORD-001 is `SPECIFICATION COMPLETE — TESTS IMPLEMENTED; NOT EXECUTED`.

The current observed repository state is:

| Boundary | Status |
| --- | --- |
| PAD-ENVGATE-001 | `BLOCKED` under TUR-016 |
| PAD-AUTHGATE-001 | `NOT AUTHORIZED`; no permit or approval exists |
| PAD-EXEC-ENVELOPE-001 | Specification only; no envelope instance exists |
| PAD-EXEC-REVALIDATE-001 | Specification only; no runtime revalidation performed |
| PAD-EXEC-COMMIT-001 | Merged documentation contract; no runtime `ALLOW` exists |
| PAD-EXEC-FIRST-EFFECT-001 | Merged documentation contract; no handoff token or acceptance record exists |
| PAD-EXEC-001 | Draft documentation contract; no release, launch, or execution exists |
| PAD-RECORD-001 | This contract plus pure in-memory harness tests; no runtime record exists |
| RUN 002 | `NOT AUTHORIZED` |
| Runtime, service, or PostgreSQL execution | Not executed |
| First effect | Not attempted |
| Evidence closure | Not created |
| Independent verification | Not performed |
| Conformance | Not claimed |

This contract and its tests create no authority, `ALLOW`, handoff token, release, first effect, runtime record, evidence closure, verification result, or conformance claim. PR #133 remains a separate draft review boundary. `GO-029` in PALACO-Citadel remains untouched.

The next decision is `ADVISORY — HUMAN DECISION REQUIRED`: review whether this record contract and its test evidence are sufficient for the next governed transition. No merge, release, launch, first effect, RUN 002, or PAD-AUTHGATE authorization is implied.
