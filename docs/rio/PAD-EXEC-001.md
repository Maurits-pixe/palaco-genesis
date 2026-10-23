# PAD-EXEC-001 — Governed execution boundary

Status: SPECIFICATION COMPLETE — NOT EXECUTED

Base: merged PAD-EXEC-FIRST-EFFECT-001 at `d9e2a26907369ecc18e95a38c568c98bcae57374`

PAD-EXEC-001 is the execution gate after the exact one-time handoff from PAD-EXEC-FIRST-EFFECT-001. It defines how one declared operation may be released, started, observed, stopped, and handed to the record gate without expanding authority or scope.

This contract does not currently execute a command, launch a process, mutate a fixture or database, send a network request, authorize RUN 002, create runtime evidence, verify an external effect, or establish conformance. It defines the future execution boundary only.

## Gate sequence and constitutional boundary

The required order remains:

PAD-ENVGATE → PAD-AUTHGATE → EXEC-ENVELOPE → REVALIDATE → COMMIT → FIRST-EFFECT → EXEC → RECORD

PAD-EXEC-001 owns one bounded question:

Can the exact handoff already accepted by PAD-EXEC-FIRST-EFFECT-001 release exactly one declared operation, observe its actual lifecycle, and preserve the distinction between process outcome, external effect, evidence, and independent verification?

PAD-EXEC-001 does not mint authority. It consumes the exact current handoff and applies the execution rules already bound by the envelope, authorization, revalidation, commit decision, and first-effect gate. A caller cannot supply, force, or infer a release decision.

The boundary is explicit:

`ALLOW ≠ HANDOFF_ACCEPTED ≠ EXECUTION_RELEASED ≠ FIRST_EFFECT ≠ EXECUTION_COMPLETED ≠ VERIFIED`

`EXECUTION_RELEASED` is a durable control-plane release record and is not itself an external effect or a new authorization. `FIRST_EFFECT` begins when the declared process launch or target operation has a consequence. `EXECUTION_COMPLETED` means that the execution lifecycle ended or was observed to end; it does not prove that the intended external state was achieved. `VERIFIED` requires a separate evidence-bearing verification step.

## Fail-closed execution statuses

The future gate may expose only a status backed by an attributable record:

- `PENDING`: no execution decision or lifecycle transition exists;
- `PREPARED`: read-only checks and exact input assembly are complete; nothing has started;
- `HANDOFF_VERIFIED`: the current one-time handoff is exact and usable; no effect has started;
- `EXECUTION_RELEASED`: final checks passed and the exact operation was durably released; no first effect is claimed;
- `LAUNCHED`: the process or target operation was observed to begin; the first-effect boundary has been crossed;
- `RUNNING`: the declared operation is active within its bounded lifecycle;
- `COMPLETED`: the process or operation ended or an end state was observed; external success is not implied;
- `FAILED`: the declared operation failed before a verified successful outcome;
- `CANCELLED`: execution was stopped under a recorded cancellation decision;
- `TIMED_OUT`: the declared time boundary elapsed; late effects must be reconstructed, not assumed absent;
- `EFFECT_OUTCOME_UNKNOWN`: an external consequence may have occurred but cannot yet be determined;
- `CRASH_AMBIGUOUS`: the durable state cannot distinguish release, launch, or effect outcome after failure;
- `BLOCKED`: a required authority, environment, service, lock, record path, or isolation capability is unavailable;
- `STALE`: an exact digest, revision, target, environment, service, or temporal binding changed;
- `REVOKED`: authority, consent, credential, mandate, or permit state was withdrawn;
- `EXPIRED`: a validity or execution window ended;
- `DENIED`: policy, identity, scope, target, or effect rules reject release;
- `UNVERIFIED`: a required binding, observation, readback, or lifecycle record cannot be independently checked;
- `CONFLICT`: authoritative inputs disagree without a governing precedence rule;
- `DUPLICATE`: a prior release or execution attempt for the exact idempotency identity already exists.

Unknown, missing, ambiguous, client-supplied, stale, replayed, or unverifiable values never default to `EXECUTION_RELEASED`, `LAUNCHED`, `COMPLETED`, or `VERIFIED`.

## Exact execution inputs

The gate must independently obtain and bind the following exact inputs:

| Input | Required binding |
| --- | --- |
| `run_id` | Unique attempted-run identity |
| `envelope_id` / `envelope_digest` | Exact canonical frozen execution envelope |
| `authorization_ref` / `authorization_digest` | Current authorization identity and digest |
| `revalidation_ref` / `revalidation_digest` | Current revalidation identity, state, and digest |
| `commit_id` / `commit_decision_digest` | PAD-EXEC-COMMIT decision record and digest |
| `commit_state` | Gate-generated current `ALLOW`; never caller supplied |
| `handoff_ref` / `handoff_digest` | PAD-EXEC-FIRST-EFFECT handoff and one-time consumption state |
| `implementation_revision` | Exact implementation commit SHA |
| `base_revision` | Exact base and dependency commit SHA |
| `workflow_revision` | Exact workflow and configuration revision |
| `command_digest` | Executable identity, command bytes, arguments, and invocation schema |
| `workspace_ref` | Exact working directory, workspace, fixture, and file-state binding |
| `runtime_ref` | Exact runtime, interpreter, toolchain, image, and launcher identity |
| `environment_ref` | Current environment identity and readiness state |
| `service_ref` / `endpoint_ref` | Exact service, endpoint, tenant, protocol, and network binding |
| `input_ref` | Immutable stdin, request, fixture, or input digest |
| `output_policy` | Allowed stdout/stderr, artifact, and observation destinations |
| `resource_policy` | Timeout, CPU, memory, process, file, network, and rate boundaries |
| `secret_ref` | Opaque credential references and permitted exposure boundary; never raw secrets in evidence |
| `scope_ref` | Exact actor, target, subject, tenant, purpose, allowed and prohibited operations |
| `temporal_ref` | Trusted time, sequence, `trust_epoch`, validity, revocation, and expiry |
| `isolation_ref` | Process, workspace, network, credential, secret, and cross-run boundaries |
| `evidence_ref` | Append-only destination, capacity, integrity, write, and readback boundary |
| `idempotency_ref` | Unique key, nonce, prior release, prior attempt, and prior-effect state |
| `record_ref` | PAD-RECORD-001 destination and schema readiness |
| `ruleset_ref` | Exact execution policy, lifecycle schema, and decision version |

A mutable branch or tag, `latest` image, uncontrolled shell expansion, wildcard environment input, cached token, old CI result, process exit code without lifecycle binding, or database row without the declared digests is insufficient.

## What counts as execution and first effect

Read-only preparation may include digest recomputation, command validation, revision comparison, authorization and revocation lookup, scope comparison, service discovery, capability inspection, resource calculation, and record-destination checks.

The first effect begins at the earliest consequential operation within the declared run, including:

- launching the process when process launch can have a consequence;
- writing or mutating a fixture, file, database, ledger, event, or service;
- sending a network request or external message;
- creating a durable execution observation or evidence artifact;
- changing authority, consent, tenant, subject, project, world, resource, or other governed state;
- any operation outside the exact envelope or authorized scope.

`EXECUTION_RELEASED` must be durably recorded before that boundary. The release record is a control-plane decision, not execution evidence. `LAUNCHED` or the equivalent first-effect state may be recorded only after the launch or target operation has actually been attempted or observed.

The gate must never describe preparation, a successful spawn call, a zero exit code, a stored row, or a timeout as proof that the intended external effect occurred. External effect and outcome require evidence and, where applicable, independent verification.

## Preconditions for `EXECUTION_RELEASED`

The gate must prove every condition below:

1. PAD-ENVGATE is current `READY` for the exact environment; the current repository state is not that condition.
2. PAD-AUTHGATE is current, valid, unrevoked, unexpired, and within the exact declared scope.
3. PAD-EXEC-ENVELOPE is canonical, frozen, exact, and digest-recomputable.
4. PAD-EXEC-REVALIDATE is current and matches the exact envelope digest.
5. PAD-EXEC-COMMIT produced a durable, attributable `ALLOW` for this exact run.
6. PAD-EXEC-FIRST-EFFECT produced a durable, exact, unconsumed `HANDOFF_ACCEPTED` for this exact run and operation.
7. Implementation, head, base, workflow, contract, test-pack, fixture, runtime, toolchain, environment, service, endpoint, and network references match exactly.
8. The command, executable, arguments, working directory, input, output policy, resource limits, and secret references match the frozen envelope.
9. Actor, target, subject, tenant, purpose, allowed operations, and prohibited operations match without scope expansion.
10. Trusted time, monotonic sequence, `trust_epoch`, validity, revocation, and expiration checks pass.
11. Isolation, credential, secret, network, process, workspace, and cross-run boundaries are enforceable.
12. The record destination is append-only, writable, readable after write, capacity-checked, and integrity-bound before launch.
13. The execution lock and idempotency boundary can prevent duplicate release, duplicate launch, and duplicate evidence lineage.
14. No previous release, attempt, first effect, target mutation, or unresolved outcome exists for this exact idempotency identity.
15. PAD-RECORD-001 or its declared record path is present and ready to receive the lifecycle and evidence record.
16. No higher-priority `BLOCKED`, `STALE`, `REVOKED`, `EXPIRED`, `DENIED`, `UNVERIFIED`, or `CONFLICT` state exists.
17. The designated execution gate authority, not the caller, produces the release result.

If one condition cannot be proven, no execution release exists and no first effect may occur.

## Final-check and release sequence

The final checks must occur immediately before release inside one exclusive lock, transaction, or equivalent compare-and-swap boundary:

1. Load the exact durable commit `ALLOW` and first-effect `HANDOFF_ACCEPTED` records.
2. Acquire the run/execution/idempotency lock and verify that no prior attempt or effect exists.
3. Re-check authorization, revocation, expiration, trusted time, `trust_epoch`, sequence, scope, target, revisions, environment, service, endpoint, toolchain, isolation, secrets, resource limits, and record readiness.
4. Recompute and compare all envelope, command, handoff, input, runtime, and configuration digests.
5. Verify that the operation is exactly the declared first effect and does not contain an implicit second operation, hidden network path, uncontrolled child process, or scope expansion.
6. Append and durably persist `EXECUTION_RELEASED` with the exact command, target, policy, identity, authority basis, and expected next state.
7. Transfer the operation to the bounded launcher exactly once.
8. Record `LAUNCHED` or the appropriate pre-launch failure immediately from the observed launcher result; never pre-write a successful launch.
9. Monitor only the declared lifecycle and resource boundaries.
10. Record the observed terminal state and hand the immutable lifecycle record to PAD-RECORD-001.

If any value changes before step 6, the gate must fail closed. If a value changes after step 6, the launcher must stop or hold according to the declared safety policy; the old release is not permission for a changed operation.

## One-time execution and replay rules

The execution identity is bound to at least:

`run_id + envelope_digest + handoff_digest + command_digest + target_ref + idempotency_key + execution_sequence`

The identity is single-use. A duplicate request may return the same durable lifecycle record or `DUPLICATE`; it must never launch a second process, repeat a target mutation, resend a network request, or create a second evidence lineage.

Retries cannot change the command, arguments, target, scope, environment, resource policy, credentials, or endpoint. A changed operation requires a new envelope, authorization, revalidation, commit decision, and first-effect handoff.

Cancellation, timeout, restart, or operator retry does not prove that a process or external effect ended. The gate must reconstruct the process and target state before any recovery action. If reconstruction is impossible, the state is `CRASH_AMBIGUOUS` or `EFFECT_OUTCOME_UNKNOWN` and execution remains held.

## Crash, timeout, and outcome ambiguity

The lifecycle must distinguish at least:

- release durable, launch not attempted;
- launch attempted, launch result unknown;
- process started, process outcome unknown;
- process ended, external effect unknown;
- external effect observed, evidence incomplete;
- evidence complete, independent verification pending;
- independently verified result.

After a crash or lost response:

- never assume `LAUNCHED`, `COMPLETED`, or `FAILED` from absence of a response;
- never re-launch merely because the launcher response was lost;
- reconstruct durable release, process identity, child-process state, target state, and evidence lineage;
- use `CRASH_AMBIGUOUS` or `EFFECT_OUTCOME_UNKNOWN` until reconstruction resolves the state;
- preserve the original record and append recovery observations; do not rewrite history.

A timeout is a boundary event, not proof of cancellation. Late target effects must be detected and recorded. A zero exit code is only an observed process result unless the declared external outcome is independently bound and verified.

## Evidence and handoff to record

PAD-EXEC-001 must produce provenance-bearing lifecycle data for PAD-RECORD-001, including:

- exact source references and digests;
- release decision, authority basis, rule version, and decision time;
- command, executable, arguments, runtime, workspace, input, output, resource, network, and secret bindings;
- process identity, start/stop observations, exit status, signals, timeout state, and child-process state;
- target requests, responses, mutations, external-effect identifiers, and outcome uncertainty;
- isolation, credential, service, endpoint, and cross-run observations;
- failure, cancellation, crash, replay, recovery, and ambiguity records;
- append-only record digest, sequence, `trust_epoch`, and relation to prior decisions;
- explicit next state: PAD-RECORD-001, independent verification, or held recovery.

Raw credentials, secret material, uncontrolled environment dumps, or unbounded personal data must not enter the record. Redaction must be deterministic, attributable, and incapable of hiding a material governance fact.

The execution record is not automatically proof of external truth, success, finality, conformance, or authorization. Missing logs, missing artifacts, absent database rows, or a successful process exit cannot be inferred as evidence.

## Required negative matrix

The future implementation and independent review must cover at least:

| Case | Required result |
| --- | --- |
| No durable PAD-EXEC-COMMIT `ALLOW` | `BLOCKED` or `DENIED`; no release |
| No exact current `HANDOFF_ACCEPTED` | `BLOCKED` or `UNVERIFIED`; no release |
| Authorization, revalidation, or handoff is stale, revoked, expired, or out of scope | `STALE`, `REVOKED`, `EXPIRED`, or `DENIED` |
| Envelope, command, input, runtime, handoff, or configuration digest differs | `UNVERIFIED` or `STALE`; no launch |
| Implementation head, base, workflow, fixture, service, endpoint, or toolchain drifts | `STALE`; no launch |
| Scope, target, tenant, purpose, or operation expands or changes | `DENIED`; new authorization chain required |
| Environment or isolation is not current and enforceable | `BLOCKED`; no release |
| Secret exposure, uncontrolled environment, child process, or network path is detected | `BLOCKED`; no release |
| Record destination is missing, not writable, not readable, or not append-only | `BLOCKED`; no release |
| PAD-RECORD-001 or the declared record path is unavailable | `BLOCKED`; no launch |
| Execution lock or idempotency boundary fails | `BLOCKED`; no release |
| Prior release, prior attempt, prior effect, or unresolved outcome exists | `DUPLICATE` or `BLOCKED`; no second launch |
| Launcher returns an ambiguous result or crashes | `CRASH_AMBIGUOUS`; reconstruct before retry |
| Timeout occurs before or after launch | `TIMED_OUT` or `EFFECT_OUTCOME_UNKNOWN`; no assumed cancellation |
| Process exits zero but target outcome is not independently observed | `COMPLETED`/`UNVERIFIED`; not `VERIFIED` |
| External effect is outside the exact envelope or scope | `DENIED`; preserve evidence and history |
| Cancellation or revocation occurs during release or execution | `REVOKED`/`CANCELLED`; apply declared stop and recovery policy |
| Client supplies `execute=true`, `allow=true`, or an equivalent override | Ignore input; compute the gate result |
| PostgreSQL COMMIT or storage success is presented as execution authorization | `DENIED`; preserve constitutional boundary |

## Current state and non-claims

PAD-EXEC-001 remains `SPECIFICATION COMPLETE — NOT EXECUTED`.

The current observed repository state is:

| Boundary | Status |
| --- | --- |
| PAD-ENVGATE-001 | `BLOCKED` under TUR-016 |
| PAD-AUTHGATE-001 | `NOT AUTHORIZED`; no permit or approval exists |
| PAD-EXEC-ENVELOPE-001 | Specification only; no envelope instance exists |
| PAD-EXEC-REVALIDATE-001 | Specification only; no runtime revalidation performed |
| PAD-EXEC-COMMIT-001 | Merged documentation contract; no runtime `ALLOW` exists |
| PAD-EXEC-FIRST-EFFECT-001 | Merged documentation contract; no handoff token or acceptance record exists |
| PAD-EXEC-001 | This specification only; no release, launch, or execution exists |
| PAD-RECORD-001 | Not opened |
| RUN 002 | `NOT AUTHORIZED` |
| Runtime, service, or PostgreSQL execution | Not executed |
| First effect | Not attempted |
| Observation and evidence | Not created |
| Independent verification | Not performed |
| Conformance | Not claimed |

The merge of PRs #128 and #129 is repository history, not runtime authority, execution permission, evidence, or conformance. This document creates no authorization, `ALLOW`, handoff token, release record, first effect, runtime result, evidence closure, or verification result. `GO-029` in PALACO-Citadel remains untouched.

The next valid contract boundary is `PAD-RECORD-001`. It may be opened only as a documentation or implementation decision after the execution contract is reviewed; it does not authorize RUN 002. Any actual execution still requires a fresh valid authority chain, current environment readiness, exact handoff, and separate human/governance authorization.
