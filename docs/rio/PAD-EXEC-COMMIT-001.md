# PAD-EXEC-COMMIT-001 — Execution acceptance and first-effect commit gate

Status: SPECIFICATION COMPLETE — NOT EXECUTED

Base: PAD-EXEC-REVALIDATE-001 at e44c61d796826e3448ced4f56a3868b81db4dd09

PAD-EXEC-COMMIT-001 is the fifth gate in the execution sequence and the last gate before a future first execution effect. It makes the explicit decision whether one exact, revalidated envelope may be durably accepted for handoff to PAD-EXEC-FIRST-EFFECT-001.

This contract does not execute a command, mutate a fixture, open PostgreSQL, send a network request, create a test observation, close evidence, authorize RUN 002, or establish conformance. It defines the acceptance boundary only.

## Gate sequence and constitutional boundary

The required order remains:

PAD-ENVGATE → PAD-AUTHGATE → EXEC-ENVELOPE → REVALIDATE → COMMIT → FIRST-EFFECT → EXEC → RECORD

PAD-EXEC-COMMIT owns one bounded question:

Has the exact revalidated run been atomically accepted, with current authority, scope, revision, temporal trust, isolation, idempotency, and evidence readiness, so that the separately governed first-effect gate may evaluate it?

The only positive decision is ALLOW. ALLOW opens only PAD-EXEC-FIRST-EFFECT-001. It does not itself execute a command or create the first external effect.

The PALACO execution commit gate is not the same as a database transaction or PostgreSQL COMMIT. A storage commit may persist a decision; it cannot create constitutional permission by itself.

## Commit decisions

The gate is fail-closed:

- ALLOW: the exact run is durably accepted for the next first-effect gate;
- DENY: policy, authority, scope, identity, or effect rules reject acceptance;
- HOLD: a human or governance decision is required; no effect is permitted;
- BLOCKED: a required source, service, storage, lock, temporal proof, or evidence capability is unavailable;
- STALE: the envelope, revalidation, revision, environment, or authority state no longer matches;
- REVOKED: authority, credential, consent, mandate, or permit state is withdrawn;
- EXPIRED: the validity window has ended;
- UNVERIFIED: the decision or binding cannot be independently checked;
- CONFLICT: two authoritative inputs disagree and no precedence rule resolves the disagreement.

Only ALLOW may be handed to PAD-EXEC-FIRST-EFFECT-001. Unknown, missing, ambiguous, client-supplied, stale, or unverifiable values never default to ALLOW.

## Required exact inputs

The commit gate must receive and independently verify:

| Input | Required binding |
| --- | --- |
| run_id | Unique attempted-run identity |
| envelope_id | Exact envelope identity |
| envelope_digest | Recomputed digest of canonical frozen bytes |
| authorization_ref | Authorization identity and digest |
| revalidation_ref | Revalidation identity, status, and digest |
| handoff_ref | Exact commit-handoff token or equivalent binding |
| implementation_revision | Exact implementation commit SHA |
| base_revision | Exact base/dependency commit SHA |
| workflow_revision | Exact workflow and configuration revision |
| test_pack | Immutable test-pack identity and digest |
| fixture_manifest | Immutable fixture identity and digest |
| environment_ref | Current environment identity and readiness reference |
| scope_ref | Actor, target, subject, tenant, purpose, and prohibited operations |
| temporal_ref | Trusted time, sequence, trust_epoch, validity, revoke, and expiry |
| isolation_ref | Process, workspace, network, credential, secret, and cross-run boundary |
| evidence_ref | Append-only destination, readback, capacity, and integrity boundary |
| idempotency_ref | Uniqueness, replay, nonce, and prior-effect state |
| commit_ruleset | Exact gate policy and decision version |

The gate must not accept a rendered summary, branch name without SHA, prior CI result, client-provided ALLOW flag, or database row without the declared digest bindings.

## Preconditions for ALLOW

ALLOW requires every condition below:

1. PAD-ENVGATE is current READY for the exact declared environment.
2. PAD-AUTHGATE has a current, valid, unrevoked, unexpired authorization.
3. The scope is unchanged and remains within the authorized least-privilege boundary.
4. PAD-EXEC-ENVELOPE is exact, canonical, frozen, and digest-recomputable.
5. PAD-EXEC-REVALIDATE is REVALIDATED against that exact envelope digest.
6. The handoff token is authentic, unique, current, and names this gate as the next gate.
7. Repository, head, base, workflow, contract, test-pack, fixture, service, and toolchain identities match.
8. Trusted time, sequence, trust_epoch, validity, revocation, and expiration checks pass.
9. Replay, idempotency, prior-run, prior-commit, and prior-effect checks pass.
10. Isolation, network, credential, secret, service, and external-effect boundaries match.
11. Evidence storage is append-only, writable, readable after write, failure-atomic, and sufficient for the declared record set.
12. The commit record and acceptance state can be persisted atomically.
13. No higher-priority DENY, HOLD, REVOKED, EXPIRED, BLOCKED, STALE, UNVERIFIED, or CONFLICT state exists.
14. The designated commit authority, not the client, produces the ALLOW decision.

If one condition cannot be proven, the decision is not ALLOW.

## No client-supplied ALLOW

The caller may submit a request and the exact declared references. The caller may not supply, force, override, replay, or infer the commit decision.

The following are never sufficient to produce ALLOW:

- a request field such as allow=true;
- a successful login or repository permission;
- a RIO message, recommendation, event, or automation result;
- a green CI workflow;
- a prior authorization without current revalidation;
- a database COMMIT;
- a human-readable approval without the bound decision record;
- a branch name, tag, or mutable environment label;
- an old handoff token or cached revalidation.

The commit authority must compute the decision from current bound inputs and append the decision before handing off. Implementation code cannot self-authorize.

## Atomic acceptance record

When ALLOW is possible, the gate must atomically persist an append-only acceptance record containing:

- commit_id and decision sequence;
- run_id, envelope_id, envelope_digest, and envelope schema version;
- authorization_id and authorization digest;
- revalidation_id, revalidation digest, and handoff-token digest;
- exact repository, implementation, base, workflow, contract, test-pack, fixture, service, and toolchain references;
- actor, target, subject, tenant, purpose, scope, and prohibited operations;
- temporal state, sequence, trust_epoch, validity, expiration, and revocation state;
- isolation, network, credential, secret, external-effect, and evidence boundaries;
- idempotency key, nonce, prior-run result, and replay state;
- decision status, ruleset version, authority identity, and decision reason;
- append-only record bytes and acceptance digest;
- expected next gate: PAD-EXEC-FIRST-EFFECT-001.

The acceptance record must be durable before ALLOW is handed off. It must not contain a command result or claim that a first effect already occurred.

## Atomic failure and crash ambiguity

The commit operation must define its crash behavior:

- if persistence fails before durable acceptance, no accepted run, ALLOW handoff, or first effect exists;
- if the outcome is ambiguous, the system must reconstruct the durable acceptance record before allowing any effect;
- an ambiguous result must not be treated as ALLOW by timeout, retry, client assumption, or process restart;
- duplicate submission for the same exact idempotency key may return the same durable decision;
- duplicate submission must not create a second acceptance, first effect, or evidence lineage;
- a failed or denied commit remains an append-only decision record;
- recovery may reconstruct state but may not rewrite a DENY, HOLD, REVOKED, EXPIRED, or historical record as ALLOW.

The gate must preserve the distinction between:

accepted and durable;
accepted but not yet first-effected;
first effect attempted;
first effect durable;
first effect outcome unknown.

This contract does not claim that any of these states currently exists.

## First-effect boundary

The first effect is any operation that can change governed state or cause an external consequence, including:

- starting the declared execution command when process launch is itself consequential;
- writing or mutating a fixture, database, ledger, event, file, or service;
- sending a network request or external message;
- creating a durable observation or evidence side effect;
- changing authority, consent, tenant, subject, project, world, or resource state.

No first effect may occur before:

1. PAD-EXEC-COMMIT produces durable ALLOW;
2. the acceptance record names PAD-EXEC-FIRST-EFFECT-001;
3. the first-effect gate performs its own current checks;
4. the exact one-time handoff is accepted by that gate.

PAD-EXEC-COMMIT does not pre-authorize effects outside the envelope. It only accepts the exact declared transition to the next gate.

## Temporal, revocation, and scope finality

Immediately before durable acceptance, the gate must re-check:

- highest accepted trusted time;
- monotonic sequence and trust_epoch;
- authorization validity and expiration;
- revocation, consent, delegation, and credential state;
- exact actor, target, subject, tenant, project, world, and purpose;
- scope and prohibited operations;
- implementation, base, workflow, environment, fixture, service, and evidence bindings.

Terminal REVOKED and EXPIRED states cannot be revived by clock rollback, old snapshots, restored databases, branch resets, cache replay, or later client input. Scope expansion, revision conflict, endpoint substitution, or evidence-boundary change produces DENY, STALE, or BLOCKED.

## Commit-lock and TOCTOU boundary

The commit gate must operate within the declared acceptance boundary:

1. obtain the exact REVALIDATED handoff;
2. acquire the run/idempotency lock or equivalent exclusive boundary;
3. re-check revocation, expiration, envelope_digest, revision, sequence, scope, evidence readiness, and prior effects;
4. compute ALLOW/DENY/HOLD/BLOCKED;
5. append and durably persist the decision and acceptance record atomically;
6. release or transfer the one-time handoff to PAD-EXEC-FIRST-EFFECT-001.

If any value changes before durable acceptance, no ALLOW is produced. If a value changes after durable acceptance, PAD-EXEC-FIRST-EFFECT-001 must detect the mismatch and fail closed; it may not treat the old acceptance as an unconditional command.

The lock or transaction does not make a PostgreSQL operation into the PALACO commit gate. The constitutional decision remains attributable to the designated gate authority.

## Evidence and provenance

The commit decision is a provenance-bearing governance record, not execution evidence. It must preserve:

- exact source records and digests;
- expected and observed binding values;
- decision actor and authority basis;
- ruleset and schema version;
- timestamps, sequence, trust_epoch, and source locators;
- failure reason or ALLOW rationale;
- relation to any superseded, denied, held, revoked, or expired decision.

No missing log, artifact, database row, or digest may be inferred as proof of ALLOW, durability, execution, or conformance.

## Required negative matrix

The future commit-gate implementation and independent review must cover at least:

| Case | Required result |
| --- | --- |
| PAD-ENVGATE is BLOCKED or not current READY | BLOCKED; no ALLOW |
| PAD-AUTHGATE is absent, revoked, expired, stale, or out of scope | DENY, REVOKED, EXPIRED, or STALE |
| Envelope is not exact, frozen, or digest-recomputable | DENY or UNVERIFIED |
| Revalidation is absent, stale, or mismatched | BLOCKED or STALE |
| Repository, head, base, workflow, test-pack, fixture, or service differs | STALE; no substitution |
| Scope expands or target changes | DENY; new authorization required |
| Revocation or expiration changes during commit | REVOKED or EXPIRED; no acceptance |
| Trusted time rolls back or trust_epoch decreases | BLOCKED or UNVERIFIED |
| Evidence destination cannot append/read back atomically | BLOCKED |
| Idempotency key or run_id was already accepted | Idempotent read or DENY; no second effect |
| Prior first effect exists for the run | DENY; preserve history |
| Commit lock cannot be acquired | BLOCKED; no ALLOW |
| Final check differs inside the lock | STALE; no acceptance |
| Client supplies allow=true or equivalent | Ignore input; compute gate decision |
| PostgreSQL COMMIT is presented as PALACO ALLOW | DENY; preserve boundary |
| Durable result is ambiguous after crash | HOLD/BLOCKED; reconstruct before handoff |
| ALLOW exists but first-effect gate is absent | No execution; no first effect |

## Current status and non-claims

PAD-EXEC-COMMIT-001 remains SPECIFICATION COMPLETE — NOT EXECUTED.

The current repository state is:

| Boundary | Status |
| --- | --- |
| PAD-ENVGATE-001 | BLOCKED under TUR-016 |
| PAD-AUTHGATE-001 | NOT AUTHORIZED; no permit or approval exists |
| PAD-EXEC-ENVELOPE-001 | SPECIFICATION ONLY; no envelope instance exists |
| PAD-EXEC-REVALIDATE-001 | SPECIFICATION ONLY; no revalidation performed |
| PAD-EXEC-COMMIT-001 | SPECIFICATION ONLY; no ALLOW/DENY decision performed |
| PAD-EXEC-FIRST-EFFECT-001 | NOT OPENED |
| RUN 002 | NOT AUTHORIZED |
| Runtime/service/PostgreSQL execution | NOT EXECUTED |
| Observation/evidence/verification | NOT CREATED |
| Conformance | NOT CLAIMED |

Repository CI and external PR merges do not constitute commit-gate ALLOW, first-effect permission, runtime execution, evidence, or conformance. This document creates no acceptance record and no authorization.

The next valid contract boundary is PAD-EXEC-FIRST-EFFECT-001. No first effect may occur before a fresh, durable, attributable ALLOW and a separate first-effect gate decision.
