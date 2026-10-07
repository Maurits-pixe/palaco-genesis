# PAD-EXEC-FIRST-EFFECT-001 — One-time first-effect handoff gate

Status: SPECIFICATION COMPLETE — NOT EXECUTED

Base: PAD-EXEC-COMMIT-001 at `08b923a9d21fbd2cc6b5f3bbec5eb4ee31de45fc`

PAD-EXEC-FIRST-EFFECT-001 is the final control-plane gate before a governed first effect. It accepts one exact, current, one-time handoff from PAD-EXEC-COMMIT-001 and records whether the next execution gate may receive that handoff.

This contract does not grant authority, create a permit, produce PAD-EXEC-COMMIT ALLOW, launch a process, mutate a fixture or database, send a network request, write execution evidence, authorize RUN 002, or establish conformance. It defines the handoff boundary only.

## Gate sequence and constitutional boundary

The required order remains:

PAD-ENVGATE → PAD-AUTHGATE → EXEC-ENVELOPE → REVALIDATE → COMMIT → FIRST-EFFECT → EXEC → RECORD

PAD-EXEC-FIRST-EFFECT-001 owns one bounded question:

Can the exact, currently authorized and revalidated PAD-EXEC-COMMIT ALLOW be accepted exactly once for transfer to PAD-EXEC-001, with no scope, revision, environment, service, isolation, evidence, or temporal drift?

The only positive result is `HANDOFF_ACCEPTED`. It is a one-time transition record, not a new authorization and not permission to perform an external effect. PAD-EXEC-001 must remain separately governed and must enforce the declared first-effect boundary.

The boundary is explicit:

`ALLOW ≠ HANDOFF_ACCEPTED ≠ FIRST_EFFECT ≠ EXECUTION ≠ VERIFIED`

Repository CI, a merged documentation PR, a branch reference, a human-readable approval, or a database transaction cannot substitute for any of these states.

## Fail-closed statuses

The gate may expose only a status backed by an attributable record:

- `PENDING`: no final handoff decision has been made;
- `PREPARED`: read-only checks and input assembly are complete; no handoff is accepted;
- `HANDOFF_ACCEPTED`: the exact one-time token was atomically accepted for PAD-EXEC-001; no external first effect is claimed;
- `BLOCKED`: a required source, lock, service, environment, toolchain, evidence, or control-plane capability is unavailable;
- `STALE`: an exact revision, digest, environment, workflow, service, or temporal binding changed;
- `REVOKED`: authority, consent, credential, mandate, or permit state was withdrawn;
- `EXPIRED`: an authorization, handoff, or validity window ended;
- `DENIED`: policy, identity, scope, target, or effect rules reject the handoff;
- `UNVERIFIED`: a required binding, record, readback, or decision cannot be independently checked;
- `CONFLICT`: authoritative inputs disagree without a governing precedence rule;
- `CONSUMED`: a previously accepted token was presented again; no second handoff or effect is permitted;
- `FAILED`: the handoff attempt failed after the final checks; recovery must reconstruct the durable state before retry.

Unknown, missing, ambiguous, client-supplied, stale, replayed, or unverifiable values never default to `HANDOFF_ACCEPTED`.

## Exact required inputs

The gate must independently obtain and verify the following exact bindings:

| Input | Required binding |
| --- | --- |
| `run_id` | Unique attempted-run identity |
| `envelope_id` / `envelope_digest` | Exact canonical frozen envelope and recomputed digest |
| `authorization_ref` / `authorization_digest` | Current authorization identity and digest |
| `revalidation_ref` / `revalidation_digest` | Current revalidation identity, state, and digest |
| `commit_id` / `commit_decision_digest` | PAD-EXEC-COMMIT decision record and exact digest |
| `commit_state` | Gate-generated `ALLOW`, current and attributable; never client supplied |
| `implementation_revision` | Exact implementation commit SHA |
| `base_revision` | Exact base and dependency commit SHA |
| `workflow_revision` | Exact workflow and configuration revision |
| `test_pack` | Immutable test-pack identity and digest |
| `fixture_manifest` | Immutable fixture identity and digest |
| `service_ref` / `endpoint_ref` | Exact service, endpoint, tenant, and protocol binding |
| `environment_ref` / `toolchain_ref` | Current environment, toolchain, and readiness identity |
| `scope_ref` | Exact actor, target, subject, tenant, purpose, allowed and prohibited operations |
| `temporal_ref` | Trusted time, sequence, `trust_epoch`, validity, revocation, and expiry |
| `isolation_ref` | Process, workspace, network, credential, secret, and cross-run boundaries |
| `evidence_ref` | Append-only destination, capacity, integrity, write, and readback boundary |
| `idempotency_ref` | Unique key, nonce, prior-run, prior-handoff, and prior-effect state |
| `handoff_token` | Unique token bound to this run, envelope, commit, gate, and next gate |
| `first_effect_ref` | Declared first effect, target, and downstream execution-gate identity |
| `ruleset_ref` | Exact first-effect gate policy and schema version |

A rendered summary, mutable branch or tag, prior CI result, cached revalidation, client-provided status, or database row without the declared digest bindings is insufficient.

## Preparation versus first effect

Preparation is limited to read-only inspection and deterministic assembly of the exact inputs. Examples are digest recomputation, revision comparison, authorization lookup, revocation lookup, scope comparison, service discovery, lock capability inspection, and evidence-destination capability checks.

The gate may create a control-plane decision record and atomically consume the handoff token as the boundary operation. That record is not an execution observation, target mutation, fixture mutation, service request, or first-effect evidence. It must not be treated as permission to perform any other write. If the control-plane store cannot make this distinction and its write is itself within the declared governed effect, the gate must return `BLOCKED`.

The following are first effects when they are consequential within the declared run:

- launching the declared process when process launch itself has a consequence;
- writing or mutating a fixture, database, ledger, file, event, or service;
- sending a network request or external message;
- creating a durable execution observation or evidence artifact;
- changing authority, consent, tenant, subject, project, world, resource, or other governed state;
- any external effect not declared in the exact envelope and scope.

No such first effect may occur before `HANDOFF_ACCEPTED` has been durably recorded and the downstream PAD-EXEC-001 gate has independently accepted the exact handoff.

## Preconditions for `HANDOFF_ACCEPTED`

The gate must prove every condition below:

1. PAD-EXEC-COMMIT produced a durable, attributable, current `ALLOW` for this exact `run_id`.
2. The commit decision, envelope, authorization, and revalidation digests match the supplied immutable records.
3. PAD-AUTHGATE authority is current, valid, unrevoked, unexpired, and within the exact scope.
4. PAD-ENVGATE is current `READY` for the exact declared environment; a blocked or unknown environment fails closed.
5. The implementation, head, base, workflow, contract, test-pack, fixture, service, endpoint, environment, and toolchain references match exactly.
6. Actor, target, subject, tenant, purpose, allowed operations, and prohibited operations match without scope expansion.
7. Trusted time, monotonic sequence, `trust_epoch`, validity, revocation, and expiration checks pass.
8. The isolation, network, credential, secret, and cross-run boundaries match the envelope and authorization.
9. The evidence destination is append-only, writable, readable after write, capacity-checked, and integrity-bound; a failed capability check is not proof of evidence.
10. The nonce, idempotency key, `run_id`, commit decision, and handoff token have no prior consumption or first effect.
11. The declared downstream PAD-EXEC-001 identity is present and exact; a missing first-effect or execution gate blocks the transition.
12. No higher-priority `DENIED`, `BLOCKED`, `STALE`, `REVOKED`, `EXPIRED`, `UNVERIFIED`, or `CONFLICT` state exists.
13. The designated gate authority, not the caller, produces `HANDOFF_ACCEPTED`.

If one condition cannot be proven, no positive handoff result exists.

## Final checks and one-time consumption

The final checks must run immediately before the handoff is accepted, within one exclusive lock, transaction, or equivalent compare-and-swap boundary:

1. Load the exact durable commit `ALLOW` and all bound digests.
2. Acquire the run/idempotency lock and verify that the token is unused.
3. Re-check authorization, revocation, expiration, trusted time, `trust_epoch`, sequence, scope, target, revision, environment, service, endpoint, toolchain, isolation, secrets, evidence readiness, and prior-effect state.
4. Compare the expected `handoff_token` digest with the observed token and bind it to the exact `run_id`, envelope, commit, current gate, and next gate.
5. Atomically consume the unique token and append the attributable `HANDOFF_ACCEPTED` record.
6. Release or transfer the accepted handoff to PAD-EXEC-001 without changing its declared scope.

The token is single-use. A duplicate or replay must produce `CONSUMED`, `DENIED`, or an idempotent reference to the same durable handoff record; it must never create a second handoff, first effect, execution, or evidence lineage. A token cannot be reused with a different run, envelope, commit, target, scope, revision, or downstream gate.

## TOCTOU, failure, and crash ambiguity

If any binding changes before token consumption, the gate must produce `STALE`, `REVOKED`, `EXPIRED`, `BLOCKED`, or `DENIED` as applicable, and no first effect may occur.

If the handoff result is ambiguous after a crash, timeout, lost response, lock failure, or storage error:

- do not assume `HANDOFF_ACCEPTED`;
- do not retry by creating a new token or changing the idempotency key;
- reconstruct the durable handoff record and token-consumption state;
- return `HOLD`, `BLOCKED`, `FAILED`, or an idempotent reference only after reconstruction;
- never infer permission from process exit, connection loss, a partial log, or a client assumption.

If token consumption is not durably recorded, no downstream execution may proceed. If it is durably recorded but the response is lost, the same exact record may be returned without a second transition. Recovery may not rewrite a denial, hold, revocation, expiry, stale state, or historical record as an accepted handoff.

## Required negative matrix

The implementation and independent review must cover at least:

| Case | Required result |
| --- | --- |
| No durable PAD-EXEC-COMMIT `ALLOW` | `DENIED` or `BLOCKED`; no handoff |
| Authorization is stale, revoked, expired, missing, or out of scope | `STALE`, `REVOKED`, `EXPIRED`, or `DENIED` |
| Envelope, authorization, revalidation, commit, or handoff digest mismatch | `UNVERIFIED` or `DENIED`; no substitution |
| Actor, target, tenant, purpose, or scope expands or changes | `DENIED`; new authorization required |
| Implementation head, base, workflow, contract, test-pack, or fixture drifts | `STALE`; no handoff |
| Environment, toolchain, service, endpoint, or isolation drifts | `BLOCKED` or `STALE`; no handoff |
| Nonce, idempotency key, run, or handoff token is replayed | `CONSUMED` or `DENIED`; no second transition |
| A prior first effect or evidence effect exists | `DENIED`; preserve history |
| Evidence destination is not writable, readable, append-only, or integrity-bound | `BLOCKED`; no handoff |
| Secret exposure or credential-boundary risk is detected | `BLOCKED`; no handoff |
| Exclusive lock or atomic compare-and-swap fails | `BLOCKED`; no handoff |
| Result is ambiguous after crash or timeout | `HOLD`/`BLOCKED`/`FAILED`; reconstruct first |
| Declared external effect is outside the exact envelope or scope | `DENIED`; no substitution |
| PAD-EXEC-001 or the required first-effect boundary is missing | `BLOCKED`; no execution |
| Any required value is absent, unknown, client-supplied, or unverifiable | `UNVERIFIED` or `BLOCKED`; never accept |

## Current state and non-claims

PAD-EXEC-FIRST-EFFECT-001 remains `SPECIFICATION COMPLETE — NOT EXECUTED`.

The observed repository state is:

| Boundary | Status |
| --- | --- |
| PAD-ENVGATE-001 | `BLOCKED` under TUR-016 |
| PAD-AUTHGATE-001 | `NOT AUTHORIZED`; no permit or approval exists |
| PAD-EXEC-ENVELOPE-001 | Specification only; no envelope instance exists |
| PAD-EXEC-REVALIDATE-001 | Specification only; no runtime revalidation performed |
| PAD-EXEC-COMMIT-001 | Specification only; PR #128 is OPEN/DRAFT/NOT MERGED; no `ALLOW` exists |
| PAD-EXEC-FIRST-EFFECT-001 | This specification only; no handoff token or acceptance record exists |
| PAD-EXEC-001 | Not opened |
| RUN 002 | `NOT AUTHORIZED` |
| Runtime, service, or PostgreSQL execution | Not executed |
| First effect | Not attempted |
| Observation and evidence | Not created |
| Independent verification | Not performed |
| Conformance | Not claimed |

This document creates no authority, permit, authorization, envelope, revalidation, commit decision, handoff token, acceptance record, first effect, runtime result, evidence closure, or conformance result. `GO-029` in PALACO-Citadel remains untouched.

The next valid contract boundary is `PAD-EXEC-001`. It may be opened only after a fresh, durable, attributable PAD-EXEC-COMMIT `ALLOW`, an exact current one-time handoff accepted by this gate, and a separately valid execution decision. None of those prerequisites is inferred from this document or from CI.
