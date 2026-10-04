# PAD-EXEC-REVALIDATE-001 — Final pre-commit revalidation contract

Status: SPECIFICATION COMPLETE — NOT EXECUTED

Base: PAD-EXEC-ENVELOPE-001 at d8d34a5d9fe442a49c35a4d6770b3a3474ea59db

PAD-EXEC-REVALIDATE-001 is the fourth gate in the execution sequence. It re-observes every authority, environment, scope, revision, temporal, isolation, replay, and evidence binding immediately before the execution envelope may enter the commit gate.

This contract exists to prevent time-of-check/time-of-use drift. It does not execute a command, create a first effect, grant authority, open PostgreSQL, produce a test observation, close evidence, or establish conformance.

## Gate sequence and boundary

The required order remains:

PAD-ENVGATE → PAD-AUTHGATE → EXEC-ENVELOPE → REVALIDATE → COMMIT → EXEC → RECORD

PAD-EXEC-REVALIDATE owns one bounded question:

Does the exact frozen envelope still match the current authority, environment, implementation, scope, temporal trust, isolation, evidence, replay, and idempotency state at the handoff to the execution commit gate?

The positive result is REVALIDATED. REVALIDATED means that the exact envelope may be presented to PAD-EXEC-COMMIT-001. It does not mean AUTHORIZED, COMMITTED, EXECUTABLE, VERIFIED, or CONFORMANT.

No command, fixture mutation, database mutation, external call, evidence observation, or first effect may occur during revalidation.

## Revalidation statuses

The gate is fail-closed:

- PENDING: the exact envelope has not yet been checked;
- REVALIDATED: every required binding matches the frozen envelope and the result is bound to its exact digest;
- STALE: one or more bindings changed after freezing;
- BLOCKED: a required source, environment, service, storage, clock, or isolation fact cannot be observed;
- DENIED: authority, scope, policy, consent, or external-effect rules reject the handoff;
- REVOKED: authority, credential, consent, mandate, or permit state is withdrawn;
- EXPIRED: the authorization or envelope validity window has ended;
- UNVERIFIED: a check exists but cannot be independently bound, recomputed, or trusted.

Only REVALIDATED may be presented to PAD-EXEC-COMMIT-001. No status is silently converted to REVALIDATED through retry, cache, default, or substitution.

## Exact input binding

Revalidation must start from one immutable envelope reference:

| Input | Required binding |
| --- | --- |
| envelope_id | Exact envelope identity |
| envelope_digest | Digest of the canonical frozen envelope bytes |
| envelope_version | Schema and ruleset version |
| run_id | Exact attempted-run identity |
| authorization_ref | Authorization identity and digest |
| environment_ref | Environment identity and latest attestation reference |
| implementation_revision | Exact implementation commit SHA |
| base_revision | Exact base/dependency commit SHA |
| workflow_revision | Exact workflow and configuration revision |
| test_pack | Immutable test-pack identity and digest |
| fixture_manifest | Fixture identity and digest |
| service_manifest | Service/database identity and endpoint-class binding |
| temporal_ref | Trusted time, sequence, trust_epoch, and validity |
| isolation_ref | Workspace, process, tenant, network, secret, and cross-run binding |
| evidence_ref | Evidence destination and readback/integrity binding |
| revalidation_id | Unique identity for this revalidation attempt |
| revalidation_ruleset | Exact checker and policy version |

The checker must load the envelope by identity and recompute envelope_digest from the canonical bytes before checking any dependent field. A human-readable summary, branch name, database row without digest, or prior CI result is not the input envelope.

## Required revalidation checks

Every revalidation must independently check and record:

1. Envelope identity, schema, canonical bytes, and recomputed digest.
2. Repository identity, implementation head, base, workflow, and contract-set revision.
3. Test-pack, fixture, expected-material, command, and normalization digests.
4. PAD-ENVGATE result, environment identity, toolchain, dependency lock, and workspace binding.
5. PAD-AUTHGATE decision, authority, actor, target, purpose, scope, and prohibited operations.
6. Authorization validity, expiration, revocation, consent, delegation, and policy state.
7. Trusted UTC source, monotonic sequence, highest accepted trusted time, and trust_epoch.
8. Service/database identity, schema/migration state, endpoint class, health, and reset boundary.
9. Workspace, process, tenant, subject, network, credential, and secret isolation.
10. Evidence destination, append-only behavior, readback capability, digest policy, and capacity.
11. Replay, nonce, idempotency, duplicate-delivery, and prior-run state.
12. Required reviewer/policy conditions and the expected next gate.

The checker must record both the observed value and the expected envelope value. Equality must be proven using the declared canonical representation and digest rules, not by a mutable display field.

## Authority and scope revalidation

Revalidation repeats the authority checks; it does not trust the earlier PAD-AUTHGATE result blindly. It must confirm:

- the authorization_id and authorization digest still identify the exact decision;
- the authority and decision-maker remain valid under the declared policy;
- the actor, target, subject, tenant, project, world, and purpose are unchanged;
- the permitted scope remains a subset of the authorized scope;
- prohibited operations and external effects remain excluded;
- consent, delegation, credential, revocation, and expiration state remain current;
- no higher-priority deny, hold, revoke, conflict, or trust downgrade exists.

An authorization that was valid when the envelope was frozen may be revoked or expired before commit. Revalidation must deny the handoff in that case. It may not revive a terminal state through a snapshot, cache, clock rollback, branch reset, or retry.

Identity is not authority, and CI is not authority. RIO, automation, implementation code, and a repository permission cannot replace the declared authorization decision.

## Revision, test-pack, and expected-material revalidation

The checker must compare exact identities for:

- repository and implementation head;
- base/dependency revision;
- workflow, launcher, and configuration;
- contract-set and ruleset;
- test-pack and ordered test list;
- fixture bytes, seeds, generators, and digests;
- expected values, encodings, comparators, and expected digests;
- command vectors, working directories, limits, and exit classifications.

Any mismatch is STALE or BLOCKED. The checker must not implicitly rebase, refresh, re-resolve dependencies, rediscover tests, regenerate fixtures, or replace expected material. A changed value requires a new envelope and a new revalidation attempt.

A green repository CI run can validate the submitted revision's structural checks. It cannot substitute for the runtime environment, authorization, frozen envelope, or final revalidation.

## Environment, service, and isolation revalidation

The checker must re-observe the exact environment rather than relying on an earlier label:

- workspace and manifest/lockfile identity;
- toolchain executable and version identity;
- dependency resolution and source identity;
- process, filesystem, storage, and resource limits;
- service/database identity, endpoint class, schema/migration state, and reset policy;
- network allowlist and egress policy;
- credential presence without exposing secret values;
- tenant, subject, project, world, and cross-run isolation;
- evidence storage, readback, append-only, and failure-atomic behavior.

An unavailable or ambiguous endpoint, production-like service, changed schema, missing tool, changed lockfile, cross-run contamination, or unbounded secret path blocks the handoff. No service is silently replaced by a mock, alternate database, or new endpoint.

Revalidation does not create a service attestation or evidence record unless that is separately specified and actually observed. This document records only the contract boundary.

## Temporal and sequence revalidation

Temporal checks must bind:

- canonical UTC observation;
- monotonic sequence;
- highest accepted trusted time;
- trust_epoch;
- authorization and envelope validity windows;
- revocation/expiration observation sequence;
- revalidation sequence and provenance.

The sequence must not be inferred from wall-clock time. A rollback, leap ambiguity, source disagreement, decreased trust_epoch, stale revocation source, expired window, or missing temporal proof produces STALE, BLOCKED, REVOKED, EXPIRED, or UNVERIFIED as applicable.

An old revalidation result cannot be reused after a temporal or identity change. The result is valid only for the exact envelope_digest, run_id, commit window, and expected next gate it names.

## TOCTOU protection and commit handoff

Revalidation must close the gap between checking and accepting the run:

1. Load and digest-check the immutable envelope.
2. Re-observe all required authority, environment, scope, revision, temporal, isolation, replay, and evidence bindings.
3. Write one append-only revalidation record bound to envelope_digest and revalidation_id.
4. Acquire the declared commit boundary or equivalent exclusive lock for the run identity.
5. Re-check revocation, expiration, envelope_digest, revision, sequence, idempotency, and isolation inside that boundary.
6. Produce a commit-handoff token or equivalent record bound to the exact revalidation and envelope.
7. Hand off only to PAD-EXEC-COMMIT-001.

If the final check differs, the lock cannot be acquired, the append is not atomic, or the handoff token cannot be bound, the result is BLOCKED or STALE and no accepted run exists.

The commit boundary must not execute the test command. It exists to ensure that a later commit decision cannot rely on a check that has already become false.

The phrase “transaction” here refers to the PALACO execution-acceptance boundary. A database transaction or PostgreSQL COMMIT does not itself grant PAD-EXEC-COMMIT permission.

## Replay and idempotency revalidation

The checker must validate:

- envelope_id, run_id, and revalidation_id uniqueness;
- authorization_id and authorization digest;
- monotonic sequence and nonce;
- no prior accepted commit for the run;
- no prior execution effect for the envelope;
- duplicate-delivery behavior;
- supersedes/derived-from relation for any rerun;
- idempotency key and expected next gate.

Replaying a valid earlier revalidation against another head, base, workflow, environment, scope, time window, run, or target is DENIED. A duplicate request for the same exact identity may return the prior result, but it may not create a second handoff, run, effect, or evidence lineage.

## Append-only revalidation record

A future revalidation record must contain:

- revalidation_id and run_id;
- envelope_id, envelope_digest, and envelope schema version;
- expected and observed values for every checked binding;
- authorization, environment, revision, test-pack, fixture, service, toolchain, temporal, isolation, replay, and evidence results;
- status and precise failure reason when not REVALIDATED;
- checker identity and revalidation ruleset version;
- observed_at, sequence, trust_epoch, and provenance;
- commit-boundary reference and handoff-token digest when successful;
- supersedes/derived-from relation when applicable;
- canonical record bytes and record digest.

The record is evidence of a revalidation decision only. It is not a test observation, execution proof, conformance certificate, authorization grant, or merge authorization.

Failed and superseded records remain append-only. They are not deleted, retimestamped, or rewritten as successful records.

## Handoff rules

PAD-EXEC-COMMIT-001 may open only when:

1. the result is REVALIDATED;
2. envelope_digest and run_id are exact and recomputable;
3. all required current bindings match;
4. authority is still valid, unrevoked, unexpired, and in scope;
5. the final check occurred inside the declared commit boundary;
6. replay and idempotency checks pass;
7. the append-only revalidation record and handoff binding are durable;
8. the handoff names PAD-EXEC-COMMIT-001 as its only next gate.

REVALIDATED is not permission to execute. PAD-EXEC-COMMIT-001 must still make the explicit ALLOW/DENY decision before the first effect.

## Required negative matrix

The future revalidation checker and independent review must cover at least:

| Case | Required result |
| --- | --- |
| Envelope digest cannot be recomputed | INVALID or UNVERIFIED; no handoff |
| Envelope is DRAFT, STALE, INVALID, BLOCKED, or REJECTED | No revalidation; no commit |
| PAD-ENVGATE is not current READY | BLOCKED |
| PAD-AUTHGATE is absent, revoked, expired, stale, or out of scope | DENIED, REVOKED, EXPIRED, or STALE |
| Repository, head, base, workflow, or contract revision differs | STALE; no substitution |
| Test-pack, fixture, expected material, or command differs | STALE or BLOCKED |
| Toolchain, dependency, service, database, or endpoint differs | STALE or BLOCKED |
| Trusted time rolls back or trust_epoch decreases | BLOCKED or UNVERIFIED |
| Consent, delegation, credential, or target state changes | DENIED or STALE |
| Isolation, secret policy, network, or evidence readback fails | BLOCKED |
| Replay or duplicate run identity is detected | DENIED; no second handoff |
| Final check differs inside commit boundary | STALE; no accepted run |
| Lock/transaction boundary cannot be acquired atomically | BLOCKED; no accepted run |
| Handoff token is missing or mismatched | UNVERIFIED; no commit |
| Revalidation succeeds but PAD-EXEC-COMMIT is absent | No execution; no first effect |
| PostgreSQL COMMIT is mistaken for PALACO commit permission | DENIED; preserve boundary |

## Current status and non-claims

PAD-EXEC-REVALIDATE-001 remains SPECIFICATION COMPLETE — NOT EXECUTED.

The current repository state is:

| Boundary | Status |
| --- | --- |
| PAD-ENVGATE-001 | BLOCKED under TUR-016 |
| PAD-AUTHGATE-001 | NOT AUTHORIZED; no permit or approval exists |
| PAD-EXEC-ENVELOPE-001 | SPECIFICATION ONLY; no envelope instance exists |
| PAD-EXEC-REVALIDATE-001 | SPECIFICATION ONLY; no revalidation performed |
| PAD-EXEC-COMMIT-001 | NOT OPENED |
| RUN 002 | NOT AUTHORIZED |
| Runtime/service/PostgreSQL execution | NOT EXECUTED |
| Observation/evidence/verification | NOT CREATED |
| Conformance | NOT CLAIMED |

Repository CI and the external merge of PR #110 do not constitute runtime revalidation, authority, commit-gate ALLOW, execution, evidence, or conformance.

The next valid contract boundary is PAD-EXEC-COMMIT-001. No first effect may occur before an explicit successful commit-gate decision.
