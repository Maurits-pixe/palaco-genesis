# PAD-EXEC-ENVELOPE-001 — Immutable execution envelope contract

Status: SPECIFICATION COMPLETE — NOT EXECUTED

Base: PAD-AUTHGATE-001 at 6b831ea2100ff974bea78495554ce7ec21ea2df7

PAD-EXEC-ENVELOPE-001 is the third gate in the execution sequence. It defines the exact machine-readable envelope that a future authorized run must freeze before revalidation, commit, or execution.

This contract does not create an authorization, permit, execution record, database transaction, observation, evidence closure, or conformance result. An envelope is a binding specification of a possible run; it is not authority and it is not execution.

## Gate sequence and boundary

The required order remains:

PAD-ENVGATE → PAD-AUTHGATE → EXEC-ENVELOPE → REVALIDATE → COMMIT → EXEC → RECORD

The envelope gate owns one bounded question:

Can the exact authorized scope be serialized, digested, provenance-bound, and frozen so that every later gate verifies the same bytes and the same declared execution plan?

Only a complete and internally consistent envelope may reach FROZEN. FROZEN means ready for PAD-EXEC-REVALIDATE-001; it does not mean AUTHORIZED, COMMITTED, EXECUTABLE, VERIFIED, or CONFORMANT.

The execution commit gate remains the first point at which a future run may become accepted for a first effect. PostgreSQL COMMIT is a storage operation and is not the PALACO execution commit gate.

## Envelope statuses

The envelope lifecycle is fail-closed:

- DRAFT: an incomplete or editable candidate; it cannot be revalidated or executed;
- FROZEN: all mandatory fields are present, canonicalized, bound, and digestible; it may be presented to revalidation;
- STALE: a bound revision, authorization, environment, temporal state, fixture, service, or policy no longer matches;
- INVALID: serialization, schema, digest, required field, type, or cross-field validation fails;
- BLOCKED: a required prerequisite or external binding cannot be observed;
- REJECTED: policy, scope, isolation, or authorization requirements deny the candidate.

No status other than FROZEN permits the next gate. FROZEN never bypasses revalidation, commit, or the requirement for an existing AUTHORIZED decision.

## Required envelope identity

Every future envelope must bind the following identities without relying on branch names, mutable labels, or implicit defaults:

| Field | Required binding |
| --- | --- |
| envelope_id | Unique identity for this exact envelope |
| run_id | Unique identity for one attempted run; never silently reused |
| envelope_version | Canonical schema and ruleset version |
| repository | Full repository identity |
| implementation_revision | Exact implementation commit SHA |
| base_revision | Exact base/dependency commit SHA |
| workflow_revision | Exact workflow, launcher, and configuration revision |
| contract_set | PAD contract set and version under test |
| test_pack | Immutable ordered test-pack manifest and version |
| environment_ref | PAD-ENVGATE environment identity and attestation reference |
| authorization_ref | PAD-AUTHGATE decision identity and digest |
| actor_ref | Exact actor or service identity |
| target_ref | Exact subject, tenant, project, world, or resource boundary |
| fixture_manifest | Immutable fixture identity, version, and digest |
| service_manifest | Declared service/database identities, versions, and endpoint classes |
| toolchain_ref | Compiler, runtime, target, dependency, and lockfile identities |
| temporal_ref | Trusted time, sequence, trust_epoch, and validity references |
| evidence_ref | Evidence destination, retention, append-only, and readback boundary |
| isolation_ref | Process, workspace, network, secret, and cross-run isolation policy |
| envelope_digest | Digest over the canonical envelope bytes |

An environment name, branch name, successful checkout, green CI run, or human-readable title is not a substitute for an exact identity.

## Authorization binding

The envelope may reference an authorization decision, but it cannot create or enlarge one. Before an envelope can become FROZEN, the authorization reference must bind:

- the exact authorization_id;
- the exact authorization digest;
- the declared actor, target, purpose, and least-privilege scope;
- validity, expiration, revocation, consent, and delegation state;
- the exact implementation, base, workflow, environment, test-pack, fixture, and service bindings;
- the expected next gate and permitted external effects.

The envelope scope must be a subset of the authorized scope. A broader command, target, data boundary, endpoint, fixture, or effect is a new authorization request and cannot be represented as an envelope amendment.

If the authorization is absent, expired, revoked, stale, conflicting, or not independently verifiable, the envelope is REJECTED or BLOCKED. An envelope never changes PAD-AUTHGATE state.

## Test-pack and fixture binding

The test-pack manifest is immutable for the frozen envelope and must specify:

- test-pack identifier, version, and contract-set identity;
- deterministic ordered test and requirement identifiers;
- exact test selection and discovery rules;
- expected material, expected encoding, and expected digest for each required result;
- fixture manifest, source, generator version, seed, bytes, and digest;
- service and database fixture identity, reset policy, and non-production designation;
- output capture, normalization, newline, locale, and redaction rules;
- allowed exit classifications and timeout behavior;
- required evidence fields and closure conditions.

Fixture bytes, expected material, command selection, ordering, or normalization rules may not change after FROZEN. Any material change creates a new envelope_id and run_id, with a new digest and provenance relation to the earlier candidate.

The envelope must not silently discover tests from filesystem order, current time, locale, network state, or an undeclared environment variable.

## Command and working-directory binding

Each declared execution step must bind:

- stable step_id and deterministic order;
- exact executable identity or toolchain reference;
- exact command and argument vector;
- exact working directory;
- declared input and output paths;
- environment-variable allowlist and redaction policy;
- stdin source and encoding;
- timeout, memory, CPU, process, storage, and output limits;
- permitted exit status and termination classification;
- expected artifacts and artifact digests;
- allowed external effects, if any.

Shell interpretation, glob expansion, aliases, implicit current directories, undeclared environment variables, network lookups, and tool auto-discovery are not permitted to alter a frozen command. A platform-specific command requires an explicitly declared platform envelope or a new envelope version.

The envelope records the command plan. It does not run the command.

## Expected material and result boundary

Expected material must be distinct from observed material. The envelope must bind:

- expected value or expected artifact reference;
- expected encoding and canonicalization rules;
- expected digest algorithm and expected digest;
- comparator or verification ruleset version;
- required versus optional result classification;
- missing, blocked, timeout, error, unsupported, and skipped semantics.

A process exit code is not an expected result by itself. A successful process does not imply VERIFIED. Missing or incomplete expected material makes the envelope INVALID or BLOCKED; it must not be filled from observed output.

The envelope cannot predeclare a successful result. It declares what must be observed and how a later verifier will classify it.

## Canonical serialization and digest

The frozen envelope must have one canonical serialization:

- one declared schema and schema version;
- deterministic field order;
- deterministic array order;
- explicit representation for absent, null, empty, and default values;
- canonical UTF-8 encoding;
- canonical UTC representation for temporal fields;
- no runtime-generated fields outside the declared schema;
- no whitespace, locale, map-order, newline, or floating-point ambiguity;
- no secret or private payload material.

The envelope digest is computed over the exact canonical bytes, not over a rendered page, database row, branch name, or human summary. The digest algorithm and encoding are part of the envelope identity.

The integrity rule is:

WHAT IS SIGNED SHALL BE EXACTLY WHAT IS VERIFIED.

Any change to a digested field changes envelope_digest and invalidates the frozen state. A new envelope and new provenance relation are required. Historical envelopes are not edited in place.

## Temporal and validity binding

The envelope must bind:

- created_at and frozen_at in canonical UTC;
- not_before and expires_at when applicable;
- monotonic sequence;
- trust_epoch;
- temporal source and observation locator;
- authorization validity and revocation references;
- expected revalidation boundary.

Sequence is not inferred from wall-clock time. Highest accepted trusted time and trust_epoch must not decrease. Clock rollback, leap ambiguity, trust-source disagreement, expired validity, or missing temporal evidence prevents FROZEN or makes the envelope STALE.

An old envelope cannot be revived by restoring a snapshot, resetting a branch, replaying a cache, or moving a local clock backward.

## Isolation, services, and external effects

The envelope must not widen the environment validated by PAD-ENVGATE. It must bind:

- dedicated workspace and process boundary;
- subject, tenant, project, world, and data isolation;
- service/database identity, version, endpoint class, schema, and reset policy;
- network allowlist and egress policy;
- credentials and secret handling without embedding secret values;
- evidence destination, append-only policy, readback path, and capacity;
- teardown, retention, and failure-cleanup behavior;
- explicit external effects and their limits.

Production endpoints, live authority, undeclared credentials, cross-tenant data, and unlisted external effects are excluded by default. A future authorization may name an effect, but the envelope must name it again and bind it to the exact command and target.

Isolation is a prerequisite and a binding. It is not proven retroactively by an execution result.

## Evidence and provenance boundary

The envelope must bind the future evidence path without claiming that evidence exists:

- evidence destination identity and record type;
- raw stdout and stderr capture policy;
- artifact and log reference policy;
- observation, evidence, verification, and seal record relations;
- append-only and failure-atomic requirements;
- digest and readback rules;
- secret and unrelated-user-data exclusion;
- provenance locator and retention class.

No observation, evidence, independent verification, or run seal is created by freezing an envelope. A missing evidence destination, unavailable readback, ambiguous retention policy, or secret-leak risk blocks the envelope.

## Replay, uniqueness, and idempotency

The envelope must bind:

- unique envelope_id and run_id;
- unique envelope sequence or nonce;
- authorization_id and authorization digest;
- expected next gate;
- replay detection state;
- idempotency key;
- supersedes or derived-from relation, when applicable.

An envelope may not be replayed for a different implementation, base, workflow, environment, test pack, fixture, target, time window, or run. Duplicate delivery may return the same envelope record, but it must not create a second run, commit, authorization side effect, or evidence lineage.

Reruns receive a new run_id, envelope_id, execution identity, observation identity, and evidence relation. Earlier records remain immutable.

## Freeze transition

The future envelope builder may transition DRAFT to FROZEN only when all of the following are true:

1. PAD-ENVGATE has a current, exact, independently bound READY result.
2. PAD-AUTHGATE has a current AUTHORIZED decision; this contract does not create one.
3. Every required identity, revision, test-pack, fixture, service, toolchain, and temporal field is present.
4. The command plan, working directories, limits, expected material, and exit semantics are explicit.
5. Isolation, network, credential, external-effect, and evidence boundaries are explicit.
6. Canonical serialization is produced and its digest is recomputable.
7. Replay, uniqueness, and idempotency checks pass.
8. Required policy and review conditions are satisfied.

FROZEN is an append-only state transition. Editing any bound field, replacing a missing value, or silently refreshing a revision returns the candidate to a new DRAFT with a new identity.

## Handoff to revalidation and commit

Only a FROZEN envelope may be presented to PAD-EXEC-REVALIDATE-001. Revalidation must repeat, against the exact envelope digest:

- repository, implementation, base, workflow, and contract revisions;
- authorization, actor, target, scope, validity, revoke, and expiration;
- environment, toolchain, dependency, service, fixture, and isolation bindings;
- trusted sequence, trust_epoch, and temporal validity;
- evidence readiness, storage, readback, and integrity;
- replay and idempotency state.

If any binding differs, the envelope is STALE or BLOCKED. No implicit rebase, substitution, refresh, or retry may change the frozen envelope.

After successful revalidation, PAD-EXEC-COMMIT-001 remains mandatory. A FROZEN envelope is not an accepted run and cannot produce a first effect.

## Required negative matrix

The future envelope builder and independent review must cover at least:

| Case | Required result |
| --- | --- |
| Authorization is absent, revoked, expired, or unverifiable | REJECTED or BLOCKED; no FROZEN envelope |
| PAD-ENVGATE is not current READY | BLOCKED; no revalidation |
| Repository, head, base, workflow, or contract revision is ambiguous | INVALID or BLOCKED |
| Test-pack, fixture, or expected digest is missing or changed | INVALID or STALE |
| Command, argument, working directory, or limit is implicit | INVALID; no execution |
| Canonical serialization is not deterministic | INVALID |
| Envelope digest cannot be recomputed | INVALID or UNVERIFIED |
| Scope exceeds authorization | REJECTED; create a new authorization request |
| Temporal source rolls back or trust_epoch differs | STALE or BLOCKED |
| Service, database, endpoint, or network identity differs | STALE or BLOCKED |
| Evidence destination cannot append and read back exact bytes | BLOCKED |
| Secret or unrelated private data may enter output/evidence | BLOCKED |
| Envelope is replayed for another run or revision | REJECTED |
| Duplicate delivery targets the same envelope | Idempotent read; no second effect |
| A frozen field is edited in place | INVALID; preserve prior envelope |
| Revalidation changes any bound value | STALE; no commit |
| Envelope is FROZEN but commit gate is absent | No execution; no first effect |

## Current status and non-claims

PAD-EXEC-ENVELOPE-001 remains SPECIFICATION COMPLETE — NOT EXECUTED.

The current repository state is:

| Boundary | Status |
| --- | --- |
| PAD-ENVGATE-001 | BLOCKED under TUR-016 |
| PAD-AUTHGATE-001 | NOT AUTHORIZED; no permit or approval exists |
| PAD-EXEC-ENVELOPE-001 | SPECIFICATION ONLY; no envelope instance created |
| PAD-EXEC-REVALIDATE-001 | NOT OPENED |
| PAD-EXEC-COMMIT-001 | NOT OPENED |
| RUN 002 | NOT AUTHORIZED |
| Runtime/service/PostgreSQL execution | NOT EXECUTED |
| Observation/evidence/verification | NOT CREATED |
| Conformance | NOT CLAIMED |

Repository CI validates repository/workspace structure only. It does not freeze an execution envelope, grant authority, authorize RUN 002, execute a command, or create evidence.

The next valid contract boundary is PAD-EXEC-REVALIDATE-001. No execution effect may occur before a later successful commit-gate decision.
