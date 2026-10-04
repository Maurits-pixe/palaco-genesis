# PAD-ENVGATE-001 — Deterministic environment gate contract

Status: SPECIFICATION COMPLETE — NOT EXECUTED

Base: PAD-INT-001 at d13a28d6721f7027437db8279f887a1865b79402

PAD-ENVGATE-001 is the first gate in the execution sequence. It establishes whether an exact, isolated, observable environment exists for a future authorized run. It does not grant authorization, create a permit, execute a command, or establish conformance.

No environment attestation or runtime observation is created by this document or by repository CI.

## Gate purpose

The environment gate answers one bounded question:

Can the declared implementation revision, base revision, workflow, test pack, toolchain, services, clock, storage, network, and isolation boundary be observed and reproduced well enough for a separately authorized run?

The answer is one of:

- READY: every mandatory prerequisite is observed, bound, and internally consistent;
- BLOCKED: a mandatory prerequisite is missing, unavailable, contradictory, or unsafe;
- STALE: an earlier attestation no longer matches the declared head, base, workflow, toolchain, service, or trust state;
- UNVERIFIED: an observation exists but cannot be independently bound or recomputed.

Only READY may be presented to PAD-AUTHGATE-001. READY is not authorization and is not execution permission.

## Exact environment identity

The environment attestation must bind:

| Identity | Required evidence |
| --- | --- |
| Repository | Full repository identity and accessible ref |
| Implementation head | Exact commit SHA under test |
| Base dependency | Exact base commit SHA and dependency branch |
| Workflow/configuration | Exact CI, launcher, and test configuration revision |
| Test pack | Test-pack and contract-set identifiers and versions |
| Workspace | Exact workspace manifest and lockfile identity |
| Toolchain | rustc, cargo, rustfmt, clippy, target, and relevant runtime versions |
| Dependencies | Locked dependency graph and registry/source identity |
| Operating environment | OS, architecture, container/VM identity, and relevant limits |
| Services | Database, relay, mock, or external service identity and declared status |
| Clock | UTC source, monotonic sequence source, trust epoch, and rollback status |
| Storage | Evidence destination, readback capability, atomicity boundary, and capacity |
| Network | Allowlist, endpoint class, egress policy, and production exclusion |
| Isolation | Working directory, process, tenant/scope, secret, and cross-run isolation |

An environment name, branch name, successful checkout, or green repository CI is not sufficient environment evidence.

## Mandatory prerequisite checks

PAD-ENVGATE must evaluate every prerequisite before allowing a READY result:

1. Confirm the repository and exact implementation/base/workflow revisions.
2. Confirm the expected workspace exists and its manifest and lockfile are readable.
3. Confirm rustc, cargo, rustfmt, clippy, target, and declared runtime versions.
4. Confirm locked dependency resolution without an undeclared substitution.
5. Confirm required database or service endpoints are the declared non-production endpoints.
6. Confirm service identity, schema/migration state, and health are observable when a service is required.
7. Confirm trusted UTC time, monotonic sequence, trust epoch, and rollback status.
8. Confirm the evidence destination is isolated, writable, readable after write, and append-only for canonical records.
9. Confirm network policy and external side effects match the execution envelope.
10. Confirm no secret, credential, private payload, or undeclared user data will enter stdout, stderr, artifacts, or evidence.
11. Confirm process, storage, time, and network limits are sufficient for the declared test pack.
12. Record the result, checker identity, observation time, and environment digest.

Failure of any mandatory check is BLOCKED or UNVERIFIED. The gate must not silently select another workspace, toolchain, database, endpoint, clock source, or branch.

## Toolchain and workspace boundary

The future attestation must record machine-readable results for:

- rustc version and executable identity;
- cargo version and executable identity;
- rustfmt and clippy availability and versions;
- active target and toolchain file;
- cargo metadata under the locked dependency policy;
- workspace package list and manifest digest;
- lockfile and source registry identity;
- command output digests and observation locators.

If any required tool is absent, mismatched, or not independently bound, PAD-ENVGATE is BLOCKED. A repository workflow that installs its own tools proves only that workflow step; it does not prove a separate runtime environment.

The current recorded state remains TUR-016: rustc, cargo, rustfmt, and clippy are unavailable in the observed local environment, and the expected workspace is not available there. No runtime gate may be opened from that state.

## Service and database boundary

When a future test pack requires a service, the environment gate must bind:

- service identity, version, endpoint class, and non-production designation;
- connection and authentication mode without exposing secrets;
- schema and migration identity;
- isolation and reset policy;
- health/readiness result and observation time;
- evidence readback path and failure behavior.

A database connection string, reachable port, or successful health response alone does not prove PAD-SQL/PAD-MIG conformance, authorization, durability, or production safety. A missing, ambiguous, or production-like endpoint blocks the gate.

No service-run, PostgreSQL execution, migration execution, or database evidence is present in this repository state.

## Clock and temporal boundary

Environment readiness requires a declared trusted-time source and a separate monotonic ordering source:

- UTC representation is canonical;
- sequence is not inferred from wall-clock timestamps;
- highest accepted trusted time and trust_epoch must not decrease;
- rollback, leap ambiguity, or time-source disagreement produces BLOCKED or UNVERIFIED;
- an old snapshot may not restore a stale environment or authorization state;
- the environment timestamp is evidence metadata, not permission.

Local wall-clock time without a trusted and monotonic boundary is insufficient for PAD-ENVGATE READY.

## Storage and evidence boundary

The future attestation must prove the intended evidence path can:

- append a run/environment record without overwriting an earlier one;
- read back the exact bytes and recompute the digest;
- preserve raw command output and artifact references;
- bind evidence to repository, workflow, toolchain, environment, and test-pack identity;
- fail without leaving a partial success;
- exclude secrets and unrelated user data.

If readback, digest recomputation, append-only behavior, or atomic failure handling cannot be observed, the environment is BLOCKED or UNVERIFIED. Environment readiness is not evidence that a later observation was successfully recorded.

## Isolation and external effects

PAD-ENVGATE must verify:

- a dedicated working directory and process boundary;
- no cross-run fixture, cache, database, or credential contamination;
- explicit tenant, subject, project, world, or authorization scope;
- declared network allowlist and endpoint class;
- production endpoints and live authority are excluded unless separately authorized;
- external side effects are disabled or explicitly named in the future authorization envelope;
- environment teardown and retained evidence paths are defined.

Isolation is a prerequisite. It is not created retroactively by a test result.

## Attestation record

A future READY/BLOCKED/STALE/UNVERIFIED result must itself be an append-only environment attestation containing:

- environment_id and attestation_id;
- repository, head, base, workflow, test-pack, and workspace identities;
- toolchain, dependency, service, clock, storage, network, and isolation observations;
- check-by-check status and failure reason;
- observed_at, sequence, trust_epoch, and provenance;
- canonical environment digest;
- checker identity and implementation/ruleset version.

The attestation must not contain an implicit authorization decision. PAD-AUTHGATE-001 owns permission; PAD-ENVGATE-001 owns prerequisite readiness.

## Required negative matrix

The future environment checker and independent review must cover at least:

| Case | Required result |
| --- | --- |
| Repository head or base cannot be pinned | BLOCKED; no authorization gate |
| Workflow or test configuration differs from the declared envelope | STALE or BLOCKED |
| Workspace manifest or lockfile is missing | BLOCKED |
| Required toolchain component is absent | BLOCKED |
| Dependency resolution is not locked or is substituted | BLOCKED or UNVERIFIED |
| Required database/service is unavailable or ambiguous | BLOCKED |
| Endpoint appears production-like or outside allowlist | BLOCKED |
| Clock rollback or trust-epoch disagreement | BLOCKED or UNVERIFIED |
| Evidence storage cannot read back exact bytes | BLOCKED |
| Append-only or failure-atomic behavior is not observable | BLOCKED or UNVERIFIED |
| Isolation or secret exclusion cannot be established | BLOCKED |
| Prior attestation is stale for the current head or environment | STALE; re-attest |
| Environment is READY but authorization is absent | No execution; PAD-AUTHGATE remains unopened |

## Status boundary

PAD-ENVGATE-001 remains SPECIFICATION COMPLETE — NOT EXECUTED. The currently recorded gate is BLOCKED; PAD-AUTHGATE-001 is not opened; RUN 002 is NOT AUTHORIZED.

Environment readiness, when eventually observed, will not by itself prove execution, evidence closure, authorization, PostgreSQL durability, or conformance.
