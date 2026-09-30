# PAD-INT-001 — Integration verification and PAD-HARNESS contract

Status: SPECIFICATION COMPLETE — NOT EXECUTED

Base: PAD-VER-001 at 720bfd38d54120e89e1c4ae2b4021353d56b8bcf

This contract defines the future integration-test envelope for PAD-SQL-001, PAD-MIG-001, PAD-SEC-001, PAD-OUTBOX-001, and PAD-VER-001. PAD-HARNESS is the execution-harness subboundary inside this contract.

No harness, integration runner, PostgreSQL service, external transport, RUN 002, verification result, or conformance evidence is created by this document or by repository CI.

## Gate sequence

The harness must stop at the first failed gate:

PAD-ENVGATE → PAD-AUTHGATE → EXEC-ENVELOPE → REVALIDATE → COMMIT → EXEC → RECORD

The gates have distinct meanings:

| Gate | Required decision |
| --- | --- |
| PAD-ENVGATE | Exact repository, toolchain, dependency, service, clock, network, storage, and isolation prerequisites are observable and compatible |
| PAD-AUTHGATE | The run is explicitly authorized for the declared scope, actor, revision, environment, and test pack; revocation and trust state are current |
| EXEC-ENVELOPE | All identifiers, commands, fixtures, expected digests, configuration, limits, and provenance are frozen before execution |
| REVALIDATE | Environment, authorization, scope, revision, revocation, trusted time, and provenance still match immediately before commit and execution |
| COMMIT | The execution envelope and the state needed to start the run are committed atomically, or no run is accepted |
| EXEC | The exact declared commands run in the isolated environment with raw output and temporal evidence captured |
| RECORD | Observations, evidence closure, verification results, and final status are appended without historical rewrite |

Passing a gate does not prove the next gate or the final contract. A gate result is evidence only for its declared scope.

## Current gate status

The current repository context remains blocked at the toolchain/environment boundary: rustc, cargo, rustfmt, and clippy are not available in the observed execution environment, and the expected workspace is not locally available.

Therefore:

- PAD-ENVGATE is BLOCKED;
- PAD-AUTHGATE is not opened;
- RUN 002 is NOT AUTHORIZED;
- no EXEC step may start;
- no new observation or evidence record may be inferred;
- no runtime or conformance claim may be made.

This status is a boundary condition, not a failed contract result. A future authorized run must create new append-only evidence rather than rewrite an earlier record.

## Deterministic test-pack manifest

Every integration run must reference one immutable test-pack manifest containing:

- test-pack identifier and version;
- contract-set identifier and version;
- deterministic ordered test and requirement identifiers;
- exact command, arguments, working directory, timeout, and allowed exit classification;
- expected material and expected digest for every required test;
- immutable fixture and fixture-manifest references;
- repository, branch, exact implementation revision, base revision, and workflow/configuration revision;
- toolchain and dependency-lock identity;
- isolation mode, service references, authorization scope, and network policy;
- output capture and normalization rules;
- provenance source, record locator, and manifest digest.

Test identifiers and ordering are stable. Test discovery, filesystem ordering, locale, platform newline conversion, implicit environment variables, and current time must not silently change the test pack.

Changing a command, fixture, expected material, toolchain, dependency, environment, or normalization rule creates a new test-pack version and new expected digests.

## Immutable fixtures and isolation

The harness must execute only against declared fixtures and declared services:

- fixture bytes are immutable and manifest-bound;
- generated fixtures use a recorded seed and generator version;
- the working directory is isolated from the repository source and unrelated user data;
- production databases, production credentials, live authority, and undeclared network access are excluded;
- any test double or external service must have an explicit identity, version, endpoint class, and digest;
- secrets are not written to stdout, stderr, artifacts, or evidence payloads;
- external side effects are denied unless the authorization envelope explicitly names them;
- a service failure is recorded as unavailable or blocked, never silently replaced by a different service.

Isolation is an execution prerequisite. It is not proven merely by naming a test environment.

## Execution envelope

Before execution, the harness must freeze one machine-readable envelope with:

| Field | Requirement |
| --- | --- |
| run_id | Stable identity for this complete attempted run |
| test_pack_id / contract_set_id | Versioned scope of required tests and claims |
| implementation_revision | Exact commit under test |
| base_revision | Exact dependency/base commit |
| workflow_revision | Exact CI or launcher configuration |
| environment_ref | Stable environment identity and observable capabilities |
| toolchain_ref | Compiler, formatter, linter, runtime, and dependency identity |
| authorization_scope_ref | Explicit permission and target boundary |
| isolation_ref | Working directory, service, network, and secret policy |
| expected_manifest_digest | Digest of all expected material |
| sequence_start | Monotonic execution sequence or trusted head |
| provenance | Source and stable record locator |
| envelope_digest | Digest over the canonical envelope |

The envelope must be sealed before the first test command. An observed head, base, workflow, or configuration mismatch blocks the run; it does not trigger an implicit rebase or substitute a new head.

## Revalidation and commit boundary

Immediately before the run is accepted, the harness must revalidate:

- repository and implementation head;
- base dependency and workflow/configuration revision;
- test-pack and expected-manifest digest;
- environment and toolchain capabilities;
- authorization scope, permit state, revocation, and trust epoch;
- isolation and network policy;
- sequence, clock, and provenance inputs.

If revalidation differs from the frozen envelope, the run is BLOCKED or NOT AUTHORIZED. It must not mutate an existing run, reuse an old permit, or continue under an altered scope.

The execution envelope, run identity, required test set, and any pending execution record must be committed as one candidate. A persistence failure leaves no accepted run, no partial evidence, and no authorization side effect.

## Execution and raw observation

For each declared test, the harness must capture:

- execution identifier and deterministic test identifier;
- exact command and working directory;
- start, end, and capture timestamps with separate sequence values;
- process exit status, including timeout or termination reason;
- raw stdout bytes and raw stderr bytes;
- artifact references and artifact digests;
- environment, toolchain, fixture, and service references;
- observed value and normalized value as distinct fields;
- provenance and observation/integrity digests.

The harness must not replace raw bytes with a rendered summary. A successful process exit code is not a VERIFIED result. A failed process may still produce an observation that requires independent classification.

## Recording and evidence closure

The RECORD gate appends, in order:

1. execution record;
2. observation record;
3. closed evidence record;
4. independent verification record;
5. run manifest and seal when all required records are complete.

Every record cross-binds run_id, test_id, execution_id, observation_id, evidence_id, expected_digest, observed_digest, evidence_digest, and integrity_digest. Missing or conflicting binding leaves the result UNDETERMINED or BLOCKED.

Evidence is append-only. A partial write, crash, digest mismatch, or failed closure must not be represented as a successful evidence record. Corrections create new records and new provenance; E0 remains immutable when E1 is added.

## Result and status rules

The harness preserves the PAD-VER-001 outcome meanings:

- VERIFIED requires complete expected material, successful observation capture, closed evidence, valid provenance, recomputed digests, and independent verification;
- MISMATCH requires complete and comparable expected and observed material that differ under the declared ruleset;
- UNDETERMINED covers missing, blocked, not-run, skipped, timeout, error, unsupported, unverifiable, incomplete, or independence-failed cases;
- BLOCKED means a prerequisite or gate prevented execution;
- NOT AUTHORIZED means no permitted execution may occur;
- SEALED means the evidence set is closed, not that every result is successful.

Blocked, not-run, skipped, timeout, unsupported, or missing observation is never VERIFIED and is not silently converted into MISMATCH.

## Replay and rerun boundary

Replay reconstructs recorded state and validates the declared chain. It does not execute commands, repair gaps, contact services, or grant authorization.

A rerun after any material change receives:

- a new run_id;
- a new execution identity;
- new observation and evidence records;
- a new expected manifest when expected material changed;
- an explicit relation to the earlier run.

No rerun may overwrite, retimestamp, reseal, or delete an earlier run. A comparison between runs is a new derived verification record with its own provenance.

## Required negative matrix

The future PAD-HARNESS implementation and independent review must cover at least:

| Case | Required result |
| --- | --- |
| Toolchain or workspace missing | PAD-ENVGATE BLOCKED; no command |
| Explicit authorization absent or revoked | PAD-AUTHGATE NOT AUTHORIZED; no command |
| Implementation, base, workflow, or test-pack head differs | BLOCKED; no implicit substitution |
| Expected-manifest or fixture digest differs | BLOCKED; no execution |
| Isolation or network policy cannot be established | BLOCKED; no execution |
| Commit of the execution envelope fails | Rollback; no accepted run or evidence |
| Test command times out or is interrupted | Observation/UNDETERMINED when safely captured; never VERIFIED |
| stdout/stderr or artifact capture is incomplete | UNDETERMINED; evidence not closed |
| Observation has wrong run/test/execution binding | Reject or UNDETERMINED; no verification success |
| Independent verifier is unavailable or not independent | UNDETERMINED; no certificate |
| Required test is skipped or not run | UNDETERMINED; no conformance |
| Rerun changes a prior record | DENY; preserve the prior record and create a new run |
| External side effect is outside the declared scope | DENY; no execution commit |
| One required result is MISMATCH or UNDETERMINED | Overall conformance denied |

## Status boundary

PAD-INT-001 and PAD-HARNESS remain SPECIFICATION COMPLETE — NOT EXECUTED. This repository state contains no harness implementation, no integration run, no RUN 002 authorization, no new observation, no evidence closure, and no conformance result.

The next permitted step after a future environment and authorization gate is an explicitly authorized execution envelope. Until then, the correct state remains BLOCKED / NOT AUTHORIZED.
