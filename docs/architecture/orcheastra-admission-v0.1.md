# ORCHEASTRA — admission gate v0.1

Status: **DRAFT / HOLD**. This package does not authorize, schedule, or execute operations.

## Placement

The module `palaco_runtime::orcheastra` is a pure, offline-capable admission
assessment. It is not a replacement for PALACO One identity verification,
TRIAS authority, evidence provenance, Citadel execution boundaries, or the
runtime revalidation step.

## Decision contract

- `ObserveOnly`: authenticated read-only inspection, with no mutation authority.
- `Proposed`: a proposed mutation has met all supplied gate signals,
  **not** a command to execute it.
- `Blocked(reason)`: mutation is forbidden; the reason is reportable to audit.

Precedence: revocation > HOLD > identity > operation-specific requirements.
Mutation requires *all* of: verified identity, verified authority,
verified evidence, scope match, current state/policy, and explicit Citadel
execution disposition. The upstream caller must substantiate these signals
with verified artifacts; booleans alone are **not** security proof.

## Integration sequence (not yet wired)

1. Verify signed identity, scoped authorization and evidence in their
   respective trust domains.
2. Check revocation and GO-13 / environment HOLD from the authoritative source.
3. Revalidate policy/state snapshot and the Citadel boundary.
4. Pass the resulting verified signals to `evaluate_admission`.
5. Log the decision, policy version and evidence references in PALACO Audit.
6. Only after a separate last-moment runtime revalidation may an executor act.

No caller is permitted to interpret `Proposed` as a capability token.
Network calls, issuance, signing, deployment and repository merges remain
outside this module.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p palaco-runtime
cargo test --workspace
```

The PR remains draft until these commands pass in CI and human review
approves the trust-boundary integration.

## Runtime-bound proposal adapter (v0.2 candidate)

The `evaluate_runtime_proposal(plan, context, claims)` adapter consumes the
existing `RuntimePlan` instead of trusting caller-supplied Citadel/context
flags alone. It verifies the original policy and state identifiers, rejects
backdated observations, checks current validity, and calls `revalidate`.

Both externally verified claims and runtime-derived checks must succeed.
The adapter still returns only `Proposed`; it does not invoke the in-memory
Citadel commit gate, issue tokens, perform IO or authorize real operations.

New regression coverage includes: valid proposal, active HOLD,
non-executable governance scope, mismatched state snapshot and expired
validity window. CI execution and independent review are still required.

## Task coordinator (v0.3 draft)

`orcheastra::tasks::TaskPlan` validates unique task IDs, all dependency
references, self-dependencies, and cycles, then returns a stable topological
ordering. Task IDs and module names are logical references, not permission
grants or executable commands.

`TaskCoordinator` records at most one admission outcome per task in an
in-memory, append-only, sequence-numbered journal. A task with unresolved
predecessors cannot be marked `Proposed`. Blocked dependencies cannot satisfy
predecessor requirements. Evidence locators must match the immutable plan.

This journal is **not** durable, tamper evident, or a substitute for the
PALACO Audit service. Recovery, persistence, hash chaining, signed references,
revalidation between proposal and execution, and distributed concurrency
control must be designed and reviewed before any real operation.

Regression tests cover stable ordering, unknown dependencies, cycles,
duplicate tasks, premature proposals, denied predecessors, incorrect
evidence references and duplicate decision attempts.

Production execution, scheduling, role creation, authorization, and merging
remain out of scope. GO-13 HOLD continues to apply.

## SHA-256 integrity chain (v0.4 candidate)

`orcheastra::chain` computes a deterministic, domain-separated SHA-256
digest of each decision. Canonical encoding uses an explicit version prefix,
the previous digest, the 64-bit big-endian sequence and length-prefixed UTF-8
task/evidence identifiers, and a fixed decision/reason tag. The genesis
previous hash is 32 zero bytes.

`chain_entries` rejects noncontiguous sequence numbers;
`verify_chain(records, trusted_head)` verifies each preceding hash, recomputes
record digests and compares the final hash to a **separately trusted** anchor.
A truncated journal only becomes detectable when an authoritative previously
recorded head is provided. No anchors are currently stored.

**Threat boundaries:** SHA-256 by itself provides integrity relative to a
trusted anchor, not signer identity, durable storage, authorization, replay
protection across independent sessions or prevention of log replacement.
A local attacker who can replace both the records and the expected head
can forge an internally consistent history. A future PALACO Audit integration
must persist records transactionally, sign or otherwise authenticate canonical
heads, anchor sequence/head pairs externally, and verify them before recovery.

No automated write, scheduling, approval, token issuance, or execution is
performed by these functions. GO-13 HOLD remains unchanged.

## Recovery checkpoints (v0.5 draft)

The `orcheastra::recovery` module exports `RecoveryCheckpoint` with a
canonical, domain-separated task-plan SHA-256 digest, committed sequence
count and journal head. `export_checkpoint` produces a matching snapshot
for a storage adapter. It performs **no durable writes** and does not sign
or authenticate the checkpoint.

`recover_coordinator` accepts a separately trusted checkpoint, validates
the entire plan and the exact record count, verifies every chained record
against the independently trusted head, and replays decisions through the
same task dependency and evidence-reference rules as normal admission.
Any mismatch results in an error without returning a partial coordinator.
It remains offline and non-executing.

### Required storage integration (not implemented)

1. Store the immutable plan and all records in transactional durable storage.
2. Authenticate the checkpoint using PALACO Audit signing and trusted
   identity/authority services; never trust a checkpoint loaded from the
   same mutable journal without an external anchor.
3. Atomically persist checkpoint sequence and head with recorded decisions.
4. On restart, fetch a trusted latest checkpoint through an authenticated,
   rollback-resistant channel, and only then call `recover_coordinator`.
5. Fail closed on unavailable or conflicting checkpoints; never auto-resume
   mutation proposals. Revalidate current revocations/HOLD and policy before
   any new proposal, independently of recovered historical entries.

The current `TaskCoordinator` is still process-local. These APIs do not
claim durable crash recovery, cross-process transactionality, signing or
authority verification. Rust CI and independent human review remain required.

## Persistence contract (v0.6 draft)

`orcheastra::persistence` defines `JournalSnapshot`,
`CommittedVersion`, `SnapshotStore`, `verify_snapshot` and
`commit_verified`. A snapshot binds the validated plan, the entire
hash-chained journal and its checkpoint. Verification checks an independently
trusted checkpoint, then performs fail-closed journal replay before invoking
a backend. The backend is required to atomically commit the complete snapshot
using compare-and-swap against an independently anchored generation. Conflicts
or missing trust fail closed. The proposal log does **not** convey execution
authorization.

This is a **storage boundary contract only**. No production durable backend
exists in this PR; there are no filesystem writes, database transactions or
operational secrets. Production storage must implement durable atomic
transactions, independently authenticated monotonic checkpoint and generation
storage, crash/restart recovery, archival, and a separate current revocation
check. Tests exercise checkpoint rejection and concurrent-modification errors
with a deliberately rejecting mock backend.

CI formatting failures from the previous run were addressed on the draft
branch; all new changes require a fresh Rust fmt/Clippy/test run.

## v0.7 validation and fault-injection follow-up

CI/CD run #410 and workspace CI #715 reported formatting failures in the
v0.6 candidate. The formatting differences shown in the job logs were fixed.
The independent Citadel interoperability job also reported a stale Cargo.lock
when using `--locked`; the workspace lock entry for `palaco-runtime` now
lists its `sha2` dependency. A new CI run must confirm all corrections.

The `SimulatedStore` adapter exists **only under cfg(test)**. It models a
transaction interruption before publishing a snapshot; a retry can commit,
but a stale generation is rejected. This is not a durability proof, disk
adapter, crash-consistent filesystem test or trusted checkpoint authority.
No actual snapshot storage implementation is enabled for production.

## v0.8 monotonic recovery fence

`TrustedRecoveryAnchor` binds a monotonic storage generation to an
independently trusted `RecoveryCheckpoint`. The read-only
`recover_at_anchor` operation denies replay when the observed storage
generation differs from the authenticated generation, even if the older
hash chain is internally correct. It then verifies the full journal and
plan against the trusted checkpoint.

This is an API-level rollback defense, NOT a source of trust or a physical
disk implementation. The independent, authenticated monotonic generation
service and actual durable storage remain absent. This helper cannot
validate that caller-supplied anchors are authentic.

PALACO CI/CD #414 and PALACO CI #719 previously failed at Clippy due
to a complex local test-case type. A named test type alias addresses that
error; fresh CI checks are required before review or merge.

## v0.9 offline file-staging prototype

`orcheastra::file_store` stages opaque snapshot bytes to an immutable
generation-named file. It uses a unique temporary file, length bounds,
domain-specific magic, SHA-256 integrity, `sync_all` on the file, rename
to the generation filename, and directory sync where supported. Reading
verifies the header, independently supplied expected generation, payload
length, absence of trailing bytes, and SHA-256 digest.

Regression tests cover reopening after close, detecting a changed payload,
rejecting trailing data and rejecting reuse of a staged generation.

**This is intentionally NOT the `SnapshotStore` implementation.** The
bytes are not yet a canonical encoded `JournalSnapshot`; the local hash
does not prove authenticity. The staging function is not a multi-process
compare-and-swap and race-free exclusive publication is not guaranteed by
the pre-rename exists check. Independent checkpoint signing, transaction
integration and crash/restart across platforms remain required before this
can be used for authority-bearing records. No automatic execution.

The earlier v0.8 run (#632) confirmed Citadel interoperability, but
CI/CD #417 and CI #722 stopped on a rustfmt change in a new test; that
formatting was fixed before this staging prototype was added. Run the
current full CI jobs before treating v0.9 as validated.

## v0.10 structured offline snapshot transfer

The `orcheastra::snapshot_file` adapter now transfers a structured
`JournalSnapshot` through bounded, generation-named local files. The
versioned JSON wire document includes task specifications, chained decision
records and a checkpoint. Import rebuilds the task graph using
`TaskPlan::build` rather than trusting cached graph indexes and replays the
journal against an externally supplied `TrustedRecoveryAnchor`.

Unknown wire versions, malformed task graphs, mismatched checkpoints,
stale generations, corrupted file bytes and invalid decision histories fail
closed. Tests cover reopening a structured file, rejecting substituted
checkpoints and unknown format versions. The integrity boundary is local
and explicitly non-executing.

**Remaining limitations:** the serialized JSON is not signed or encrypted;
local file staging is not a multi-writer atomic compare-and-swap; no durable
authenticated checkpoint service exists, and no production PALACO Audit
adapter has been connected. These APIs cannot authorize execution or verify
the authentic origin of an independently supplied anchor. Do not infer that
a recovered historic proposal is currently admissible.

CI note: v0.9 CI/CD #421 and PALACO CI #726 failed on file-store rustfmt,
while Citadel #636 succeeded. The formatting diff has been corrected in this
branch; v0.10 requires fresh formatting, Clippy and test validation.

## v0.10.1 exclusive publication hardening

The local staging adapter has been hardened to publish the fully synced
temporary file using an **exclusive hard link** rather than an overwriting
rename. An already existing generation filename is rejected atomically,
including when another local writer wins a race. The temporary link is then
removed and the directory is synced. Unsupported filesystems fail closed.

This remains an untrusted local **file transport**. It does not replace
the independent monotonic checkpoint, confirm journal provenance, or
provide a complete durable multi-file transaction. Temporary files can
remain after power loss; consumers must ignore all unanchored files.

## v0.11 PALACO Audit checkpoint-verifier integration

The `palaco-audit::orcheastra` module provides an independent
`AuditAnchorVerifier` boundary and a read-only `recover_from_audit`
entrypoint. The audit verifier, not the untrusted snapshot caller, must
supply the latest authenticated `TrustedRecoveryAnchor` scoped to the
exact nonempty journal ID. Refused, unavailable or stale verifiers fail
closed; inconsistent file generations, corrupt snapshots and invalid
journal histories are also rejected. The recovery return type does not
contain any execution interface.

An actual production verifier implementation is **not** included. No
cryptographic signatures are generated or checked here; a fixture verifier
is only used in the tests. A production verifier must validate signer
identity, signatures, journal scope, policy, revocation and monotonic
generation from an authoritative independent service. Until that exists,
this is an integration contract, not authenticated production recovery.

Regression cases cover missing checkpoint, incorrect journal scope,
successful inert historical replay, and disagreement about generation.

## v0.12 authenticated audit checkpoint candidate

`palaco_audit::orcheastra::mac` provides a scoped HMAC-SHA-256
checkpoint authenticity contract. The MAC covers a domain-separated
version, exact journal ID, pinned key ID, monotonic generation, plan hash,
decision sequence and hash-chain head. A verified tag is necessary but
insufficient: an independent `GenerationAuthority` must attest the latest
generation for the same journal. The verifier rejects changed fields,
wrong journal scope, unknown key identifiers and historical generations.
Tag comparison is performed without early exit.

The implementation uses an externally provisioned 256-bit symmetric key
and the existing workspace `sha2` dependency. Test fixtures use a
nonproduction deterministic key. No production key manager, secure secret
storage, remote attestation, key rotation, independently durable
generation authority or asymmetric digital-signature infrastructure
has been implemented. HMAC provides *shared-secret authentication*, not
publicly verifiable digital signatures or proof of a unique human signer.
Production integrations must isolate key material in a trusted service,
define revocation/rotation policy and publish monotonic generation anchors
independently of the untrusted snapshot transport.

`HmacAnchorVerifier` implements the existing PALACO Audit
`AuditAnchorVerifier` interface, so recovered records remain inspectable
but cannot execute, authorize or resume tasks. GO-13 remains HOLD.
