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

## v0.13 monotonic publication proposal (DRAFT / HOLD)

`palaco_audit::orcheastra::publish` introduces a separate
`CheckpointPublisher` contract and `publish_checkpoint` function.
Before proposing the next checkpoint, it fetches an independently
verified previous anchor for the exact journal ID, validates the whole
candidate snapshot, requires a strictly larger decision sequence, confirms
the same immutable task-plan digest and verifies the previously committed
chain head at the exact prior sequence. The candidate generation must be
exactly the previous generation plus one.

The publisher must perform an **authenticated, atomic compare-and-swap**
against the independent authoritative anchor. A stale writer, missing
anchor, altered historical prefix, changed task plan or exhausted
generation is rejected. A successful result is only evidence that the
audit publisher accepted a checkpoint, not task admission or execution.

This is a protocol and test-double boundary, not a deployed persistent
generation service or a distributed transaction. The publisher contract
has no implementation backed by production storage. For production,
bind the journal ID, authenticated writer identity, signing key,
checkpoint and monotonic generation in one auditable durable transaction,
with explicit crash recovery and revocation checks. Never infer current
authority from any historical `Proposed` journal entry. GO-13 HOLD remains
in force.

## v0.14 staged file + audit checkpoint publication (DRAFT / HOLD)

`palaco_audit::orcheastra::staged_commit::stage_then_publish` now
composes existing interfaces in a fail-closed sequence: fetch the trusted
previous checkpoint; validate strict plan/sequence/prefix extension;
stage the versioned snapshot in an immutable local generation file;
reopen and verify the exact staged bytes; only then ask the independent
`CheckpointPublisher` for its authenticated CAS publication.

The local file is never itself trusted. An interrupted, rejected or
ambiguous CAS can leave an *orphaned unanchored snapshot*, which recovery
must refuse by checking the authoritative generation and checkpoint.
No automatic deletion/retry of a conflicted generation is attempted.
Regression tests cover successful file reopen through the read-only
PALACO Audit recovery API, rejected publisher leaving an untrusted orphan,
and malformed candidate rejected before staging.

This is a composition and fault-injection test, not an atomic transaction
across filesystems and a remote audit service. Real crash consistency,
multi-host durability, authority authentication, key custody and independent
generation storage are not yet implemented. Production callers MUST NOT
interpret the return value as permission to execute historic proposals.
GO-13 HOLD continues to apply.

## v0.15 read-only reconciliation after ambiguous publication (DRAFT / HOLD)

`palaco_audit::orcheastra::reconcile` introduces
`reconcile_publication` for cases where an audit CAS result is unknown,
such as a lost acknowledgment or an interrupted process. It asks the
independent trusted verifier for the latest journal-scoped anchor and
compares it with the expected previous and proposed next anchors:

- `Unanchored`: the authoritative anchor is still the previous value.
  The local staged file must remain untrusted, regardless of its content.
- `Conflict`: a different anchor is authoritative, or an authority
  change was detected during verification. No automatic retry/rollback.
- `Committed`: the independently trusted anchor equals the proposal,
  the generation-addressed snapshot file was re-opened and replayed
  through PALACO Audit, and a final anchor read still agrees.

Missing files, invalid journal identifiers and failed verifier reads
produce errors instead of presumed commit success. Tests model a lost
ACK after successful publication, orphaned files after rejected CAS,
competing checkpoints, missing files and an authority advancing mid-read.

This protocol **never** performs CAS, deletes snapshots, executes
historical proposed tasks or grants authority. It assumes an
authenticated and rollback-resistant verifier, separately provisioned
keys, and journal-specific snapshot directories supplied by the host.
The repeated reads are not a substitute for an atomic cross-system
transaction or a linearizable production audit service; such a
service is still unimplemented in this PR. GO-13 HOLD remains.

## v0.16 local immutable checkpoint archive (draft / HOLD)

`palaco_audit::orcheastra::archive` adds a separate on-disk archive
transport for `MacCheckpoint` records. Journal identifiers are mapped
to SHA-256 namespace directories, and each generation is written only
once with a synced temporary file, exclusive hard-link publication and
directory sync. The bounded, versioned binary envelope includes exact
journal scope, key ID, generation, plan hash, sequence, chain head and
the existing HMAC tag. On restart, the archive can re-open a single
specified generation and reject malformed/truncated/extra bytes.

The `LocalArchiveSource` adapter feeds the existing
`HmacAnchorVerifier`, which still requires a **separately provisioned
key and an independent `GenerationAuthority`**. This is an actual
filesystem transport with restart/reopen regression tests, not a
standalone trusted checkpoint authority. Its generation hint must not
come from a self-claimed local archive "latest" filename. A local
attacker could replace the archive and its snapshot together or roll
the disk back. Physical disk durability and race semantics depend on
the underlying filesystem; no distributed consensus, remote timestamp,
rotation/revocation key vault, hardened service boundary or cross-host
atomic transaction has been implemented.

No archive API issues execution permission. GO-13 remains HOLD.

## v0.17 key rotation and emergency revocation (DRAFT / HOLD)

`palaco_audit::orcheastra::key_policy` introduces
`KeyPolicyAuthority` for independently authenticated, journal-scoped
verification key metadata. `RotatingAnchorVerifier` fetches exactly
one untrusted MAC checkpoint, resolves the key policy for its exact
journal/key identifier, rejects revoked keys and generations outside
the policy's inclusive validity window, and then delegates MAC and
independent monotonic generation verification to the existing HMAC
verifier. A pinned, single-record transport prevents a second fetch
from switching the candidate between key resolution and MAC checking.

The regression matrix covers accepting a rotated key, refusing an old
key beyond its generation window, emergency revocation of an otherwise
valid historic MAC, missing policies and stale generations.

**Limitations:** this is a verifier integration contract, not a
production key vault, signing service, secret-rotation ceremony, HSM,
revocation feed, or proof that policy data is independently trustworthy.
Production implementations must authenticate the policy authority,
bind key identity to the journal, isolate key material, enforce revocation
and securely publish the latest high-water generation. Historic audit
decisions are not current authorization. GO-13 HOLD remains unchanged.

## v0.18 revocation and high-water consistency hardening (DRAFT / HOLD)

The rotating HMAC verifier now rereads separately authenticated key
policy and monotonic generation *after* verifying the checkpoint MAC.
It denies recovery when the key was revoked or rotated between reads,
the verification key material or allowed generation window changed,
or a new generation became authoritative during verification. Tests
inject revocation and generation advance between checks; neither
may produce a trusted recovery anchor.

This is a read-side consistency defense, not an independently deployed
key vault or atomic read transaction. For production, key-policy,
journal-scope authorization and high-water generation must be served
by authenticated, consistent authority APIs with revocation epochs
and strong race semantics. A policy change immediately after the
final check is not prevented by repeated reads alone. Historical
journal inspection remains non-executing; GO-13 HOLD remains in force.

## v0.19 consistent authoritative verification boundary (DRAFT / HOLD)

`palaco_audit::orcheastra::consistent_authority` introduces
`ConsistentAuditAuthority` and a read-only
`ConsistentAnchorVerifier`. The adapter pins the untrusted checkpoint
exactly once, verifies journal scope, and delegates combined generation,
key policy, revocation and MAC verification to one authority contract.
That service must provide a linearizable, authenticated view of these
security-critical values; a series of unrelated API reads is not sufficient.

A test-only `RefCell` state holder demonstrates the required decision
semantics, including valid MAC acceptance, revoked-key rejection,
generation rollback rejection, key rotation, corrupted MAC and unavailable
authority. It is **not** a durable, multi-process or remotely
authenticated authority, and must not be promoted into production.

Future production wiring requires: authenticated journal-scoped callers,
hardened key custody, consistent transaction/snapshot isolation,
revocation epoch enforcement, independent monotonic generation
persistence, and explicit crash/partition behavior. The public
`AuditAnchorVerifier` remains read-only, so verified history never
authorizes task execution or releases GO-13 HOLD.

## v0.20 PostgreSQL transaction candidate — not deployed (DRAFT / HOLD)

The reviewed-in-source migration candidate
`docs/architecture/orcheastra-authority-postgres-v0.20.sql`
defines a restricted `palaco_orcheastra_audit` schema with a
journal-scoped high-water state, revocable generation-window key
policy and checkpoint publication history. The
`publish_checkpoint` function locks current journal and key-policy
rows, checks the complete expected generation/sequence/head/policy
epoch and active key, rejects revoked keys, then updates the anchor
and appends a unique history row in the *same PostgreSQL transaction*.
A key-policy trigger bumps the policy epoch after policy updates.
Public schema/table/function privileges are explicitly revoked;
no production role is granted access by this candidate.

The Rust `authority_transaction` module adds an
`EpochGuardedAuthority` adapter and fail-closed publication
function that checks candidate history, key revocation and a
policy-epoch CAS. Fixture tests cover initial commit, duplicate
writer, mid-publication revocation and invalid scope.

**Important limitations:** Neither migration nor Rust adapter
is connected to a running PostgreSQL instance. SQL has not been
applied or database-integration-tested. No service principal is
provisioned; no credential issuance, signing-key custody or verified
HMAC transaction is implemented. The SQL function is a storage
primitive only: it must *never* be exposed to untrusted callers or
used as an authentication decision independently of the secure
service. Before migration, validate PostgreSQL syntax, ownership,
RLS/grants, trigger behavior, lock contention, policy changes
and crash/restore semantics in staging, and independently review
authorization and secret management. GO-13 stays HOLD.

## v0.21 PostgreSQL integration verification (DRAFT / HOLD)

The draft PR now includes
`.github/workflows/orcheastra-postgres-integration.yml`,
which boots a disposable PostgreSQL 16 GitHub Actions service and
applies the v0.20 schema *only to that CI database*. It then runs
`scripts/orcheastra_postgres_integration.py` using a loopback-only
connection and an explicit `PALACO_TEST_EPHEMERAL=YES` guard.
The integration matrix exercises initial CAS and ledger write,
duplicate-writer denial, policy-epoch invalidation and revocation,
transaction rollback of both journal and history, and a two-client
race in which exactly one writer may commit.

This CI job uses synthetic fixture credentials on an isolated ephemeral
container; it does **not** access PALACO Supabase or production databases.
It verifies PostgreSQL storage semantics only, not HMAC or a deployed
trusted authentication service. Production rollout remains blocked
pending service-role review, RLS/grants, key custody, authenticated policy
reads, migration rehearsal, recovery and threat-model evaluation.
GO-13 stays HOLD.

## v0.22 PostgreSQL least-privilege integration verification (DRAFT / HOLD)

The isolated PostgreSQL integration harness now provisions two disposable
`NOLOGIN` test roles: a read-only audit-history reviewer and a fully
unprivileged role. The reviewer receives narrowly scoped schema usage
and SELECT on `anchor_history` only; neither role can execute
`publish_checkpoint`, mutate journal state or read key-policy rows.
Tests switch database roles with `SET ROLE`, expect explicit
permission-denied responses and confirm that blocked attempts do not
alter the trusted generation. The existing duplicate CAS, concurrent
writers, revocation and full transaction rollback cases remain enabled.

No roles or grants are created outside the ephemeral GitHub Actions
PostgreSQL 16 container. The draft migration deliberately grants no
trusted publisher role. These are *negative authorization tests*, not
production authentication, cryptographic key custody or proof that a
service role is correctly provisioned. Production role provisioning,
RLS and tenant isolation, migration review and end-to-end security
service remain unimplemented. GO-13 HOLD is unchanged.

## v0.23 isolated PostgreSQL process-restart recovery (DRAFT / HOLD)

The disposable PostgreSQL 16 GitHub Actions service is now restarted
**after** the CAS, revocation, rollback, concurrency and least-privilege
tests have run. A second test invocation,
`scripts/orcheastra_postgres_integration.py --verify-restart`, opens
fresh client connections and checks that the committed generation,
sequence, chain head and history row survived the PostgreSQL service
restart; the rolled-back journal and history remain absent; revoked
key policy and its updated epoch persist; duplicate and revoked
publications are still denied; and the read-only role cannot publish.

The database is the same ephemeral container, never a connected
PALACO production instance. These tests exercise PostgreSQL
process restart, WAL recovery and read-side consistency only; they
do NOT prove recovery from hardware failure, disk rollback, disaster
restore, permanent data-loss scenarios, encrypted key vault durability,
independent MAC signing, cross-host consensus or end-to-end authorization.
The audit history remains non-executable. GO-13 HOLD remains.

## v0.24 operation-scoped audit service boundary (DRAFT / HOLD)

`palaco_audit::orcheastra::service_boundary` separates the
`Verify` and `Publish` audit operations. `AuthenticatedAuditCaller`
is a **trusted host integration** that MUST authenticate caller identity,
expiry, audience, revocation and exact journal scope independently of
client-supplied data. The read-only `verify_for_caller` API returns only
the trusted checkpoint; `publish_for_caller` forwards a strictly
validated candidate to the epoch-guarded transactional CAS contract.
Unit tests deny cross-journal requests and verify-only attempts to
publish, ensure blocked requests never call the backend, and exercise
a distinct authorized publication request.

This Rust layer is not an actual network authentication service or
a credential issuing endpoint. Production callers MUST recheck the
operation-scoped authorization *inside* the backend's atomic database
transaction; otherwise a permission revocation after the initial check
may race the publish operation. No user session, bearer token, signing
key, real database role or external principal is provisioned by this
change. Historical decisions remain inert. GO-13 HOLD is unchanged.

## v0.25 authorization-epoch guarded database publication (DRAFT / HOLD)

The new candidate `docs/architecture/orcheastra-authority-authz-v0.25.sql`
adds per-journal principal policy and a monotonic authorization epoch.
A policy-change trigger advances that epoch under the same journal row
lock used for checkpoint CAS. `publish_authorized_checkpoint` locks the
journal and caller-policy row in a consistent order, checks the expected
authorization epoch, explicit publish permission, nonrevocation, then
invokes the existing epoch-protected checkpoint publication in the
**same PostgreSQL transaction**. Denials do not append audit records.

The isolated CI suite `scripts/orcheastra_postgres_authz_integration.py`
tests a permitted publication, replay rejection, stale authorization
epoch, revoked principal, removed publish permission, unknown journal,
wrong principal and transaction rollback. No SQL is applied to any
connected PALACO system; CI uses a disposable PostgreSQL 16 instance.

**Security gate:** `p_principal_id` is a fixture identifier passed as
SQL data, **not** an authenticated identity. This SQL function MUST NOT
be exposed to clients. A future independent service must bind principal
identity cryptographically to its transport, prevent impersonation,
enforce exact journal and operation scopes, deny direct access to the
legacy unguarded publisher, and integrate authentication/HMAC/key
custody with the database transaction. This candidate demonstrates
revocation serialization only, not a finished trusted authority.
GO-13 HOLD and non-execution requirements remain unchanged.

## v0.26 database-session-bound principal facade (DRAFT / HOLD)

`docs/architecture/orcheastra-authority-session-v0.26.sql`
adds a narrowly granted PostgreSQL `SECURITY DEFINER` facade that
derives principal identity from **`session_user`**, rather than from
an untrusted `principal_id` argument. It routes into the v0.25
authorization-epoch CAS with journal scope, key revocation, and
policy-epoch checks. Its `search_path` is pinned to `pg_catalog`,
and the facade is revoked from PUBLIC in the same transaction in
which it is created.

The isolated GitHub Actions database provisions a disposable
password-authenticated LOGIN role and grants it only schema usage
and execution of the session-bound facade, never the lower-level
publisher, caller-policy table or journal-state tables. Negative
tests attempt direct legacy/parameterized publishing, revoked
publication, unknown journal, missing per-journal permission and
duplicate publication. An authenticated PostgreSQL session identity
cannot be substituted by passing a different `principal_id` value.

**Production security limitations:** this is a CI-only database role
integration, NOT a deployed identity provider, end-user login, managed
secret or mTLS service. The fixture uses a local test password and
loopback transport. Production would require reviewed non-superuser
function ownership, hardened GRANTs, transport authentication,
connection-pool identity safety, independent HMAC verification,
audited key custody, and adversarial role/search_path review.
Do not directly expose the old lower-level functions to any
application role. GO-13 remains HOLD.

## v0.27 journal-first authorization revocation serialization (DRAFT / HOLD)

The PostgreSQL candidate
`docs/architecture/orcheastra-authority-ordering-v0.27.sql`
adds a restricted `set_caller_publication` policy-mutation primitive.
It explicitly acquires the `journal_state` row lock *before*
updating `caller_policy`; the existing authorization-epoch trigger
increments the epoch in the same transaction. The v0.25 publisher
already acquires the same journal lock first, so cooperating policy
mutations and checkpoint publications serialize without lock-order
inversion. The migration deliberately grants no publisher role access
to policy mutation.

The isolated database test concurrently submits a session-bound
publication and an administrator revocation, accepts only outcomes
that correspond to a valid serialization order, and verifies that
the revoked caller cannot publish afterward. It also checks the
authorization epoch and that no spurious audit history was written.
A success **before** revocation linearizes is possible and correct;
publication **after** committed revocation must be refused.

This contract requires all privileged policy writers to follow the
journal-first locking discipline. Legacy direct table UPDATE/DELETE
by a database owner can still create an inverted lock order or bypass
expected epoch semantics; production must constrain all mutation
paths, including key policy deletion, and separately review lock
timeouts, superuser bypass, service identity, key custody and HMAC
verification. This code is only applied to a disposable CI database.
PR remains DRAFT; GO-13 HOLD remains.

## v0.28 key-policy mutation and deletion guards (DRAFT / HOLD)

The candidate migration
`docs/architecture/orcheastra-authority-key-policy-v0.28.sql`
adds `set_key_revocation` and `rotate_active_key`, both of which
lock `journal_state` before the journal's key-policy row.
`set_key_revocation` advances the key-policy epoch via the v0.20
trigger. `rotate_active_key` accepts only a pre-existing,
nonrevoked key permitted for the next generation, and increments
the epoch when the active key changes. Both return false for
missing journals, unknown keys or invalid requests.

Physical DELETE of `key_policy` and `caller_policy` rows is
rejected by triggers, preserving revocation/policy tombstones
in the audited data model. The migration grants NO privileges to
application publisher or reader roles. A new isolated PostgreSQL
test races a session-bound checkpoint publication with journal-first
key revocation, verifies the key remains revoked, checks that
old keys cannot publish after rotation, enforces deletion denial,
and tests unprivileged callers cannot invoke the mutation functions.
The tests permit only a publication that linearizes before revocation.

**Remaining limits:** a database owner/superuser can modify or
disable triggers and may perform raw table updates; the guards
are not an external immutable trust anchor. Every trusted policy
writer must follow the journal-first locking contract. Physical
key deletion and caller-policy deletion are intentionally blocked,
not silently interpreted as revocation. This does not integrate
cryptographic key custody, production service authentication or
a remote HMAC authority. SQL executes only in disposable CI;
no PALACO production migration, merge or deployment is authorized.
GO-13 HOLD remains unchanged.

## v0.29 transactional policy-event evidence (DRAFT / HOLD)

The isolated PostgreSQL migration
`docs/architecture/orcheastra-policy-evidence-v0.29.sql` adds a
`policy_change_history` table and an `AFTER UPDATE` journal-state
trigger. Each monotonic key-policy or authorization-epoch change is
recorded in the **same PostgreSQL transaction** as the policy mutation.
The entry includes the journal scope, category, old and new epoch,
previous/current active key IDs, observed generation, database
`session_user` and timestamp; it stores no secret key material.

The trigger fails closed if an epoch decreases or the active key changes
without advancing the key-policy epoch. Unique
`(journal_id,category,epoch)` ordering prevents duplicate epoch
records. UPDATE, DELETE and TRUNCATE triggers reject modifications
to the policy-event table, and restricted publisher roles receive no
access. The isolated integration tests check key and caller revocations,
rotation attribution, denied raw key swaps, rollback, mutation denial
and privilege isolation.

**Important limits:** this is a same-database event history, not a
cryptographically signed, remotely anchored, append-only archive.
Database owners can disable triggers, modify schema or rewrite data.
The recorded `session_user` is the DB session identity, not an
independently verified human principal. Production requires reviewed
owner separation, immutable off-database replication/anchoring, audit
verification of policy history versus checkpoint history, key custody,
and staging permissions review. No production database migration or
merge has been performed. GO-13 remains HOLD.

## v0.30 independently recalculated policy SHA-256 chain (DRAFT / HOLD)

The candidate PostgreSQL migration
`docs/architecture/orcheastra-policy-hash-v0.30.sql` adds a
`policy_hash_chain` indexed by journal, policy category and epoch.
It backfills existing v0.29 evidence and appends a domain-separated
SHA-256 digest for subsequent events within the same transaction.
Each link stores the previous digest, exact canonical payload bytes
and its own digest. The linked policy epochs are checked before insert.
UPDATE, DELETE and TRUNCATE are rejected; publisher roles have no
direct table grants.

A standalone Python verifier recomputes SHA-256 from the exported
payload bytes, checks predecessor links, contiguous epochs and the
canonical representation of each corresponding event. CI deliberately
mutates a copied payload and removes a predecessor to prove those
changes are detected. The verifier pins the chain heads to a
runner-local JSON manifest **outside the database container**, then
rechecks them after PostgreSQL restarts.

**Limits:** SHA-256 is not a signature or remote authority. The
canonical payload is still produced by PostgreSQL, and the CI
manifest exists only during one ephemeral job; it is neither
independent archival storage nor a durable production root of
trust. Database owners could rewrite both data and chain or remove
a whole scope without an independently retained external manifest.
Hardware failure, restored-old-backup detection and off-host
anchoring are still unimplemented. No production migration or merge
is performed. GO-13 HOLD remains unchanged.

## v0.31 independently signed policy-head checkpoint (DRAFT / HOLD)

A standalone Python verifier now generates and checks an **Ed25519**
signature for the complete set of v0.30 journal/category policy-head
digests. `scripts/orcheastra_policy_signed_checkpoint.py` first
recomputes the PostgreSQL policy hash chain independently, serializes
the *complete* head map using deterministic JSON and signs those exact
bytes with a fresh OpenSSL-generated ephemeral private key outside the
PostgreSQL container. It pins the trusted public key and detached
signature on the CI runner, then destroys the signing private key.
Subsequent verification uses only the pinned public key, signed
manifest, and independently recalculated database heads.

The CI matrix deliberately tests altered signed bytes, a different
public verification key, and a database-rollback simulation which
removes the newest event from one otherwise internally consistent
policy chain. This last case demonstrates why a correctly recomputed
hash chain is insufficient: its *old* head must disagree with the
independently signed expected head. After PostgreSQL process restart,
CI repeats signature verification and the complete DB-head comparison.

**Boundaries:** these files exist only for one disposable CI runner.
There is no durable off-host transparency log, trusted timestamp,
external HSM/KMS, independently operated witness, or secure production
recovery service. A private key is generated for this test only and
deleted immediately after signing. A modified database cannot be
trusted if the runner's public-key and signature snapshot is also
compromised. Checkpoint validation grants no task-execution authority.
No production migration, merge or release is authorized. GO-13 HOLD
remains unchanged.

## v0.32 root-authorized trust key rotation fixture (DRAFT / HOLD)

A separate ephemeral CI trust lineage models signed Ed25519 key
rotation with explicit, monotonic versioning. A newly generated
temporary root signs the successor's *exact* public key and transition
from version 1 to 2. The successor signs a version-2 policy-head
checkpoint. The trusted root public key, successor public key,
rotation signature, checkpoint signature and high-water version
reside on the CI runner **outside PostgreSQL**. Both private keys
are deleted after signing; subsequent verification requires only
the pinned public keys and signed records. Tests reject altered
rotation metadata, altered checkpoint versions, key substitution
and high-water downgrades and repeat verification after restart.

This intentionally starts a **new test trust lineage**: the v0.31
private key was already destroyed, so it cannot authorize a real
rotation to v0.32. Do not silently reinterpret the v0.32 root
as a successor to v0.31 or claim an actual production rotation.
The fixture does not advance a live policy head or operate an
off-host trust store, KMS/HSM, timestamp/witness service or backup
recovery authority. A compromised CI runner can alter locally pinned
trust records. An authenticated trusted root must be established
independently before deployment. Neither signature validation nor
historical recovery grants execution permissions. GO-13 HOLD.

## v0.33 signed trust-state registry and non-executing recovery gate (DRAFT / HOLD)

`scripts/orcheastra_trust_registry_v033.py` adds a **separate,
disposable CI trust-registry fixture**. A newly generated, independent
Ed25519 test root signs a complete policy registry containing exact
key IDs, status (`active`, `revoked`, `expired`), validity
timestamps and minimum checkpoint versions. A runner-local high-water
record pins registry version 3, checkpoint version 2, and the
SHA-256 digest of the signed v0.32 checkpoint. The registry signature,
pinned public root and high-water record are held outside PostgreSQL.

The reader verifies the already pinned v0.32 trust rotation, the
complete registry signature, canonical bytes, checkpoint digest,
highest registered version and policy scope. It then denies unknown
keys, revoked keys, expired keys, out-of-window timestamps, stale
checkpoint versions, registry downgrade and mismatched snapshots.
Additional negative tests attempt to forge a revoked key into active
status and reduce the signed registry version. The test signer
private key is deleted before subsequent verification; the entire
admission check is repeated after database restart.

**Important:** the test clock is a pinned UTC fixture value, not a
trusted production clock. This is a separate CI root, *not* a
retrospective signature from the destroyed v0.31 key, and not a
managed off-host root or production identity authority. The fixture
does not preserve trust data across CI runners, support disaster
recovery, distribute keys, or verify a real PALACO One principal.
Recovering a valid historical audit checkpoint remains read-only and
NEVER authorizes task execution. GO-13 HOLD and DRAFT remain.

## v0.34 fail-closed read-only recovery dispositions (DRAFT / HOLD)

The isolated `scripts/orcheastra_recovery_disposition_v034.py`
provides explicit classifications `VERIFIED`, `STALE`,
`REVOKED` and `UNAVAILABLE`. **Every** disposition carries a
mandatory `execution: HOLD`. The classification distinguishes
expired/revoked keys, unknown or malformed trust state, older
checkpoint or registry versions, wrong checkpoint digests, invalid
validity windows and absent high-water data.

The production-facing entrypoint concept, `trusted_recovery`, first
validates the v0.32 rotation and independently calculated database
heads, the v0.33 registry's Ed25519 signature, the signed checkpoint,
and the pinned digest. Any absent, corrupt, ambiguous or otherwise
unverifiable trust material yields `UNAVAILABLE`, not authorization.
The separate pure `decision` function assumes those proofs were
already authenticated; it MUST NOT be exposed directly to
untrusted callers as a security boundary.

Ephemeral CI tests exercise 12 positive/negative classifications,
assert `execution = HOLD` in every case, and re-verify the authentic
checkpoint after PostgreSQL restart. Tests use a fixed UTC fixture
clock; no secure network time source, durable external witness, real
service identity or independent key custody is connected.
`VERIFIED` means read-only historical audit verification only.
It never grants execution of a task, decision, account operation or
network action. PR #348 remains DRAFT and GO-13 HOLD.

## v0.35 reproducible, read-only recovery evidence report (DRAFT / HOLD)

The isolated CI tool `scripts/orcheastra_recovery_report_v035.py`
reconstructs the current `VERIFIED` recovery disposition through
the authenticated v0.34 verification path and creates a canonical
JSON report. It captures the fixed test-clock observation, explicit
disposition and `execution: HOLD`, version numbers of the v0.30–35
controls, and a closed allowlist of SHA-256 digests and byte lengths
for 15 pinned proof artifacts (public keys, signed checkpoints,
rotation evidence, registry and high-water records). No private
signing keys, database credentials or bearer tokens are exported.

A SHA-256 digest covers the complete canonical report. CI rejects
modified report contents, attempts to self-hash an unauthorized
`execution: ALLOW` report, missing evidence references, stale
control versions and incomplete JSON. After a PostgreSQL service
restart, it recalculates **all** evidence hashes and verifies the
entire recovered disposition and report against the runner-pinned
copy. Any missing, mismatched or unverifiable input fails closed.

**Boundaries:** report hash integrity is not an Ed25519 report
signature, secure trusted timestamp, remote audit witness, or durable
off-runner archival evidence. The test clock is fixed; results are
meaningful only within the isolated CI run, whose local trust
artifacts are separately protected only by runner isolation.
`VERIFIED` is strictly historical, read-only audit status;
`authorization: NONE` and `execution: HOLD` remain mandatory.
No production deployment, merge or external execution occurs.
GO-13 HOLD and DRAFT are unchanged.

## v0.36 portable, signed recovery evidence bundle (DRAFT / HOLD)

The isolated `scripts/orcheastra_recovery_bundle_v036.py` creates a
deterministic ZIP containing the canonical v0.35 recovery report,
its detached **Ed25519 signature**, the report signer public key,
a canonical evidence manifest, and **exact bytes** of the 15
allowlisted v0.35 evidence artifacts. The signer private key is
generated on the CI runner, never included in the ZIP, and deleted
after signing. The verifier accepts the signer only if its public
key SHA-256 fingerprint matches a separately supplied trusted pin.

The portable command requires no database connection:
`python3 scripts/orcheastra_recovery_bundle_v036.py --verify-portable
/path/to/recovery-evidence-v036.zip /trusted/report-signer.sha256`.
It validates archive member allowlisting, duplicate entries, size
limits, detached signature, canonical report and manifest, individual
evidence hashes and lengths, and mandatory
`authorization: NONE` / `execution: HOLD`. CI explicitly clears
database environment variables for this verification. It also tests
for a forged execution decision, altered/missing evidence, a forged
manifest and the wrong pinned public-key fingerprint.

An in-run database-aware verification additionally recomputes the
trusted current recovery report and checks equivalence, including
after a PostgreSQL service restart. The portable check proves package
integrity **relative to the separately trusted public-key pin**; it
does NOT independently query live revocation status or know if an
entire valid package is obsolete. The archive is not uploaded,
published or issued as a live trust certificate, and its ephemeral
signer is NOT a production PALACO authority. Public-key pins need
secure out-of-band distribution; retention beyond the CI job,
timestamping, off-host storage and independent witnessing remain
unimplemented. `VERIFIED` means read-only historic evidence only.
PR remains DRAFT; no merge, deploy or execution. GO-13 HOLD.

## v0.37 controlled evidence handoff, retention and freshness (DRAFT / HOLD)

The isolated `scripts/orcheastra_evidence_handoff_v037.py`
uses the portable v0.36 signed evidence bundle as input and writes
a canonical handoff manifest with exact SHA-256 of that bundle,
pinned signer-public-key digest, explicit scope and a monotonic
`sequence`. A separately supplied high-water policy records the
minimum trusted sequence and newest bundle digest. The receiver
first verifies the Ed25519 signature, then assesses the bundle's
freshness relative to this independently pinned high-water state.

**Critical distinction:** a bundle can remain cryptographically
`VERIFIED` but be classified `HISTORICAL` rather than
`CURRENT` when its sequence is lower than the independently
trusted minimum, or its digest differs from the latest trusted
digest. Future unanchored sequences and absent/malformed high-water
data are rejected. The receiver refuses to grant authority under
either classification: all outcomes include
`authorization: NONE`, `execution: HOLD` and `read_only: true`.

The handoff carries explicit retention metadata:
`CI_FIXTURE_NO_ARCHIVE`, `preserve_original=true`,
`automatic_purge=false`, `deletion_allowed=false`, and
`review_required_for_disposal=true`. This is an explicit policy
statement, **not** a deployed storage/retention enforcement system.
CI exercises valid current evidence, a historical still-signed
bundle, mismatched latest digest, bad sequence, unavailable high
water, forged execution permission, silent purge request and wrong
signer pin. The portable verifier is exercised with DB variables
cleared and checked again after PostgreSQL restart.

**Trust boundary:** the high-water manifest is supplied separately;
the fixture itself does not sign, timestamp or publish that manifest
via an independent service. A receiver MUST obtain and authenticate
it through an independent trusted channel. An attacker controlling
both the bundle and its high-water file may forge currency claims.
No durable off-host archival system or production transfer has been
implemented; no release/merge is authorized. GO-13 HOLD.

## v0.38 separately signed high-water witness (DRAFT / HOLD)

The isolated `scripts/orcheastra_signed_high_water_v038.py`
generates a new CI-only Ed25519 witness identity and signs a
canonical statement containing the entire v0.37 high-water record,
an explicit witness version, and `authorization: NONE` /
`execution: HOLD`. The witness signer public-key fingerprint and
minimum accepted witness version are pinned separately on the
CI runner, *outside* the transferable evidence bundle. The private
signing key is deleted immediately after signing.

An offline receiver first checks that the separately supplied witness
public key matches its trusted fingerprint, authenticates the
detached signature, rejects versions below the independently held
floor, and only then passes the authenticated high-water policy to
the v0.37 transfer verification logic. A valid historical bundle
therefore cannot be represented as `CURRENT` merely by editing
the high-water JSON. Tests reject changed witness versions and
bundle hashes, an incorrect signature or witness public key,
missing statement bytes, and versions beneath the trusted floor.
CI explicitly clears database environment variables for the
portable verification and repeats the check after PostgreSQL restarts.

**Trust boundary:** both trusted fingerprint and minimum accepted
witness version must be distributed and maintained securely through
an independent channel. This example signs only a disposable CI
fixture; it has no independent off-host operator, durable clock,
public transparency service, or rollback-resistant production
counter. An old valid signature remains replayable if the receiver
loses its independently pinned version floor. This does NOT grant
task execution or production authority. PR #348 remains DRAFT,
GO-13 HOLD, with no merge or deployment.
