# WNRA-04F — Durable one-shot lease ledger and crash-boundary contract (DRAFT)

**Date:** 2026-11-11 (Europe/Amsterdam)  
**Repository:** `Maurits-pixe/palaco-genesis`  
**Parent:** PR #281, head `0a526547273261bc06e89d7ddf29558489f13f0c`  
**Status:** DERIVED DESIGN / NOT IMPLEMENTED / NOT AUTHORIZED  
**Gates:** GO-13 HOLD; AUTHORIZATION DENY; no merge, production credentials, signing, runtime activation or release.

## 1. Evidence: what the preceding slice does and does not prove

PR #281's exact head had four successful GitHub workflows: native Windows metadata `42963409777` (job `130334992198`), PALACO CI `42963409760`, Citadel A1 `42963409864`, SBOM `42963409728`. The native Windows log showed **8/8 WNRA-04E lease-model tests `ok`**, with no skips in that suite. The model is explicitly in-memory, single-process, manually clocked and uses simulated stale revisions. It does **not** provide real atomicity across workers, durable state, authenticated producer statements or issuance authority.

**Goal:** specify a transaction-safe, crash-conservative persistence boundary for a future *test-only* implementation. A design and a simulator cannot confer a production capability.

## 2. Proposed persistence boundary

Use a worker-owned transactional data store with **one authoritative writer transaction per lease transition**, a unique key on `lease_id`, and durable commits. SQLite is an acceptable candidate for a **single-host disposable test harness**, with one database file and no shared-network filesystem; it is not automatically suitable for multi-host coordination or production. A multi-host system requires an explicitly selected authoritative transactional service and failover/fencing proof. Do not silently substitute eventually consistent caches, JSON files, browser storage or filesystem locks.

Minimal logical schema (illustrative only):

| Field | Purpose |
| --- | --- |
| `lease_id` | Unique opaque identifier, never reusable |
| `statement_ref`, `build_id`, `attempt_id`, `artifact_ref` | Immutable source and attempt binding |
| `consumer_id`, `audience` | Restricted reader and scope |
| `not_before`, `expires_at` | Trusted-time window |
| `state`, `revision` | Versioned one-shot transition |
| `last_trusted_time` | Reject rollback or indeterminate time |
| `revoked_at`, `terminal_reason` | Revocation/deny lineage |
| `transition_id`, `audit_ref` | Idempotency and append-only audit correlation |

Unique constraints must cover `lease_id`, `transition_id` and any issuer-defined anti-replay source nonce. New issuance for the same `statement_ref`/`attempt_id` is forbidden unless a separately approved rotation/retry contract says exactly how duplicates are fenced.

## 3. Atomic transition and durable audit discipline

Every transition is a single ACID transaction:

1. Begin transaction and read lease row at expected `revision`.
2. Verify trusted-time bounds, issuer/revocation and identity/role binding **outside the attacker's control**. A test harness may supply fakes, but must label them as such.
3. Compare-and-swap `WHERE lease_id = ? AND revision = ? AND state = ?`; require exactly one updated row. If 0 rows changed, return `DENY`, never retry into a newly granted permit.
4. Record a correlated **append-only transition event in the same transaction**, with nonsecret identifiers, previous/new state, monotonic revision and decision reason.
5. Commit durably before any capability is handed off. A commit error, read-only database, full disk, uncertain fsync result or lost audit insert must fail closed.

The real file-handle capability must never be stored in the ledger. Persistence stores nonsecret references only, bound to a worker identity. On restart, no stale process handle may be reconstructed from a string.

### Crash matrix

| Failure boundary | Required recovery outcome |
| --- | --- |
| Before commit for `ISSUED -> REDEEMING` | Transaction absent, no read capability handed off |
| After committed `REDEEMING`, before read | On restart conservatively mark `DENIED`; no automatic reissue |
| During read/staging | No partial bytes published; `REDEEMING` remains unreusable |
| After digest match but before `CONSUMED` commit | No governed handoff; recover as denied/indeterminate |
| After `CONSUMED` commit, client response lost | Repeat returns existing result reference, never another read |
| During revocation vs handoff | Serialize/fence against same lease revision; revocation wins until a valid committed handoff boundary |
| Storage unavailable or replication/failover uncertain | `HOLD/DENY`; never trust an in-memory optimistic cache |
| Clock rollback or unverified time source after restart | `HOLD/DENY` until trusted-time recovery |

The conservative restart rule must be implemented in a transaction that walks nonterminal `REDEEMING` rows and marks them `DENIED`, with recovery audit events **before** accepting new redemption. Fail shutdown/restart if recovery/audit cannot complete. A committed `ISSUED` row may be eligible only if current trusted time, issuer revocation and statement proof are revalidated; never carry prior authorization from a cached read.

## 4. Concurrency, durability and forensic proof obligations

- **Actual competition:** independently opened connections/processes attempt the same `lease_id` and expected revision; exactly one may commit `REDEEMING`. Record both outcomes without assuming thread scheduling proves multiprocessing atomicity.
- **Crash injection:** terminate a disposable child process at each transaction/read/handoff boundary, reopen database and prove no second successful consumption and no partial materialization.
- **Disk durability:** inject commit errors/read-only, full-disk or journal failure using disposable fixtures. Confirm neither a success response nor capability is produced on ambiguous commit status.
- **Replay:** re-submit `transition_id` after restart and after a lost reply; respond idempotently with non-capability evidence.
- **Audit integrity:** audit rows are append-only under a separate governance policy; modification/deletion is detected by an independently anchored proof mechanism. A simple local hash chain alone is not an independently trusted signature.
- **Clock:** positive time jumps are permitted only within explicit expiry policy; backward jumps or missing trusted time fail closed. Test both `now == expires_at` and clock rollback.
- **Revocation:** test concurrent revocation vs handoff, issuer key retirement and forced recovery; fail closed when current revocation cannot be determined.
- **Isolation:** a disposable test database may model these conditions; it must not read or migrate user-owned or production databases.

## 5. Native Windows and environment questions

If SQLite is chosen for the test-only slice, specify local NTFS assumptions, appropriate locking/isolation and journal durability settings, and run crash/restart fixtures on **native Windows**. Do not presume network share, file locking or WAL semantics are identical across platforms. Review antivirus/file-handle interference and negative `SQLITE_BUSY` conditions. No worker is permitted to interpret an exception as successful redemption. Windows handle-relative source opening and immutable staging remain separate unimplemented security boundaries.

## 6. Next smallest candidate and explicit omissions

**WNRA-04G proposed:** isolated, test-only SQLite-backed lease ledger using disposable temporary directories; unique constraints, CAS update + audit in one transaction, two-connection contention, reopen-and-replay negatives, and crash-boundary negative fixtures. No real issuer, credentials, signatures, native file reads, producer proof, production database or deployed service. Bind Windows CI to the exact candidate head and inspect skipped tests.

Additional future work: authenticated producer event, immutable staging, human security review, application-specific authority gate and eventual release governance. This document itself changes none of those.

## 7. Three-lens AI review

- **TRIAS:** a transactional ledger is required but not sufficient: durable evidence != trusted producer != authorization. GO-13 HOLD / AUTHORIZATION DENY remains.
- **ORACLE:** source for the 8 executed lease-model tests is native Windows run `42963409777`, job `130334992198`, at pinned PR #281 head. Crash recovery, fsync proof, cross-process CAS, trusted time and revocation are **NOT EXECUTED**.
- **MENTOR:** implement only the disposable SQLite harness next, with real connection-level contention and reopen tests. Keep real producer leases and staging out of this slice.

This is an AI review via three lenses, **not** three independent or human approvals. Next admissible transition: `WNRA-04F DRAFT specification` -> `separate DRAFT WNRA-04G disposable ledger candidate`; deployment, production authority, signing, merge and release remain **HOLD/DENY**.
