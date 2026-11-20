# PALACO Trusted Evidence v21 — Monotonic Authority Checkpoints

**DRAFT / GO-13 HOLD.** This module does **not** implement an authoritative external ledger, authenticated checkpoint storage, signing-key custody or a production-ready rollback defense. It defines a strict verifier contract that can be tested with synthetic checkpoints.

## Implementation

`monotonic_authority_checkpoints_v21.py` composes the existing v19 `read_decisions()`, v18 domain-separated statements and v20 Ed25519 proof verification.

- `checkpoint_candidate(claims, receipts)`: derive a deterministic candidate root using a SHA-256 hash chain, including the previous hash, monotonically contiguous sequence, the SHA-256 hash of each exact v18 receipt statement and the SHA-256 hash of its opaque proof. A computed root is **not** a trust anchor.
- `verify_checkpoint(claims, receipts, get_trusted_checkpoint, verify_receipt)`: replay every decision, enforce first/duplicate/conflict consistency, contiguous sequence and required receipt signatures. It then compares the exact calculated `(sequence,head)` to independently authenticated, monotonic external `get_trusted_checkpoint()`. Neither a lower older root nor a higher unmatched root is accepted. Only literal Boolean True from independent `verify_receipt(statement, proof)` is sufficient. An unsigned/empty history cannot be trusted.
- `AnchoredCommitInspector(authority, get_trusted_checkpoint, verify_receipt)`: a v20-compatible `verify_committed(statement)` callback. It reads a **fresh full v19 history each call**, verifies all signatures and the external checkpoint, then returns True only if the exact statement exists in that validated history. A local cache cannot silently continue to trust obsolete history.
- The external `verify_receipt` callback must cryptographically validate the authority's signature, trusted signer identity, current key policy and revocation, but MUST NOT itself recurse into v20's committed-decision callback. Use a trust adapter such as v7 Ed25519 with independent pinned keys. `get_trusted_checkpoint` must come from an independently authenticated, monotonic store and never compute its value from the local SQLite file.
- Inspection always returns `authorization: DENY`, `release: HOLD` and `production_release_enabled: false`. Existence of a verified receipt remains proof inspection, **not** execution permission.

## Test scenarios

```sh
python -m unittest discover -s release-registry -p 'test_monotonic_authority_checkpoints_v21.py' -v
```

22 synthetic regression cases are committed for deterministic roots, appended history, stale checkpoints, signature tampering, modified/deleted history, wrong/future/Boolean checkpoints, missing/failed providers, double-first-claim and sequence-gap detection, fresh vs stale v19 history, v20 verifier integration and non-authorization. The keys are generated ephemerally inside tests and independent trust callbacks are synthetic fixtures. **Tests have been authored, but their execution is not independently confirmed.**

## Important unimplemented requirements

- Production-grade authenticated monotonic checkpoint storage outside the v19 SQLite host (such as an independently secured append-only anchor with signed time/provenance and durable checkpoints).
- Committed vs orphan receipt proof across external HSM and database transactions. v19 signs inside SQLite transaction; an orphaned signature alone is never acceptable. v21 assumes the local v19 readback is trustworthy only when its *complete root* matches a separately controlled checkpoint.
- Synchronization and atomically published checkpoint after each DB commit; consistency of commitment/anchor publication is **not guaranteed**, so unavailable checkpoints must deny rather than use locally calculated fallback.
- Multi-instance distributed consensus, secure retention, trusted epoch/key rotation/revocation, disaster recovery and adversarial storage tests.
- No guarantees against privileged replacement of the checkpoint provider or its keys. Only an independently controlled anchor can make rollback detection meaningful.

**GO-13 HOLD: no merge, deployment, account changes, key issuance, receipt publication for real people, automatic recovery or production release.**
