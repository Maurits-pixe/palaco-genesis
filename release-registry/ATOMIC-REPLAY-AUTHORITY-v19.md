# PALACO Trusted Evidence v19 — Atomic Replay Authority (draft)

**GO-13 HOLD — NOT a live central authority, distributed database or recovery authorization.**

`atomic_replay_authority_v19.py` implements a local single-SQLite-file replay coordinator and an explicitly external signing interface for the v18 distributed replay contract.

## Mechanism

- An external `authorize_candidate(claim)` callback must authenticate the submitting device/sender and current policy before the coordinator considers a claim. Only literal `True` proceeds. **This callback is not implemented and may become stale while a transaction is waiting**, so a production design must bind policy freshness to atomic intake.
- `decide(claim)` acquires `BEGIN IMMEDIATE`, counts and checks the local decision sequence, and assigns one monotonic local integer for each decision.
- A unique first-claim index on `(sender_id,recipient_id,message_id)` determines the winner. First use returns `first-claim`; a subsequent claim with identical package digest is a `duplicate`; the same tuple and a different digest is a `conflict`. A duplicate arriving from another device is still a duplicate.
- The v18 `receipt_statement` binds claim bytes, authority sequence, and decision. A REQUIRED `sign_receipt(statement)` callback returns an opaque proof string that is committed alongside the decision in one SQLite transaction. The signing callback is **not** a trusted signer implementation. A signer failure aborts DB changes. A signed-but-uncommitted orphan receipt remains a risk; verifiers must require committed, independently anchored decisions.
- `read_decisions` checks local history continuity, canonical records, local first-winner index consistency and decision ordering. It exports claims and v18-shaped receipts for separate verification through `inspect_decisions`.
- SQLite triggers prevent ordinary UPDATE/DELETE on both tables. They cannot block privileged file replacement, malicious schema changes, storage rollback or copying a database to another server.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_atomic_replay_authority_v19.py' -v
```

22 regression scenarios were authored covering first/duplicate/conflict, restart, alternate devices, same-file concurrent claims, sequential order, intake denials/failures, signer errors and rollback, receipt binding, v18 diagnostic interop, update/delete triggers, corrupted index/history and invalid candidates. **The suite has been committed but its successful execution has not been independently established.**

## Security requirements before any production use

1. Independently authenticated, active signer identity/key policy, secure hardware or equivalent private-key custody and revocation-aware Ed25519 signer implementation; do not equate a string returned by `sign_receipt` with a valid signature.
2. Durable, externally stored and authenticated monotonic decision watermark. The current local sequence can be rolled back by replacement of the whole SQLite database. A receipt from this coordinator alone is not trustworthy.
3. Centralized atomicity across *all* PALACO device recipients. Two separate SQLite copies can each grant a `first-claim`, so this implementation is **single-writer-database only**, not distributed consensus.
4. Recovery testing, power-loss injection, filesystem hardening, concurrency and load testing, transaction-vs-signature atomicity or outbox design, authenticated transport, tenant separation and auditable key rotation.
5. Current revocation checks and sender permission must be revalidated at a point consistent with the decision commit. Pure test callbacks that always approve are NOT policy.
6. Sensitive metadata privacy, retention and controlled access, and full v14 evidence verification after decryption. No execution is permitted merely from a first-use receipt.

**No merge to main, account modification, production activation, receipt issuance for real users, or recovery authorization.**
