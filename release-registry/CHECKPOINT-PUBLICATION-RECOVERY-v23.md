# PALACO Trusted Evidence v23 — Checkpoint Publication & Recovery

**DRAFT / GO-13 HOLD. No real trust authority or deployment.**

`checkpoint_publication_recovery_v23.py` implements a local SQLite transactional intent/outbox for coordinating an existing v19 decision journal with a separate v22 checkpoint journal. Because they reside in distinct databases, their commits are **not atomic together**. The outbox records an immutable intent first, allowing a later attempt to inspect whether a checkpoint was already published and avoid a second append.

## Workflow

- `stage_next()` reads the v19 decision history, calculates deterministic v21 prefix checkpoints, requires that the local v22 checkpoint matches the completed local outbox chain, and atomically stages exactly one intent `(sequence, previous_head, head)`. It **never publishes** on staging and refuses a second pending intent.
- `reconcile(verify_receipt, authorize_publish, independently_verify_anchor)` requires three separately controlled trust callbacks. It verifies that v19 still contains the exact target prefix; if v22 is at the predecessor it requests **one** v22 CAS append. If v22 is already at the target it recognizes a possibly lost acknowledgement and does not append again. Any other state is a conflict and is refused.
- Following publication (or detection of prior publication), `independently_verify_anchor(sequence, head)` must consult a **genuinely independent monotonic root**, not the local checkpoint it receives. Only literal Boolean True permits appending an immutable completion record. A failed or missing attestation leaves the intent pending for controlled reconciliation.
- `inspect_local()` returns untrusted counters and pending status. All reports contain `authorization: DENY`, `release: HOLD` and `production_release_enabled: false`.
- Database triggers refuse ordinary UPDATE/DELETE on both intent and completion tables. They do **not** block privileged database replacement, malicious schema changes or whole-file rollback.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_checkpoint_publication_recovery_v23.py' -v
```

22 synthetic regression scenarios were committed: staged intent survives restart, first reconciliation, no duplicate publication, loss of acknowledgement, missing or false/non-Boolean/exceptional external attestations, missing signer/publisher, bad signature/policy, double stage, empty source, next checkpoint, completed restart, deliberate corruption, append-only SQL triggers and permanent DENY/HOLD. **The test code has been committed; successful execution has not been independently verified.**

## Safety and failure limits

- v19 authority records, v22 checkpoint records and v23 outbox are separate SQLite transactions. An interrupted process can leave the checkpoint published but outbox pending; this is intentional. The workflow only converges if genuine independent attestation becomes available.
- No shared distributed consensus, remote publisher, secure root-of-trust, actual Ed25519 enrollment, current revocation authority, trusted time or production authorizer has been implemented here.
- The external callbacks are called inside/outside local transactions as indicated by v22/v23; a remote network call while holding an SQLite write lock can block writers and requires timeout, retry/backpressure and operational redesign.
- The `inspect_local` view is not a trusted release state. A restored older outbox file, replaced v19/v22 database or untrusted attestation callback may defeat local invariants. A separately administered authenticated monotonic checkpoint service is essential.
- No automatic work execution, identity issuance, recovery of live data, user-account mutation, release or authorization may follow from a successful local reconciliation.
- Fault injection, sudden power-loss recovery, malicious filesystem races, end-to-end cryptographic validation, and multi-process/device interoperability need independent test execution and review.

**GO-13 HOLD — no merge to main, no deployment, no real-user receipt publication, no production or recovery authorization.**
