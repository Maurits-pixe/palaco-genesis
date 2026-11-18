# PALACO Trusted Evidence v17 — Durable Replay Registry

**DRAFT / GO-13 HOLD. No production authorization or deployment.**

`durable_replay_registry_v17.py` implements a local SQLite callback for v16 `receive_exchange(..., claim_replay=...)`. It uses a transactionally unique key `(sender_id, recipient_id, message_id)` and records a SHA-256 digest of the exact signed package. It returns literal `True` for the first claim and literal `False` for all later claims of the same triple, **even if** ciphertext and package digest change.

## Candidate implementation

- Uses a SQLite `PRIMARY KEY` plus `BEGIN IMMEDIATE` to serialize writers and ensure one claim wins in a trusted single-machine SQLite deployment.
- Validates all three identifiers against the existing v16 identifier contract and the digest as exactly 64 lowercase hex characters.
- Uses `PRAGMA synchronous=FULL` and explicit commit, with rollback on exceptions.
- A new instance may reopen an existing database and discover prior claims. `inspect(...)` offers read-only local diagnostics.
- SQLite triggers refuse ordinary `UPDATE` or `DELETE` operations. The module does not provide claim expiry, reset, deletion or replay-policy override.
- No signing keys, raw message bytes, plaintext or governance receipts are stored. Identifiers remain metadata subject to privacy controls.

## Integration

```python
from durable_replay_registry_v17 import DurableReplayRegistry
from authenticated_exchange_v16 import receive_exchange

replay = DurableReplayRegistry("/trusted/local/claims.sqlite")
# This only supplies a replay callback; verify_sender must be a genuine,
# independently provisioned/current key and revocation policy validator.
# No test callbacks should ever be used to authenticate real users.
# plaintext, report = receive_exchange(
#     signed_bytes, expected_recipient_id="recipient-001",
#     recipient_private_key=receiver_private_key,
#     verify_sender=trusted_sender_verifier, claim_replay=replay)
```

This is **not** end-to-end integration or a verified trust source; it is a local interface illustration.

## Test coverage

```sh
python -m unittest discover -s release-registry -p 'test_durable_replay_registry_v17.py' -v
```

20 authored scenarios cover initial claim, repeated claims, modified ciphertext with reused ID, persistent claims after restart, distinct IDs/senders/recipients, concurrent writers across same/different instances, malformed identifiers and digests, no state mutation on invalid claims, database mutation/deletion guards, empty lookup and invalid filesystem paths.

**Test execution is not independently verified.** A correct test file or successful web deployment status does not establish SQLite concurrency guarantees on every filesystem or real-world recovery behavior.

## Important residual risks

- **Not distributed:** devices with different database files can each accept a first claim. A centrally shared atomic registry or independent cross-device coordination is required for global replay resistance.
- **Not tamper-proof:** a privileged process can replace the whole SQLite file, remove triggers or restore an old copy. A separately trusted monotonic checkpoint and storage permissions are necessary.
- **Not hardened against filesystem race attacks:** paths with hostile ancestor symlinks, database replacement between initialization and connection, filesystem snapshots and SQLite journal/WAL sidecars are not protected by this candidate.
- **No guaranteed crash/power-loss durability** independent of filesystem, drive controller and OS behavior; durable testing and backup/restore rules remain required.
- A transient error or database lock must fail closed via the v16 receive contract. Do not fall back to in-memory acceptance.
- Recipient-key trust, Ed25519 signer identity, revocation, trusted time and key lifecycle remain separate external obligations. Decrypted content still requires v14 evidence verification before any interpretation.

**GO-13 HOLD — no merge to main, user-account changes, production publication, issuance, or recovery authorization.**
