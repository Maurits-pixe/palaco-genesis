# PALACO Trusted Evidence v22 — Durable Checkpoint Anchor Service

**Draft / GO-13 HOLD.** This is a locally durable candidate checkpoint journal in a *separate* SQLite file. It is **NOT**, merely by being separate, an independently trusted monotonic anchor.

## Implemented contract

`durable_checkpoint_anchor_v22.py` offers `DurableCheckpointAnchor(path)`:

- `advance(claims, receipts, expected_sequence, expected_head, verify_receipt, authorize_publish)` validates v21 first-use/duplicate/conflict ordering, contiguous sequence and all receipt checks through a mandatory external signature-and-revocation callback. It verifies the previous complete history hash and proposes one **next** checkpoint only.
- A separate `authorize_publish(sequence, head)` provider must independently authenticate the publisher and current policy. Only literal Boolean `True` permits a local append. This is currently a **callback**, not a real authentication provider.
- SQLite `BEGIN IMMEDIATE` serializes updates and compares the expected `(sequence, head)` to the stored latest row before inserting exactly one new checkpoint. Stale writers fail; updates/deletes are rejected by ordinary SQL triggers.
- `current()` reads and checks the local row linkage after restart, returning `(sequence,head)` for **diagnostic use only**. It is NOT a trusted checkpoint source for v21.
- `inspect(independently_verify_anchor)` requires the caller's separate authenticated, monotonic source to confirm exact `(sequence,head)` before offering a tuple compatible with v21 `get_trusted_checkpoint()`. It fails on missing, exceptional, false or non-Boolean verification and on empty history.
- Publication reports never grant authority: `authorization: DENY`, `release: HOLD`, `production_release_enabled: false`.

## Regressions

```sh
python -m unittest discover -s release-registry -p 'test_durable_checkpoint_anchor_v22.py' -v
```

23 scenarios authored for first/second checkpoint, restart persistence, stale and racing updates, skipped sequences, changed history, bad receipt, missing/false/non-Boolean/exceptional verification and publication policies, missing or invalid external attestation, local ordinary mutation/delete triggers and deliberate corruption. The tests use synthetic callbacks and are **not independently confirmed as run**.

## Critical limitations

- This module does not create or manage a true independent root of trust; a database stored under the same administrator as v19 may be rolled back or replaced together with the decision database. Independently controlled monotonic signed anchors or equivalent tamper-resistant infrastructure are mandatory.
- Local linkage checks do not reconstruct arbitrary missing/forged checkpoint content without a separate original decision history. Whole-file rollback or valid-looking replacement requires independent checkpoint attestation for detection.
- Revalidation of external authorization and signatures occurs before the local transaction and can become stale before commit; real policy consistency requires coordinated protocol design.
- v19 decisions and v22 anchor commits are in distinct databases and are **not atomic together**. A crash between commits must fail closed rather than automatically publish or discard proofs. A durable outbox and recovery state machine are required.
- No independent trusted time, external signer key custody, cross-device consensus, real distributed service, secure filesystem roots, privacy management or system-level power-loss tests are included.
- `inspect()` returns a tuple only after an external callback says True; the callback MUST NOT simply compare to the local tuple or be backed by data from the same compromised storage domain.

**GO-13 HOLD: no merge to main, production deployment, real-world signing or receipt issuance, account changes, recovery activation or authorization.**
