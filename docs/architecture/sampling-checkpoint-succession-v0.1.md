# Sampling Checkpoint Succession v0.1 — DRAFT / GO-13 HOLD

The offline `tools/sampling_checkpoint_succession.py` verifier accepts a
bounded, hash-linked series of historical signed sampling ledger
checkpoints. Every record has an exact increasing revision, previous
record SHA-256 (domain `PALACO-SAMPLING-CHECKPOINT-SUCCESSION-V1`), a
checkpoint (batch count, ledger head, manifest/evidence hashes), and a
multi-organization Ed25519 witness quorum.

The full local ledger and nonce index are checked in a read-only
snapshot. Each historical checkpoint must exactly match its ledger
prefix, the batch counts must strictly increase, and the final
checkpoint must equal the current pinned ledger state. Independent,
authenticated genesis/last-record pins, minimum revision, ledger
head and batch-floor inputs prevent rollback when maintained properly.
Current witness revocations apply to the entire submitted history;
the verifier rejects duplicate keys, duplicate organizations,
malformed or invalid signatures, conflicting checkpoints and gaps.

This is evidence verification, NOT an issuance service. It cannot
prove legal organizational independence, prevent withheld off-chain
evidence, publish pins, or establish independent physical custody.
The verifier performs no signing, deployment or restoration; all
successful responses remain `pending-review`, with GO-13 HOLD,
authorization DENY and no public release.

Run `python3 -m unittest discover -s tests -p 'test_sampling_checkpoint_succession.py' -v`.
