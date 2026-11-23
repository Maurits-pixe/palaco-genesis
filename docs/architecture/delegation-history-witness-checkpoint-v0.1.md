# Witnessed Delegation History Checkpoint v0.1 — DRAFT / GO-13 HOLD

`tools/delegation_history_witness_checkpoint.py` verifies 2–16 detached
Ed25519 witness signatures over one exact assessor-delegation status-chain
head, genesis, revision, delegation envelope digest, organization ID, and
assessor fingerprint. Domain: `PALACO-DELEGATION-HISTORY-WITNESS-V1`.

Before verifying the witness quorum, it re-verifies the entire chain of
signed organization registries, identity assessor evidence, narrow
delegation, and delegation-status events using the existing modules.
The caller must independently authenticate genesis and latest hashes,
minimum revisions, key roots, current revocations and witness
key-to-organization mappings. Identical signatures cannot vote twice;
different keys mapped to the same organization cannot satisfy quorum.
A conflicting submitted checkpoint is denied even when cryptographically
signed by an eligible witness. A revoked delegation never qualifies.

This is a verifier, not a signing service, remote attestation, custody
proof, legal organization check or authority quorum. It cannot establish
that witness organizations are genuinely independent, prevent withholding
of outside statements, or make caller-supplied trust anchors immutable.
Its only successful state is `pending-review`. GO-13 stays HOLD and
authorization, restore, merge and release remain DENY.

Tests: `python3 -m unittest discover -s tests -p 'test_delegation_history_witness_checkpoint.py' -v`.
