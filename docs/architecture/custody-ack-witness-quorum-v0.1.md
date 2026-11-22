# PALACO Custody Acknowledgement Witness Quorum v0.1 — DRAFT / GO-13 HOLD

`tools/custody_ack_witness_quorum.py` checks 2–16 independent Ed25519
witness statements concerning the same complete local acknowledgement
audit chain. The caller must supply a separately authenticated allowlist
of witness fingerprints, public-key roots, up-to-date revocations,
minimum signature threshold and externally stored event-count floor.

Each witness envelope is verified with the existing signed checkpoint
module. Every signature must authenticate and match the exact same
local SHA-256 head and event count. Duplicate signers, revoked keys,
untrusted keys, malformed envelopes, valid but conflicting claims and
insufficient quorum all yield `quarantined`. No majority can override
a contradictory submitted witness.

**Limitations:** the code cannot prove that witness keys are controlled by
different organizations or humans, prevent suppression of a contradictory
statement outside the submitted set, prove custody of original files, keep
roots and floors independently, or coordinate quorum across networks.
Identity independence is a deployment/governance obligation, not a property
of distinct Ed25519 fingerprints. This is *evidence quorum*, explicitly
not release or recovery authorization. Validity remains pending-review,
GO-13 HOLD, with no merging, deployment or restoration.

Tests: `python3 -m unittest discover -s tests -p 'test_custody_ack_witness_quorum.py' -v`.
