# Signed Custody Acknowledgement Anchor v0.1 — Draft / HOLD

The read-only verifier `tools/signed_custody_ack_anchor.py` authenticates a
detached Ed25519 witness statement about the complete local acknowledgement
audit chain. The canonical statement commits to the exact last event SHA-256
hash and event count. Domain-separated signature bytes are prefixed with
`PALACO-SIGNED-CUSTODY-ACK-ANCHOR-V1`.

The caller MUST supply independently authenticated witness public keys,
current revocations and an externally authenticated minimum event count.
The verifier rejects revoked or untrusted witnesses, malformed fields,
changed signatures, stale counts, altered history and deleted rows.
A valid witness is strictly `pending-review`; no authority is bestowed.

**Limitations:** this module neither signs nor publishes anchors and cannot
make a local SQLite ledger immutable. A compromised signing key or a stale,
caller-controlled minimum defeats rollback protection. Trust bootstrap,
out-of-band storage, verified witness independence, durable receipts,
recovery approval, deploy and release mechanisms are not implemented.

Test with `python3 -m unittest discover -s tests -p 'test_signed_custody_ack_anchor.py' -v`.
