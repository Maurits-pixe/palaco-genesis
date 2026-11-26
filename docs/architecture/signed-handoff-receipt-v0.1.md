# PALACO Signed Offline Handoff Receipt v0.1 — DRAFT / HOLD

`tools/signed_handoff_receipt.py` validates a detached Ed25519 receipt
signed by a custodian's caller-authenticated public key. The receipt binds a
recipient ID, independently pinned offline handoff bundle SHA-256, a caller-
supplied unique 128-bit receipt ID and the **sole** disposition
`received-for-independent-review`. A receipt can never declare approval.

The verifier first checks the receipt schema, key fingerprint, revocation set
and domain-separated signature, then re-verifies the entire handoff package,
signed history anchor, external bundle digest and local history.

`index_receipt` stores digest-only metadata in a **separate** local SQLite
file with `BEGIN IMMEDIATE`, a unique receipt ID and one observed
acknowledgement per bundle/recipient/custodian key. Duplicate or conflicting
observations are quarantined. It does not accept timestamps as proof of
delivery, generate any signer keys, transmit packets or restore state.

There is **no externally authenticated custodian directory**, secure delivery,
actual human receipt proof, write-once remote ledger, or globally coordinated
replay protection. A local database owner can rewrite/rollback its contents.
The receipt ID must be generated securely by the independent signer; this
module verifies its shape only. No authorization/restore/merge/deployment is
ever granted. GO-13 HOLD.

Tests: `python3 -m unittest discover -s tests -p 'test_signed_handoff_receipt.py' -v`.
