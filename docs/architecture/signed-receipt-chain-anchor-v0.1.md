# Signed Receipt Audit Anchor v0.1 — Draft / GO-13 HOLD

`tools/signed_receipt_chain_anchor.py` verifies an independently supplied
Ed25519-signed checkpoint containing an exact receipt audit-chain SHA-256 head
and event count. Signature messages are domain separated with
`PALACO-SIGNED-RECEIPT-CHAIN-ANCHOR-V1`.

The verifier requires separately authenticated witness public keys, an
externally supplied revoked-key set and a trusted minimum receipt event count.
It checks the signature, the complete local hash chain and cross-table
reconciliation with `observed_handoff_receipts`. A deleted, altered or
appended record is rejected when it conflicts with the signed checkpoint.

This code **does not issue, distribute or store signed checkpoints**, secure
signing keys, maintain immutable off-device floors, or provide a trusted
timestamp. Caller-provided keys and floor do not automatically become trusted.
A stolen signing key, stale external count or compromised anchor service can
defeat rollback resistance. Successful checks remain `pending-review` and
never approve recovery, deployment, authorization or merges.

Tests: `python3 -m unittest discover -s tests -p 'test_signed_receipt_chain_anchor.py' -v`
