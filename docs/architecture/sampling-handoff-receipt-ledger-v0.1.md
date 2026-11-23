# Sampling Handoff Receipt Ledger v0.1 — DRAFT · GO-13 HOLD

`tools/sampling_handoff_receipt_ledger.py` integrates the strict
`sampling_succession_evidence_handoff.verify_receipt` gate with a
transactional SQLite receipt ledger. Under `BEGIN IMMEDIATE`, the
complete existing SHA-256 hash chain and separate nonce index are
revalidated before the complete signed handoff history is independently
reverified. One transaction writes the receipt fingerprint and the
nonce index together. Rejected signatures and replayed nonces cannot
become successful receipt records.

Each event binds the recipient ID, verified recipient signing key,
package SHA-256, signed receipt evidence SHA-256, consumed nonce,
monotonic sequence and prior event hash under a domain-separated hash.
Receipts from the same key about the same package cannot be issued
twice even with a different nonce. Read-only `inspect` verifies the
hashes, the nonce index, continuous sequence and separately pinned
head hash and minimum receipt count.

**Threat boundary:** SQLite is local mutable storage, not an
independent immutable archive. The caller MUST provide up-to-date,
separately authenticated head/count pins before every append and
review, and must retain those anchors durably. For cross-device
replay protection a separately administered shared nonce authority
is still necessary. The module records receipt digests, NOT source
files and not proof of off-device storage, legal independence or
physical delivery. No signer private keys are used and no remote
requests are issued.

All positive outcomes remain `pending-review`, with
`release_gate=HOLD`, authorization DENY and no merge, deployment
or automatic restoration.

Test: `python3 -m unittest discover -s tests -p 'test_sampling_handoff_receipt_ledger.py' -v`.

## Post-write integrity hardening (2026-11-23)

After writing both tables inside the same `BEGIN IMMEDIATE` transaction,
the ledger rescans the entire receipt chain and nonce index **before commit**.
If the expected sequence, new head, nonce binding, or chain integrity is
missing, the transaction is explicitly rolled back and the receipt is denied.
Negative regression tests install SQLite triggers that delete inserted nonces
or corrupt event hashes and verify no receipt rows survive. This detects
some forms of in-transaction tampering; it does not make local SQLite
storage tamper-proof or replace independently authenticated external pins.
