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

## Bounded nonce-index integrity scan (2026-11-24)

Both the receipt history and its nonce index are read with a strict
`MAX_RECORDS + 1` query limit. An index exceeding `MAX_RECORDS`
fails closed before the index set is materialized. The full expected
nonce/sequence mapping must still exactly match the bounded receipt
chain. Regression tests cover an extraneous nonce and an oversized
index on both read-only inspection and subsequent registration.

This provides a bounded database read; it is **not** a storage-size quota,
external nonce authority, or protection from every SQLite resource
exhaustion vector. GO-13 remains HOLD and all authorization is denied.

## Individuele read-only ontvangstinspectie (2026-11-24)

`inspect_entry(db, expected_head, minimum_receipts, sequence)`
opens SQLite in read-only mode and verifies the **entire** local receipt
chain plus nonce index within one database read transaction before exposing
the requested record metadata. Both an independently authenticated exact
head hash and minimum entry count are mandatory. Nonexistent or invalid
sequence numbers, chain manipulation and rollback fail closed.

The response provides the recipient, signing-key identifier, package hash,
receipt nonce, receipt digest, previous event hash and event hash for
independent forensic comparison. It does **not** expose source documents,
validate off-device delivery, grant storage custody or authorize anything.
All successful lookups remain `pending-review`, `HOLD`, and DENY.

## Signed evidence re-verification (2026-11-24)

`verify_entry_evidence(db, package, receipt, trust, expected_head,
minimum_receipts, sequence)` first verifies the entire read-only local
chain, nonce index and separately trusted head/count pin, then performs
fresh Ed25519 receipt signature, package history, witness eligibility and
recipient revocation checks through the strict handoff verifier. Only if
the signed receipt's digest, recipient, key, package digest and nonce
match the indexed row does it return a positive **pending-review** result.

The externally managed `used_nonces` policy must be supplied as an
evidence-verification snapshot that does not incorrectly treat the
receipt currently under examination as a *new* replay attempt; the
ledger itself already requires that nonce to be present. The caller
must independently authenticate the trust roots and pins. Validation
is read-only and is not a certificate of delivery, possession or legal
independence. All authorization remains DENY and release GO-13 HOLD.

## Atomic rollback on nonce insert failure (2026-11-24)

The two-table receipt registration transaction now explicitly calls
`rollback()` when the second insert raises `sqlite3.IntegrityError`.
Without that step, returning normally from a Python SQLite connection
context manager could commit the first receipt row even though writing
the nonce index failed. A negative regression test injects an aborting
nonce-table trigger, rejects the attempted handoff and confirms **both**
tables remain empty with the genesis head unchanged.

This protects the local atomicity contract for that failure path; it
does not provide external immutability, a distributed transaction
protocol, or delivery/custody proof. GO-13 remains HOLD, authorization DENY.
