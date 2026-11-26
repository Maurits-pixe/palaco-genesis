# Receipt Audit Chain v0.1 — DRAFT / GO-13 HOLD

The receipt register now writes an SHA-256 receipt audit event **inside the
same SQLite transaction** as the receipt index INSERT. Each event commits the
receipt ID, bundle SHA-256, custodian key fingerprint, recipient identifier,
receipt digest, sequence and prior chain hash. No raw signature or private key
is retained in this chain.

`tools/receipt_audit_chain.py` offers `append(conn, ...)` for the existing
transaction and a read-only `verify(db, expected_head, minimum_events)` that
compares the full chain to *all* current index rows, verifies continuity,
requires an externally authenticated head and rejects a shorter-than-expected
history. Failure always quarantines. Success remains pending-review/HOLD.

The chain and SQLite index are NOT an external immutable ledger. A malicious
database owner can rewrite both and fabricate a matching local head. To detect
full rollback, the expected head and minimum event count must be protected
outside the database, with independently authenticated custody and freshness.
There is no remote service, automatic restoration, or release authority.

Test: `python3 -m unittest discover -s tests -p 'test_receipt_audit_chain.py' -v`.
