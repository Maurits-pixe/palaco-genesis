# Delegation Receipt Audit Chain v0.1 — DRAFT / GO-13 HOLD

The module `tools/delegation_receipt_audit_chain.py` creates a
SHA-256 domain-separated chain for verified offline delegation-evidence
handoff receipts. The existing `delegation_evidence_handoff.register_receipt`
now creates a new audit event BEFORE inserting the matching receipt
index row, under the SAME SQLite `BEGIN IMMEDIATE` transaction.
Any exception rolls back both writes.

A read-only `inspect(db, expected_head, minimum_entries)` validates
contiguous event numbering, event and preceding hashes, schema-constrained
fields, and an exact set match against the indexed receipts table. It
requires an independently authenticated expected head SHA-256 and a
minimum number of events. Missing history, altered records, chain gaps,
stale count, and mismatched heads result in `quarantined` and HOLD.

This system cannot prove that data was actually delivered or stored
independently. The SQLite database is neither tamper-proof nor an
append-only remote repository. An attacker can replace BOTH local tables.
The expected audit head and lower count bound must therefore be
retained out of band by an independent trusted party. Caller-supplied
witness keys, revocations, and delegation history pins must also be
authenticated separately. No merge, release, deployment, recovery or
authorization is implemented.

Run `python3 -m unittest discover -s tests -p 'test_delegation_receipt_audit_chain.py' -v`.
