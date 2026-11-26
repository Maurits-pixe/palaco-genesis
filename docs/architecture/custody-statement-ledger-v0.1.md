# PALACO Custody Statement Ledger v0.1 — DRAFT / GO-13 HOLD

This module adds a local, transactional audit ledger for *claims* of custody,
not evidence of physical or off-device custody.

`tools/custody_statement_ledger.py` first verifies the custodian Ed25519
signature, exact policy/receipt checkpoint envelope hashes, custodian key
allowlist, revocations and independent policy/event floors. Only then does
it open a distinct SQLite ledger and begin `BEGIN IMMEDIATE`. Each insert
atomically writes a minimal indexed statement row and a domain-separated
SHA-256 event chaining to the previous event.

An identical statement ID and envelope is rejected as replay. Reusing an
existing statement ID with another envelope is a conflict. Reacknowledging
the same checkpoint for the same custodian under a new statement ID is also
rejected; the receipt-event count for each custodian must increase.

`inspect` reconciles every audit event with every current index row and
checks full hash continuity against a caller-supplied **independently pinned**
head and minimum entry count. It is read-only and never creates the file.

**Unaddressed:** the local SQLite file is mutable; an adversary can rewrite
both tables and recompute every hash. The external head and minimum must be
stored, authenticated and updated in an independent system; this module does
not implement one. Receipt database and ledger reads occur in distinct
transactions, so concurrent updates require end-to-end re-verification.
There is no actual remote delivery, authenticated storage attestation,
secure key custody, key rotation workflow or global replay detection.
No sign-off, restoration, release, merge or deployment is authorized.

Run: `python3 -m unittest discover -s tests -p 'test_custody_statement_ledger.py' -v`.
