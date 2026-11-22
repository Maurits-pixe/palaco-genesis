# Custody Acknowledgement Audit Chain v0.1 — DRAFT / HOLD

`tools/custody_ack_audit_chain.py` creates a domain-separated SHA-256
hash chain for locally received custody-ledger checkpoint acknowledgements.
The existing `register_ack` flow now validates the external witness,
package SHA-256 and signed acknowledgement before beginning a SQLite
`BEGIN IMMEDIATE` transaction. Each accepted acknowledgement and the
corresponding hash-chain event are committed atomically.

A read-only `inspect(register_db, expected_head, minimum_events)` verifies
sequence continuity, each event hash and **exact consistency with the
receipt-index table**, and requires both an externally authenticated last
hash and minimum length. Missing or altered rows, corrupt event hashes,
untrusted heads and insufficient history return quarantined/HOLD.

**Trust boundary:** an attacker controlling the local file can rewrite both
tables. The expected head and minimum count must be kept independently
and authenticated outside this program. No remote immutable witness,
external key custody, global replay registry or trusted timestamps are
implemented. An acknowledgement is not actual proof of remote storage.
No authorizations, restores, releases, merges or deployments occur.

Test: `python3 -m unittest discover -s tests -p 'test_custody_ack_audit_chain.py' -v`.
