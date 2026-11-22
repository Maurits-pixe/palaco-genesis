# Local SHA-256 audit chain v0.1 — DRAFT / HOLD

`tools/local_audit_chain.py` supports appending bounded metadata events within
an existing SQLite transaction and verifying the stored hash chain in read-only
mode. Events are domain-separated by `PALACO-LOCAL-AUDIT-V1` and include their
sequence, previous hash, event type, subject and detail. The supported types are
`registry-revision` and `candidate-indexed`. Raw evidence is not stored.

Read-only verification:

```python
from tools.local_audit_chain import verify
report = verify("local.sqlite", expected_head="...independently authenticated head...")
```

A matching local hash chain without an externally authenticated expected head
proves only **internal consistency**. A database owner can rewrite entries and
recompute all hashes, or roll back the complete database. Even a trusted head
does not authenticate the event identities or underlying signed evidence by
itself. For independent protection, publish an authenticated head to separate
write-once/append-only infrastructure and verify it after retrieval; no such
service is implemented here.

Earlier local writes performed before the audit integration are not covered.
Only subsequent instrumented changes emit entries. No authorization is granted.
GO-13 HOLD.
