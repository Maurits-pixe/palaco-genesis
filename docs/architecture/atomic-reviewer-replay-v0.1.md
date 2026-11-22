# Atomic reviewer + replay SQLite prototype — DRAFT / HOLD

The module `tools/atomic_reviewer_replay.py` makes local signed reviewer
revision-floor and record-ID uniqueness changes inside **one SQLite database
transaction** (`BEGIN IMMEDIATE`). The caller supplies issuer trust roots,
reviewer public keys, an evaluation time, and a trusted minimum revision.

Order: issuer-signed snapshot validation → reject stale externally known
revision → reviewer status / validity → Ed25519 candidate integrity →
BEGIN IMMEDIATE → recheck revision floor → revision update + replay insertion
→ commit. A rollback or equivocation returns quarantine without updating replay
state. Bad candidates are not indexed. Identical intra-batch record IDs are
quarantined. Revocation revisions can advance without authorizing reviewers.

**Limitations:** a database-file rollback, malicious local writer, independent
host, compromised clock, or untrusted issuer root defeats security assumptions.
This is *not* an authoritative revocation/replay service, and cannot replace
a server-side immutable ledger, authenticated monotonic revision authority,
or key governance. A local SQL transaction only provides atomicity for that
single file. All results remain `pending-review` or `quarantined`, with
authorization and evidence verification permanently false. GO-13 HOLD.

Test with:
```bash
python3 -m unittest discover -s tests -p 'test_atomic_reviewer_replay.py' -v
```
