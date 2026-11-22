# Local signed reviewer revision floor v0.1 — DRAFT / HOLD

The prototype records the highest Ed25519 issuer-signed reviewers-register revision
in a local SQLite database, using a transaction and per-issuer primary key. A
lower revision is rejected (`registry-rollback`); different signed snapshots
at the same revision are rejected (`registry-equivocation`). Identical
re-observation is idempotent. A higher revision may revoke all reviewers, and
does not need any active reviewer. Invalid signatures are rejected **before**
a local database is opened or written.

Run regression tests:

```bash
python3 -m unittest discover -s tests -p 'test_local_reviewer_revision_floor.py' -v
```

Critical limitations: the database itself can be deleted, restored or copied.
No immutable audit log, authenticated external roots, secure trusted time,
global consensus, or actual reviewer authorization is established. A caller
must enforce the persisted floor against reviewer evaluation; simply recording
a revision does not make the reviewer-gated replay pipeline safe. No automatic
link into the authorization flow has been enabled. Status remains HOLD.
