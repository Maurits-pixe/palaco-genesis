# Local Checkpoint Recovery Assessment v0.1 — DRAFT / HOLD

`tools/checkpoint_recovery_assessment.py` performs a strictly read-only,
fail-closed assessment of **two distinct SQLite stores**:

1. The evidence database with its SHA-256 audit chain.
2. The separate checkpoint-floor database.
3. A **detached issuer-signed checkpoint witness** provided by the caller.
4. An issuer trust map, explicit revoked issuer set, and external minimum sequence.

It first inspects both SQLite files using read-only connections and
`PRAGMA integrity_check`, then verifies the witness Ed25519 signature,
the whole audit chain and its final hash/sequence, and finally compares the
checkpoint-floor sequence/head to that witness. Missing or corrupt databases,
invalid issuers, revoked keys, stale witnesses, tampered chains, missing floors,
floor rollback and equivocation are quarantined.

No files are created, changed or automatically restored during assessment.
A matching result remains `pending-review`: source authenticity, secure
timestamps, independently governed revocation and external immutable witness
storage are NOT provided. Two SQLite read transactions are not coordinated:
concurrent writers may change the files between checks. A malicious process
may replace both stores and influence the witness unless external trust sources
are used. This is diagnostics, **not** secure disaster recovery.

All results preserve `authorization_granted: false`,
`automatic_restore: false`, `recovery_approved: false` and `release_gate: HOLD`.

Test: `python3 -m unittest discover -s tests -p 'test_checkpoint_recovery_assessment.py' -v`.
