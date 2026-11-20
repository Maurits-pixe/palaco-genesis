# PALACO Trusted Recovery v3 — Secure Restore Candidate

**Draft / GO-13 HOLD.** This module does not connect to real accounts, trusted identities, external keys, or network services. It is not a production restore system. No existing database may be overwritten.

## Behavior

`restore_to_new_file(backup_bytes, checkpoint, scope, verify, approve, destination)` first validates the v2 backup and its injected independent verifier. Then it demands a separate, explicit approval callback. Approval bytes bind scope, exact checkpoint sequence and head, backup SHA-256 and destination basename under a distinct v3 domain prefix.

Only a fully new, absolute destination filename in an existing directory is accepted. The candidate creates a temporary SQLite file in the same folder, inserts metadata events in one transaction, replays the new journal, flushes the database file, then publishes with `os.link`, which cannot silently replace an existing destination. It removes the temporary path after completion or failure.

The callback is **not** an approval system: no real human consent or identity proof is implemented. A callback returning `True` without independently validating authorization is unsafe. An injected `verify` returning `True` without authenticating the receipt is equally unsafe. Synthetic test fixtures do not satisfy the production requirements.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_secure_restore.py' -v
```

Sixteen tests cover new destination restoration, unchanged original, existing destination refusal, repeat restoration refusal, missing/false/truthy/exceptional approval, absent trust verification, incorrect checkpoint, damaged backup, invalid destination, missing parent, hidden filename, approval binding, and pre-approval validation.

## Open risks and requirements

- No built-in signing key, trustworthy reviewer binding, consent UI, time/freshness checks, trusted monotonic checkpoint, independent revocation lookup or guaranteed verifier.
- Path ancestry, filesystem races, hard-link support, filesystem privilege boundaries, full machine power-loss durability, disk-full and hostile concurrent processes need security review and platform tests. The implementation is an **offline local candidate**, not a hardened hostile-filesystem primitive.
- `os.link` availability varies by platform and filesystem. Folder fsync is best effort; therefore a successful return is **not** a universal crash-durability guarantee.
- No existing file overwrite, no automatic rollback or real-world account migration, no user payload or credentials, no app integration, and no cross-device synchronization.

Review any use outside a temporary isolated test directory. All release, authorization, deployment, key issuance and shared-login gates stay closed.
