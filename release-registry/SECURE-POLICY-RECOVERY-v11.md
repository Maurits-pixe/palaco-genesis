# PALACO Trusted Evidence v11 — Secure Policy Recovery

**DRAFT / GO-13 HOLD — no production authority.** This module is a new-file-only, metadata-only recovery candidate for a v9 policy event history stored in the v10 SQLite format.

## Proposed behavior

- `make_backup(events)` creates deterministic JSON containing the event list. This is **not** a signature, provenance receipt, or trusted checkpoint.
- `inspect_backup(data, get_trusted_anchor, verify_policy)` enforces a size bound, exact backup schema, canonical encoding, complete v9 replay, and v9's separate external anchor and current-policy callbacks.
- `restore_new_journal(..., approve)` requires a separate external approval callback AFTER validation. It binds approval bytes to backup SHA-256, exact sequence/head and target basename via a v11 domain prefix.
- An absolute, previously unused destination is mandatory. A temporary SQLite file is constructed in the same parent folder; events are inserted in a transaction and replayed before publication.
- `os.link` performs a no-replace final publication where supported. Any existing destination remains unchanged. The candidate removes temporary files on success/failure.
- Result is a diagnostic with `HOLD`, `DENY`, and `production_release_enabled: false`.

## Regression tests

```sh
python -m unittest discover -s release-registry -p 'test_secure_policy_recovery_v11.py' -v
```

20 test scenarios were added for successful synthetic restore, unchanged source, denial of release, existing destination, repeated restore, missing/false/non-Boolean/exceptional approval, missing/old anchors, denied policy, tampered and noncanonical backups, invalid destination, approval binding, fail-before-approval and empty-ledger denial. Passing CI/browser/system tests is **not** claimed by adding test files.

## Safety limitations

- Callbacks in tests are synthetic and **not independent trust sources or human consent**. Production requires authenticated external monotonic anchoring, trusted time, current revocation/policy lookup and verified owner authorization.
- Hostile filesystem race safety, symlinked ancestors, cross-platform hard-link support, disk-full, power-loss durability, cleanup failure, WAL/journal behavior and directory fsync need further engineering. This is for isolated test directories only.
- A successful call does not prove universal crash durability. This module cannot install a policy into a running PALACO application, synchronize devices or grant key authority.
- The output includes file path metadata; deployment would require privacy review and log redaction.
- Existing journals are never overwritten. This is not automatic rollback or replacement.

**No merge, live deployment, key issuance, shared login, recovery activation or production-data use.**
