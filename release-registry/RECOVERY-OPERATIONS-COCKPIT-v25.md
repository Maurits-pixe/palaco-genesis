# PALACO Trusted Evidence v25 — Recovery Operations Cockpit

**DRAFT / GO-13 HOLD.** This is a diagnostic, read-only module with a separate owner-review acknowledgment ledger. It is NOT a deployed website, authenticated login, autonomous scheduler, production authorization, or recovery executor.

## Implemented

`recovery_operations_cockpit_v25.py` supplies:

- `snapshot(supervisor)` reads only the existing v24 `inspect()` report, applies strict field and fail-closed checks, and produces a deterministic SHA-256-bound, canonicalizable diagnostic snapshot. It always includes `authorization: DENY`, `release: HOLD`, `operations_enabled: false` and `production_release_enabled: false`.
- `render_html(snapshot)` creates self-contained, mobile-responsive, offline-friendly **static HTML** with a muted green-and-gold PALACO presentation, strict snapshot digest verification, HTML escaping and a restrictive Content Security Policy. It contains **no buttons, forms, scripts, network access or privileged actions**. This is a generated HTML string, not a published ChatGPT Site.
- `OwnerReviewLedger(path)` stores a one-per-day **JA/NEE owner-review acknowledgment** in a separate local SQLite append-only journal. Sunday is excluded; Monday through Saturday are eligible. A `JA` does **not** authorize anything and must not trigger `v24.run_once`, `v23.reconcile`, a release or an identity change.
- `record(snapshot, day, verdict, owner_id, evidence_ref, verify_owner, verify_trusted_date)` requires independently configured, current owner verification and trusted date validation. Both must return literal `True`. The data is bound to the exact snapshot SHA-256, date, verdict, owner identifier and an opaque evidence reference via a domain-separated SHA-256 review digest. No personal receipts, proof bytes, access tokens or secrets are stored.
- The owner verification callback and trusted clock/date service are **not implemented**. In the absence of these external services, recording a review fails closed. A hash alone does not establish author identity. SQLite triggers prevent ordinary edits and deletion but do not protect against privileged file replacement or rollback.
- `read(day)` checks locally stored review digest and supplies a diagnostic, read-only status, again DENY/HOLD.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_recovery_operations_cockpit_v25.py' -v
```

25 regression cases have been authored for static UI, deterministic snapshots, tampered reports/digests, inconsistent status, JA/NEE non-authority, single review per date, restart persistence, Saturday permitted/Sunday excluded, missing/failing owner or trusted-date checks, rejected decisions, append-only guards, tampering detection and absence of execution methods. All owner and date provider callbacks are synthetic fixtures. **The tests are committed but their successful execution has not yet been independently confirmed.**

## Access and operational limitations

A displayed report is **not** independently authenticated evidence. The cockpit lacks live accounts, role and key revocation, a real verified owner identity, an external monotonic audit root, real trusted time, legal retention controls and actual secure HTML delivery. No owner or signer credentials are generated, enabled or assigned.

A daily JA/NEE record is merely evidence that an independent provider was asked to confirm a review for a snapshot. It has no authority over v19–v24 recovery operations or other PALACO modules.

Before any live use: independently authenticated identity/role provider, trusted date source, independent anti-rollback audit, proven concurrency and failure-injection tests, privacy policy, access control, and security review. The design should keep the manual acknowledgment workflow separate from any later operational approval/release system.

**GO-13 HOLD — no merge to main, public site activation, live user data, account changes, signing, execution, recovery or production release.**
