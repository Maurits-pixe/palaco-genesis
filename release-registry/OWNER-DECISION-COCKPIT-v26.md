# PALACO Trusted Evidence v26 — Owner Decision Cockpit

**DRAFT / GO-13 HOLD.** A mobile-friendly static owner interface and an explicitly invoked, non-authorizing JA/NEE acknowledgment contract. No live site, account login, trusted identity provider or autonomous recovery.

## Implementation

`owner_decision_cockpit_v26.py` builds on the existing v24 supervisor and v25 `OwnerReviewLedger`.

- `OwnerDecisionCockpit.overview(day)` generates a new read-only v25 snapshot for the specified day and reads the existing v25 daily review, if any. It shows `AWAITING_OWNER`, `ALREADY_REVIEWED`, or `SUNDAY_FREE`. Sunday is excluded; Monday through Saturday are eligible. The local date is a *caller-provided value*, not an independently trusted clock.
- `record(day, verdict, owner_id, evidence_ref, expected_snapshot_sha256, verify_owner, verify_trusted_date)` **only records** JA or NEE. It checks that the expected digest matches the fresh overview, reads the supervisor a second time, rejects a changed snapshot, then delegates to v25's independently required owner and date verification and append-only one-review-per-day SQLite ledger. Owner identity, current revocation, role membership and trusted time must be supplied externally. There is **no action-execution method**.
- `render_owner_html(view)` outputs self-contained responsive green-and-gold PALACO HTML with text-escaped details, a restrictive Content Security Policy and status, snapshot digest, review state, and JA/NEE shown as deliberately **disabled** controls. The buttons are disabled because there is **no connected authentication or submission backend**. Do not present a click on a static mockup as a confirmed review.
- The rendering and snapshot interfaces enforce `authorization: DENY`, `release: HOLD`, `operations_enabled: false` and `production_release_enabled: false` in their data contracts. **JA does not cause recovery, signing, deployment, database modification outside the v25 review ledger, identity issuance or policy release**.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_owner_decision_cockpit_v26.py' -v
```

25 synthetic tests committed for status rendering, mobile-safe static HTML, refusal of interactive execution, JA/NEE acknowledgment, weekday/Saturday/Sunday rules, repeat denial, stale snapshots and changing supervisor state, provider failure, identity/date refusal, tampering, restarts, and no privileged execution API. The tests have **not yet been independently confirmed to execute successfully**.

## Remaining security and reliability gates

1. A real authenticated owner session and current independent role/revocation verification. Fixture callbacks that always approve are never acceptable in production.
2. An independently authenticated current date and an irreversible, externally verifiable audit checkpoint for owner reviews. v25 currently stores a local hash and SQLite row; both can be rolled back by a privileged process.
3. Read-check-write of the v24 snapshot and the v25 review are **not atomic across databases**. Even the second snapshot read can race with a subsequent supervisor change before the ledger commit. A trusted atomic authorization protocol, revalidation and/or serializable snapshot binding is required before live use.
4. Secure backend, CSRF protection, session handling, logging, privacy and retention rules, mobile accessibility QA, and independent adversarial/fault-injection testing.
5. Real integration with an approved PALACO site/app requires explicit deployment management; v26 only supplies the Python module and HTML generator.

**GO-13 HOLD — no merge to main, real-user account change, automatic task execution, recovery authorization, or production publication.**
