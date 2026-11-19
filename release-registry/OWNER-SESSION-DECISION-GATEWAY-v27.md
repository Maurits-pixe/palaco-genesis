# PALACO Trusted Evidence v27 — Owner Session & Decision Gateway

**DRAFT / GO-13 HOLD. No live PALACO One login or deployment.**

`owner_session_decision_gateway_v27.py` defines the strictly non-authorizing session-bound JA/NEE review mechanism to bridge a *future* PALACO One owner session to the v26 cockpit and v25 review ledger. The module provides no session issuer, external trusted clock or production capability.

## Workflow

- `begin(session_assertion, day, verdict, evidence_ref, expected_snapshot_sha256, verify_session, trusted_now)` validates a caller-provided owner assertion using required external `verify_session(assertion, "OWNER_REVIEW", day)`. The provider must independently check signed session authenticity, active OWNER role, MFA/freshness, device binding, revocation, authorization scope and expiry and return a trusted owner identifier; any other result fails closed. A trusted external epoch-time callback is required and must match the **UTC calendar day** in this draft.
- A fresh v26 cockpit snapshot must match the caller's expected digest, and the day's review must not already be recorded. Sunday is excluded.
- A new unpredictable 256-bit random challenge is issued with a 300-second lifetime. Only SHA-256 of the challenge token, owner identity, date, verdict, evidence reference, snapshot digest and issued/expiry timestamps are retained in SQLite. The plaintext challenge is only returned once; an authenticated application must prevent exposure via URLs, logs or browser storage.
- `confirm(challenge, session_assertion, verify_session, trusted_now, verify_owner, verify_trusted_date)` starts a SQLite transaction, rejects unknown/used/expired challenges and clock rollback, and **reverifies the session and owner identity**. The v26 cockpit rereads the snapshot and the v25 ledger requires current owner and date validation before writing a **JA/NEE acknowledgment only**.
- The challenge is marked consumed after the v25 review is recorded. Because the databases are independent, a process crash between the v25 write and challenge-consumption transaction leaves a spent daily review in v25; further attempts fail closed under v25's unique daily key. This is not atomic multi-database commit and **not** general exactly-once infrastructure.
- Database triggers reject ordinary deletion and mutation of challenge binding fields; only one transition from unconsumed to consumed is permitted. A privileged database admin may still replace or roll back storage.
- A daily **JA** is a record of assessment and **never** authorizes recovery, publishes checkpoints, executes v24 actions, changes accounts, issues identities or lifts HOLD. The gateway has no privileged execution methods.

## Test coverage

```sh
python -m unittest discover -s release-registry -p 'test_owner_session_decision_gateway_v27.py' -v
```

26 synthetic scenarios authored for begin/confirm, JA/NEE, replay refusal, multiple challenges for the same day, restart, changed identity/revocation, challenge expiry and clock rollback, date mismatch, Sunday, stale or changing snapshots, owner-policy rejection, unavailable providers, malformed time/token, challenge hash-only persistence, append-only guards and missing execution API. **Tests committed, execution not independently confirmed.** Fixture callbacks grant synthetic permissions and do not authenticate real PALACO users.

## Production blockers

1. No verified PALACO One identity provider, real session-token validation, owner MFA, device security, revocation, role source or session-binding system is installed here. This is only a Python interface.
2. No trusted, globally consistent current date/time service. The draft uses UTC dates for token validity; the intended Dutch Mon–Sat calendar requires an explicitly validated Europe/Amsterdam time policy and handling of midnight/daylight-saving transitions.
3. The v26 two-snapshot freshness check and v25 review write are separate transactions and may race. The gateway does not claim linearizable state capture across v24, v25 and v27.
4. No HTTPS session delivery, origin restrictions, CSRF protections, rate limiting, authenticated backend endpoint, browser transport, audit event hardening or privacy/retention schedule.
5. No independent anti-rollback root exists for gateway database, review ledger or other local SQLite stores. Session verification callbacks must never be simple truthy fixture callbacks in production.
6. The challenge token is a bearer secret: it must be handled as secret information and never embedded in a public download, browser URL, screenshot, logging field or audit proof.
7. No deployment or owner-account creation occurred. Any future frontend must keep JA/NEE disabled until real authenticated session and trusted backend interfaces are provisioned and tested.

**GO-13 HOLD — no merge to main, production release, user-account modification, real-user review issuance or automatic execution.**
