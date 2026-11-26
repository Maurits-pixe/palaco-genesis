# PALACO Revision-Gated Replay v0.1 — DRAFT / HOLD

This prototype connects the local signed reviewer revision-floor to the reviewer-gated
evidence replay pipeline in this order: **verify issuer-signed snapshot → reject
rollback/equivocation using local SQLite revision floor → review signer status
and valid interval → verify candidate Ed25519 signature and digest → local
SQLite duplicate-ID screening**.

It rejects stale or conflicting snapshots before the candidate's record ID
can be inserted into the replay index. A later valid revocation revision
can be stored, even if all reviewers are revoked. Tests cover ten positive
and negative conditions.

**Critical limitations:** revision-floor storage and replay-index storage are
two separate databases and do not form one atomic transaction. The floor can be
deleted, restored, or raced against independently by processes; another host
may see a different state. Issuer trust roots, public keys, current time and
external minimum revision are supplied by the caller. This is NOT authoritative
revocation enforcement, trusted state, or issuance infrastructure.

Even on a clean result, evidence remains pending manual review and
authorization remains DENY. No production integration or deployment.
