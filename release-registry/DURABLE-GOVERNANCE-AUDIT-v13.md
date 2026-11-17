# PALACO Trusted Evidence v13 — Durable Governance Audit

**DRAFT / GO-13 HOLD.** This is a local SQLite implementation of the v12 review model. It does not authenticate users, establish a trusted audit anchor, approve a policy restore or authorize release.

## Implementation

`durable_governance_audit_v13.py` supplies `DurableGovernanceAudit(path)`.

- `bind(plan)`: a single proposal is bound once to each new local SQLite database. Rebinding, including binding a different proposal, is rejected. Invalid or missing proposal rows fail closed.
- `append(expected_head, actor_id, role, verdict, receipt)`: serializes writes with SQLite `BEGIN IMMEDIATE`; loads and verifies all previous events before using v12's review-contract checks; persists the next canonical review event in one transaction; fails on stale heads, repeated actor IDs, invalid roles or malformed receipts.
- `read(expected_head)`: a read-only SQLite snapshot, full canonical replay of stored events and explicit expected-head check. It verifies local consistency **not** external authenticity.
- `inspect(verify_role, get_trusted_audit_anchor)`: calls the independent v12 role and audit-anchor interfaces against the consistent snapshot and can return only a report containing `authorization: DENY`, `release: HOLD`, and `production_release_enabled: false`.
- DB-level triggers prevent ordinary updates and deletes of proposal and review rows. They cannot stop privileged SQLite users, malicious file replacement or direct page edits.

The metadata records include opaque review receipt strings stored locally to support future evidence inspection. Do not use real identity or account receipts without privacy, data retention, encryption and role-access design.

## Negative test scenarios

```sh
python -m unittest discover -s release-registry -p 'test_durable_governance_audit_v13.py' -v
```

21 test cases added: initial bind, restart replay, two successive writes across restarts, repeated binding, proposal replacement, stale concurrent write, duplicate identity, invalid role, stale read, mutation/deletion trigger checks, corrupted proposal/review rows, altered review sequence, missing/stale trust, synthetic two-role completion, rejection veto and empty-history trust denial.

Test files being committed does **not** establish that the suite was run or passed; GitHub CI results must be checked independently.

## Limitations

- No secure independent signer/owner-role binding, trusted time, revocation lookup, attested reviewer receipts or externally authenticated monotonic audit anchor.
- SQLite `synchronous=FULL` and transactions do not prove durability during hardware power failure, crash recovery on every filesystem or operation under hostile concurrent processes.
- Audit DB is one-proposal-per-file; no cross-device replication, centralized retention policy, privacy controls, or browser/mobile governance workflow.
- A caller-supplied expected head is not anti-rollback. Independently secured and monotonic external checkpoints are mandatory to detect replacement of an entire internally consistent history.
- A complete synthetic review never authorizes `restore_new_journal`. Production restore requires a separate human process and reviewed authorization boundary.

**No merge, deployment, account modification, production approval, key issuance, restoration or release switch. GO-13 HOLD.**
