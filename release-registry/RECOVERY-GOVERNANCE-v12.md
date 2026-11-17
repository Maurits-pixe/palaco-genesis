# PALACO Trusted Evidence v12 — Recovery Governance Candidate

**GO-13 HOLD. This is a draft review model, NOT a live identity, authorization or recovery service.**

## Governance boundaries

`recovery_governance_v12.py` introduces deterministic, domain-separated review hashes and a distinct governance proposal bound to the exact v11 `approval_bytes` digest, evidence digest, destination basename, sequence and recovery head.

Reviews are a forward-only, in-memory hash chain with exact metadata fields, monotonic sequence numbers, previous hash, actor ID, proposed role, verdict and opaque receipt. Each reviewer identity can appear only once per proposal. The two supported role labels are `owner` and `independent-reviewer`, but labels in a file are **untrusted claims** until checked by a separately configured provider.

`inspect_governance` requires two independently implemented, fresh and trusted integrations:
- `get_trusted_audit_anchor(proposal_sha256)` must retrieve an externally pinned, authenticated monotonic `(review_count, head)`, not compute it from the submitted history.
- `verify_role(statement, receipt, actor_id, role)` must cryptographically authenticate the reviewer, verify that the person/device is authorized in that role and scope at the relevant time, verify freshness, revocation, signature, non-replay and separation of duties. No such service is implemented here.

A complete *candidate review* needs two distinct actors, both roles and no rejection. The result never grants restore approval, key issuance or release authority: `authorization: DENY`, `release: HOLD`, `production_release_enabled: false`. The v11 `approve` function is **not** wired to this report. A rejection blocks candidate completion, even if other parties approve. No signatures, receipts, account data, credentials or private keys are exported in the report.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_recovery_governance_v12.py' -v
```

19 synthetic test cases are committed: two-role path, missing second role, rejection veto, duplicate reviewer, invalid role or receipt, stale head, tampering, reordering, missing anchor/verifier, rollback, non-Boolean verification, verification exceptions, empty history, frozen review metadata, invalid proposal, destination binding, and report redaction. **These tests have been authored but are not independently confirmed as executed.**

## Missing requirements

- Independent owner/role authority, real user verification, trusted signing keys, policy for role separation and current revocation.
- Authenticated, independently controlled durable audit anchor; time/freshness and event ordering; recovery process with explicit human consent.
- Persistent append-only audit database, transaction isolation, cryptographic receipts, actor account binding, browser/mobile QA, power-loss and adversarial tests, security review.
- No auto-authorize or invocation of `restore_new_journal` through this candidate.

No merge to main, production publication, account modification, release activation or restoration of real policy data.
