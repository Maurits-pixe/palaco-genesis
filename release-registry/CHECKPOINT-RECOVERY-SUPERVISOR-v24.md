# PALACO Trusted Evidence v24 — Checkpoint Recovery Supervisor

**DRAFT / GO-13 HOLD.** No production scheduler, human authorization, external trust anchor or real automatic recovery is enabled.

`checkpoint_recovery_supervisor_v24.py` adds a persistent, explicit single-attempt supervision layer over v23's durable outbox. It uses its own SQLite append-only attempt log and rejects uncertain or security-sensitive recovery conditions rather than silently retrying them.

## Core behavior

- `CheckpointRecoverySupervisor(path, queue, max_attempts=3)` requires a v23-compatible queue and a local SQLite database at a controlled path. The retry budget is strictly an integer between 1 and 10, default 3.
- `inspect()` supplies a locally derived overview with pending, sequence, number of attempts, bounded retry limit, last error and state `READY`, `RETRYABLE`, `BLOCKED`, `EXHAUSTED`, or `NO_PENDING`. This overview is diagnostic only.
- `run_once(verify_receipt, authorize_publish, independently_verify_anchor)` makes **at most one** explicit v23 reconciliation attempt. It requires all three external trust callbacks. The supervisor has **no timer, no background loop and no automatic privilege elevation**.
- Each attempt is serialized by `BEGIN IMMEDIATE` and recorded as an append-only result. A successful v23 `LOCALLY_RECONCILED` is accepted only when its sequence matches the pending intent and the result still explicitly contains `authorization: DENY`, `release: HOLD`, `production_release_enabled: false`.
- Only `EXTERNAL_ANCHOR_UNAVAILABLE` is considered **RETRYABLE**. After the configured attempt budget is exhausted, the target is **EXHAUSTED** and further attempts are refused.
- Negative external attestation, changed authority history, missing trust providers, signature/publisher failure, contradictory checkpoint state and unrecognized v23 failures do **not** trigger a retry policy. They are **BLOCKED** or fail closed.
- Raw exception text, callback secrets and decrypted evidence content are not written to the attempt log; only stable error codes are retained.

## Regression suite

```sh
python -m unittest discover -s release-registry -p 'test_checkpoint_recovery_supervisor_v24.py' -v
```

22 regression cases have been authored: first success, no duplicate attempt, retryable external outage, explicit retry only, restart recovery, retry-budget exhaustion, signature/publisher/attestation rejection, missing verifier, persistence of blocked state, invalid retry configuration, append-only guards, deliberately corrupted attempt sequence, error redaction, renewed budget on a new checkpoint, and permanent DENY/HOLD. These tests use synthetic trust callbacks and **have not been confirmed as executed**.

## Operating limitations

A v24 supervisor is not a production deployment or authorization engine. An external authenticated signer/policy, independently controlled monotonic checkpoint authority, secure key lifecycle, trusted time, verified multi-device registry and operational audit still need implementation. If these services are absent or not independently attested, fail closed.

This design makes external calls while holding the supervisor's local SQLite write lock; for a production rollout, implement a nonblocking lease/outbox state machine with lease expiry, crash recovery, exactly-once durable idempotency and verified concurrent-worker behavior. Independent security and fault-injection tests are required.

The supervisor DB, v23 outbox DB, v22 anchor DB and v19 authority DB can all be rolled back or replaced by a privileged process. Their separation in filenames is NOT cryptographic independence. Never substitute a callback that only compares against the same local anchor database.

No merge to main, account changes, key issuance, automatic recovery, external publication, or production authorization. **GO-13 HOLD.**
