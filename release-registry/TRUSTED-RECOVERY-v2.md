# PALACO Trusted Recovery v2 — candidate

This is a **read-only proposal**, not a trusted production implementation. It adds an explicit external trust boundary to the offline SQLite journal's replay checks. No live signing, key distribution, owner identity, revocation service, trusted clock, or external checkpoint provider is connected.

## Boundary

- `checkpoint_statement(scope, sequence, head)` produces canonical, domain-separated bytes for external independent signing/verification.
- `verify_recovery(journal, checkpoint, scope=..., verify=...)` demands a non-empty opaque receipt and a callable verifier. It accepts **only literal Boolean True** from that verifier. Missing/offline/false/exceptional verification rejects recovery.
- The verifier callback **must independently** authenticate trusted signer identity, key status, signature, scope, monotonically pinned checkpoint, policy and current revocation state. The candidate code cannot enforce those obligations without a trusted external adapter; an always-true callback is insecure.
- Replay must independently match the checkpoint's exact sequence and SHA-256 head. The journal is not modified.
- `prepare_backup(...)` returns canonical metadata-only backup bytes. `verify_backup(...)` checks the canonical encoding, event replay, scope and checkpoint before returning metadata. **No restore is implemented**, so no backup can overwrite the journal.
- No secrets, payload bytes, credentials or user records belong in this layer.

Example synthetic testing contract (NOT production):

```python
def test_only_verifier(statement: bytes, receipt: str) -> bool:
    return statement.startswith(b"PALACO-TRUSTED-RECOVERY-v2:") and receipt == "fixture"
```

An actual adapter must not rely on this fixture or a stored user-supplied checkpoint alone.

## Test command

```sh
python -m unittest discover -s release-registry -p 'test_trusted_recovery.py' -v
```

Seventeen tests cover accepted replay/restart, missing or false verifier, truthy nonboolean, exceptions, wrong scope/head/sequence, empty receipts, unknown fields, backup validation and tamper rejection. Tests are synthetic and do **not** prove that an external trust provider exists.

## Unresolved gates

A trusted verifier/service, authenticated signer binding, durable monotonic anchor outside the journal, independently signed receipts, freshness and revocation, reliable checkpoint rotation, encryption and key management, durable cross-device backups, actual restore transaction with human approval, crash/power-loss fault injection, and user-facing integration are still absent.

**GO-13 HOLD. No merge, deployment, account activation, key issuance, shared login, or production synchronization.**
