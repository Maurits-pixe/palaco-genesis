# Signed Audit Checkpoint v0.1 — DRAFT / HOLD

`tools/signed_audit_checkpoint.py` verifies a detached Ed25519 signature over
a strict canonical JSON checkpoint containing `schema_version`, `sequence`
and `head_hash`. The signature is domain-separated with
`PALACO-AUDIT-CHECKPOINT-V1`. It then verifies the *complete local audit
chain* read-only and checks that its final hash **and sequence** match.

The caller MUST supply authenticated issuer roots and a trusted external
minimum sequence. A matched, cryptographically valid checkpoint returns only
`pending-review`; it does not grant authority or certify who signed it.

**Not implemented:** external checkpoint publication/storage, issuer credential
governance, revocation, trusted timestamps, secure monotonic counters, consensus
or tamper-proof database storage. A self-signed checkpoint and untrusted roots
provide no security. A compromised issuer can sign a malicious chain.
Old checkpoints can pass unless the external sequence floor is protected and
monotonically updated. No production deployment or merge is authorized.

Tests:
```sh
python3 -m unittest discover -s tests -p 'test_signed_audit_checkpoint.py' -v
```

GO-13 HOLD. Authorization DENY.
