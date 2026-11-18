# PALACO Trusted Evidence v20 — Signed Authority Receipts

**DRAFT / GO-13 HOLD — no live signing, authorization or deployment.**

`signed_authority_receipts_v20.py` implements a narrow Ed25519 signature adapter for v19's `sign_receipt(statement)` and a strict proof verifier for v18's `verify_authority(statement, receipt)`. Unlike v19's synthetic receipt test strings, v20 creates and checks actual Ed25519 signatures with the `cryptography` library.

## Design

- `SignedReceiptIssuer(private_key, key_id, authorize_sign)` receives an externally controlled Ed25519 signing key. It only signs canonical v18 receipt statements bound to an exact claim, authority sequence and decision, and ONLY after a required independent `authorize_sign(statement, key_id)` callback returns literal `True`.
- Issued proof is a strictly canonical JSON string with exactly `key_id` and 64-byte canonical Base64 `signature_b64`. No private-key material is serialized. This format is compatible with v19's opaque `proof` string.
- `SignedReceiptVerifier(pinned_public_keys, verify_key_policy, verify_committed)` uses the existing v7 Ed25519 verifier with independently provisioned pinned public keys, current key-revocation/authorization callback, and a **separate mandatory externally authenticated committed-decision proof callback**. It accepts only literal Boolean `True` from both external policy and commit checks.
- The verify-committed callback must prove that the exact canonical decision statement was durably committed in a monotonic externally anchored authority record. A locally signed *orphan* receipt from a rolled-back v19 transaction MUST be rejected. These external services are **not implemented by v20**.
- Wrong key ID, unknown/revoked key, altered signature, modified decision, noncanonical proof or statement, absence of either external trust integration, policy failures and unsigned arbitrary input fail closed.
- The v18 inspection report and all v19 decisions remain read-only diagnostics. `authorization: DENY`, `release: HOLD`, `production_release_enabled: false`.

## Test scenarios

```sh
python -m unittest discover -s release-registry -p 'test_signed_authority_receipts_v20.py' -v
```

22 synthetic test cases committed, including Ed25519 positive/negative checks, changed statements/signatures, incorrect key IDs, external key revocation, uncommitted decision, non-Boolean or unavailable external providers, signing-policy refusal, malformed proofs, direct v19/v18 contract interoperability, and rejection without database mutation. The test fixtures generate in-memory ephemeral signing keys; they DO NOT prove operational key custody, trusted authority identity or external anchoring. **Test execution is not yet independently confirmed.**

## Critical limitations

- Cryptographic signature correctness alone does not prove trusted issuing authority. Public keys must be independently enrolled, pinned, scoped, rotated, revoked and distributed securely; do not trust keys supplied by a receipt.
- Signing happens within the v19 SQLite transaction, but external HSM/signers may issue a valid orphan signature before transaction rollback. Only independent committed-decision proof can close this trust gap.
- No actual hardware-backed key custody, external monotonic checkpoint, signed root metadata, expiration/freshness service, revocation oracle, secure production interface, distributed consensus, device identity or independent security review exists.
- The example callback signatures are extension interfaces and MUST NOT be replaced by test-only unconditional `True` logic in production. A real verifier must verify committed decisions rather than trusting an event merely because an in-memory coordinator reports it.
- Signing a receipt does not activate recovery, process v14 decrypted payloads, issue identities or authorize production.

**No merge to main, production deployment, real-user receipt issuance, account modifications or recovery activation. GO-13 HOLD.**
