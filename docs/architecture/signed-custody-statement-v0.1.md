# Signed Custody Statement v0.1 — DRAFT / GO-13 HOLD

The verifier `tools/signed_custody_statement.py` checks a detached
Ed25519 **claim of custody**. It includes exact domain-separated hashes of
the previously signed custody-policy envelope and receipt-chain checkpoint,
policy revision, event count, chain head, custodian identity and statement ID.

Trust requirements at the call boundary:
- Independently authenticated custodian ID -> signing key fingerprint set;
- public keys and revocations distinct from governance and witness keys;
- independently pinned governance roots, policy minimum revision,
  witness roots, witness revocations and external receipt count floor.

All content/signature, policy and underlying receipt-chain reconciliation
must agree. A custodian key equal to the specified governance issuer or
receipt witness key is rejected to enforce separation of signing roles.
A valid result still returns only `pending-review`, `release_gate=HOLD`
and no authorization, restoration, merge, publishing or deployment.

The statement does **not** prove that a human received the data or that any
off-device independent, immutable store actually retained it. No real
custodian directory, key ceremonies, trusted timestamps, transmission,
physical custody, replay-resistant remote ledger or external storage is
implemented. Treat signatures as authenticated claims under caller-supplied
trust policy only.

Test: `python3 -m unittest discover -s tests -p 'test_signed_custody_statement.py' -v`.
