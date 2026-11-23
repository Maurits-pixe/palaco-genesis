# Organization Authority Evidence v0.1 — DRAFT / GO-13 HOLD

The verifier `tools/organization_authority_evidence.py` checks a detached
Ed25519-signed, narrowly scoped **assessor-review delegation claim**.
It binds a particular organization ID, assessor public-key fingerprint,
current signed witness registry envelope SHA-256, registry revision and
the exact SHA-256 of the underlying signed identity-evidence envelope.

Verification first rechecks the entire registry succession against
independently pinned genesis/head hashes and a minimum registry revision,
then the assessor's identity-evidence signature and revocation policy.
The delegation is accepted only if its signer belongs to an externally
pinned allowlist of delegator keys, is not revoked, and is not the assessor,
registry issuer or a historical witness. An externally pinned minimum
delegation revision rejects old claims. Any other scope than
`identity-evidence-review-only` is rejected.

**No real-world authority is granted.** An authenticated claim does not
prove the signer's legal right to represent the organization. No legal
registry lookup, verified power of attorney, signer identity ceremony,
independent immutable archive, key rotation process or remote revocation
service exists in this module. An old claim can only be excluded if the
caller maintains the minimum delegation revision and current revocations
outside PALACO. There is no release, recovery, merge, deployment, or
automatic authorization. All valid results remain `pending-review` and
`release_gate=HOLD`.

Tests: `python3 -m unittest discover -s tests -p 'test_organization_authority_evidence.py' -v`.
