# PALACO Signed Reviewer Registry v0.1 — DRAFT / HOLD

`tools/signed_reviewer_registry.py` validates an issuer-signed Ed25519 snapshot
containing reviewer IDs, public-key fingerprints, UTC validity periods, revocation
flags and monotonically increasing revision numbers.

It uses an explicit domain separator (`PALACO-REVIEWER-REGISTRY-V1`) to prevent
cross-protocol signature substitution. Verification requires independently
authenticated issuer trust roots, a trusted evaluation time, and an externally
persisted minimum revision. The prototype does **not** supply those trust roots,
trusted time, persistent rollback protection, reviewer identity proof or
authorization. An eligible reviewer only receives `pending-review`; the
`authorization_granted` field is always false.

This module is **not yet wired** to the signed replay pipeline. That pipeline
continues to require additional independent checks. The test private key is a
public test fixture and must never be used for actual issuance.

Run: `python3 -m unittest discover -s tests -p 'test_signed_reviewer_registry.py' -v`

No database migrations, key issuance, deployments, merges or public exposure.
**GO-13 HOLD.**
