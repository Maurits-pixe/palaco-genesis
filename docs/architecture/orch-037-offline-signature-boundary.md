# ORCH-037 — Offline Signature Trust Boundary

**Status:** DRAFT / FAIL CLOSED. Stacked on ORCH-036A PR #203.

## This PR

Adds an explicit signature envelope and verifier interface to the offline manifest pipeline. The default verifier always rejects, even when the SHA-256 manifest root matches. The gate validates canonical manifest binding and key-identifier syntax before delegating signature handling to a separately reviewed implementation.

Five regression tests cover rejection by default, mutated manifest, invalid key ID, invalid manifest and a deliberately permissive verifier used only inside tests to demonstrate that the interface itself does not prove cryptographic authentication.

## Missing trusted path

- No Ed25519 implementation, key provisioning, secure key custody, signer authorization, revocation, trusted time or key rotation.
- No security review of external cryptography dependencies.
- No durable recovery, encrypted personal storage or real offline READY evidence.
- A custom verifier can claim success without checking the signature. Any implementation must be independently reviewed, strictly bound to an approved key registry, canonical signed message and domain label.
- Neither a hash match nor a test-stub signature yields authorization.

## Valid next step

Select reviewed Ed25519 verification dependency and lockfile, define canonical message format with domain separation, define trusted publisher key registry, revocation/expiry and anti-rollback policy, implement negative tests (wrong key, changed signature, replay, old key, expired key), then audit. Until then all production manifest signature checks use `DenyAllSignatureVerifier`.

**Decision: engineering candidate only; personal data, merge, deployment and offline READY remain HOLD.**
