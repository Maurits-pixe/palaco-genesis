# PALACO Trusted Evidence v7 — Ed25519 Trust Adapter

**Status: development candidate; GO-13 HOLD. No deployment or authorization.**

`ed25519_trust_v7.py` implements a narrow, real Ed25519 signature verification adapter for the `verify_attestation(statement, signature, key_id)` callback in `trusted_evidence_v6.py`.

## Cryptographic boundary

- Uses the established `cryptography` Python package's Ed25519 public-key verification. This package is an explicit non-standard dependency; installation and version/security maintenance remain separate build responsibilities. If it is missing, verification returns `False`.
- Pinned public keys are provided as a mapping of key IDs to **exactly 32 raw bytes**, independently of the received evidence. Keys carried inside a received JSON document must never be trusted.
- Detached signatures are canonical, padded Base64 strings representing exactly 64 signature bytes. Any malformed encoding, unknown key, tampered statement or tampered signature fails closed.
- A separately supplied `verify_policy(key_id, statement)` callback **must** determine current signer permission, freshness, key revocation and policy context. Missing, failed, exceptional or non-boolean verification denies. It is not implemented by this candidate.
- The adapter does **not** generate signing keys, sign statements, maintain an external key registry, check time or revocation independently, authenticate external checkpoints or authorize restoration. Nor does it alter the v6 evidence report's `authorization: DENY` and `release: HOLD`.

## Example (test fixtures only)

```python
from ed25519_trust_v7 import Ed25519TrustAdapter

# A real application must obtain these from an independently authenticated
# configuration with a trustworthy revocation/rotation policy.
key_bytes = bytes.fromhex("00" * 32)  # INVALID DEMONSTRATION KEY, DO NOT USE
def example_policy(_key_id, _statement):
    return False  # Missing policy and revocation = deny

verify_attestation = Ed25519TrustAdapter(
    {"demo-only": key_bytes}, verify_policy=example_policy)
```

This example never accepts any signature. Do not substitute a fixture that returns True in real deployments.

## Regression tests

```sh
python -m pip install 'cryptography>=43,<47'   # isolated development environment only
python -m unittest discover -s release-registry -p 'test_ed25519_trust_v7.py' -v
```

15 local tests passed on 17 Nov 2026, using Python 3.13 and cryptography 46.0.4. A first test run identified an exception-handler bug, which was corrected before committing. Tests generate temporary in-memory Ed25519 keypairs and cover valid signatures, changed messages, altered signatures, unknown or forged keys, malformed Base64, missing policy, policy denial, policy failure and non-boolean policy responses. No private signing keys are committed.

## Required integration gates

Before use outside isolated tests: pin and audit the dependency; independent trusted-key distribution and rotation; actual revocation oracle; trusted time/freshness; signed policy and external monotonic checkpoint; end-to-end v6/v7 fixtures; integration test vectors; independent review of error handling; proof that key material is not derived from untrusted evidence; CI and platform tests.

**GO-13 HOLD: no merge to main, live user data, production release, site deployment, account changes or recovery activation.**
