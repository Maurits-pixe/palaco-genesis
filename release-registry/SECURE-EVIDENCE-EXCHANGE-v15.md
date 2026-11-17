# PALACO Trusted Evidence v15 — Secure Evidence Exchange

**DRAFT / GO-13 HOLD.** This candidate encrypts a *synthetic* v14 governance proof bundle for one designated recipient. It is not connected to production, does not transport data over Bluetooth or the network, and does not grant restoration or authorization.

## Protocol

`secure_evidence_exchange_v15.py` supplies `seal_bundle` and `open_bundle`:

- Sender selects a recipient identifier and a **preauthenticated** 32-byte X25519 public key. `authorize_send(recipient_id, key_bytes)` is a **required external** policy and current consent check; only literal Boolean True proceeds. Never get this key or policy from the untrusted proof bundle itself.
- Every seal creates a fresh ephemeral X25519 key, derives an independent 256-bit AES-GCM key using HKDF-SHA256 and a domain-separated salt bound to sender ephemeral public key, recipient public key and recipient ID. A fresh 96-bit nonce authenticates the envelope metadata as associated data (AAD).
- The canonical JSON envelope includes `schema`, `recipient_id`, `ephemeral_public_key_b64`, `nonce_b64` and `ciphertext_b64`. Strict unknown-field, canonical encoding, length and recipient-ID validation is enforced.
- Receiver supplies its private X25519 key and expected recipient ID. Invalid or altered ciphertext, headers, nonce and wrong private keys fail closed. Decryption returns only the original bytes: it does **not** assert that the sender is legitimate, that content is a valid v14 bundle, or that anyone may restore a journal.
- The caller must invoke the separate `governance_proof_bundle_v14.verify_bundle` with independently authenticated role and audit-anchor providers **after** decryption.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_secure_evidence_exchange_v15.py' -v
```

20 synthetic tests have been committed covering roundtrip, randomized sealing, missing/rejected/nonboolean/erroring send policy, wrong private key, wrong recipient ID, tampered ciphertext/nonce/ephemeral key, unexpected envelope fields, noncanonical JSON, malformed recipient/public key, empty and overlarge inputs, invalid private-key type and no plaintext leakage into the envelope. Execution and independent GitHub CI results have not yet been confirmed.

## Missing security & operational guarantees

This protocol offers encryption for a key chosen by the caller, **not** authenticated identity or sender signatures. Public-key substitution, malicious recipient mapping, replay of a valid envelope, metadata leakage (recipient ID), endpoint compromise, plaintext retention, receipt sensitivity, secure deletion, backup encryption and key rotation remain unaddressed.

A real secure exchange must add independently authenticated recipient enrollment, authenticated sender signatures, policy-bound expiration/replay protection and revocation, key lifecycle and authenticated storage, least-privilege access, secure UI, operational audit and privacy controls. The current module does not check that input is a valid v14 proof bundle, by design; untrusted decrypted content MUST remain in quarantine until v14 verification.

The cryptographic `cryptography` library is an explicit dependency; package lock and supply-chain review are not included in this commit. Do not use actual personal reviewer data or receipts in this candidate.

No merge to `main`, no publication, no user account changes, no Bluetooth or network transmission, no key issuance and no recovery/production authorization. **GO-13 HOLD.**
