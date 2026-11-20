# PALACO Trusted Evidence v16 — Authenticated Secure Exchange

**DRAFT / GO-13 HOLD.** `authenticated_exchange_v16.py` is a candidate wrapper around v15 encryption. It neither connects to network/Bluetooth nor authorizes users, production, account changes, release or restoration.

## Protocol

- Sender creates a v15 X25519 / HKDF / AES-256-GCM encrypted envelope for an independently authenticated recipient key. The recipient's current permission must be checked by `authorize_send`.
- A sender-provided Ed25519 private key signs a v16 domain-separated statement binding the *entire exact ciphertext envelope SHA-256*, sender key ID, recipient ID, randomly generated message ID and schema. This wrapper carries the signed message and canonical 64-byte detached Base64 signature.
- Receiver requires `verify_sender(statement, signature_b64, sender_id)` from an **independently authenticated**, current signer/key registry and revocation policy, e.g. the v7 Ed25519 verifier configured with independently pinned keys. Never use keys supplied by the message as a source of trust.
- After valid signature and successful decryption, `claim_replay(sender_id, recipient_id, message_id, package_sha256)` MUST **atomically and durably** reserve the exact sender/recipient/message tuple, rejecting reused IDs even if the ciphertext differs. The candidate has no storage service of its own. A Boolean true from an insecure in-memory/test callback gives no real replay guarantee. Unknown/offline registry, failed claim or non-Boolean callback fail closed.
- Receive returns original decrypted bytes and a redacted inspection report with `authorization: DENY`, `release: HOLD` and `production_release_enabled: false`. Those bytes remain untrusted content until the separate v14 proof-bundle verifier validates exact source bytes, independent governance roles and pinned audit anchor.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_authenticated_exchange_v16.py' -v
```

20 tests committed: synthetic valid signing/encryption, exact replay denial, message ID reuse with new ciphertext, distinct messages, altered IDs/envelope, forged sender, wrong recipient, missing or denied providers, exceptional replay store, non-Boolean claims, invalid signature, noncanonical encoding, denied send, wrong decryption key, bad signing key and no plaintext in the report. Ephemeral signing and recipient keys are generated in-memory. **Their execution and GitHub CI success have not yet been independently confirmed.**

## Threat model and remaining gates

- A signed envelope proves control of a private key **only if** the public key's sender mapping is authenticated and current, including revocation. The source code does NOT provide such mapping, secure key custody or a trusted clock.
- A reliable replay registry must persist and atomically enforce first-use across devices, outages and process crashes; in-memory fixtures cannot. Race testing and distributed fork protection remain necessary.
- This implementation uses a random ID by default, with externally supplied IDs allowed only for test/integration; callers must independently prevent collisions if supplying their own.
- There is no cryptographic forward-secret guarantee after all relevant endpoint keys are compromised, no signed trusted timestamp or message expiry, no automatic key-rotation protocol, no secure device enrollment, no actual live user-consent service.
- Callback-provided approvals are **not** release authority. The v15/v16 envelope also leaks nonsecret metadata such as sender/recipient IDs. Legal/privacy review is required for real use.
- External cryptography dependency pinning and security review, interop test vectors, real recipient key registry, persistent replay service, signed-policy governance, full v14 integration and operational mobile QA are still pending.

**No merge to main, no production publication, no restoration, no account change and no issuance. GO-13 HOLD.**
