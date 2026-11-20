# PALACO Trusted Evidence v30 — Identity Key Rotation & Revocation Authority

**DRAFT / GO-13 HOLD — no production key rotation or PALACO One account changes.**

## Implemented

`identity_key_rotation_v30.py` adds a local, append-only, two-phase key-transition candidate:

- `prepare(old_key, new_key, public_key, expected_sequence, expected_head, verify_predecessor, check_policy)` verifies the externally authenticated current monotonic predecessor and the independent key-transition publisher policy. It records an immutable `PREPARE` event with generation, old/new key IDs and the SHA-256 fingerprint of the proposed **public** Ed25519 key. No private key enters this module. One pending transition at a time.
- `commit(...)` requires the exact matching pending PREPARE (including public-key fingerprint), a fresh external anchor for the PREPARE event and current independent policy approval. It appends a `COMMIT` event as another contiguous, domain-separated SHA-256 chain step.
- SQLite `BEGIN IMMEDIATE` plus expected `sequence,head` enforces local compare-and-swap against concurrent/stale writers. Ordinary row updates/deletions are prevented by SQL triggers.
- `inspect_local()` reports current local generation, active key ID, pending transition and retired count for diagnostics; never certifies a key.
- `trust_key(key_id, claims, verify_current_head, check_external_key, expected_fingerprint)` is a **fail-closed optional v28 trust_key callback**: only the current locally committed key ID whose public-key fingerprint matches the expected independently supplied fingerprint is considered, **only when no transition is pending**, **only when an independently authenticated current monotonic head is confirmed**, and **only if external key enrollment/current revocation policy returns literal True**. A valid local COMMIT is not, by itself, trusted publication.
- An older key is locally retired when the next generation commits and cannot be silently reselected. Rotation does **not** automatically call the v29 key-revocation journal: that cross-service coordination and authoritative external revocation must be designed and tested.
- Every result remains `authorization: DENY`, `release: HOLD`, `production_release_enabled: false`. A successfully completed local transition is not permission to use or issue the key.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_identity_key_rotation_v30.py' -v
```

30 synthetic regression cases committed, including pending and committed rotation, restart persistence, mismatch/stale CAS/forged predecessor, exact key fingerprint, two key generations, refusal to reuse retired keys, refusal of old keys, negative/non-Boolean external checks, deliberate corruption, append-only triggers and non-authorization. External checks in tests are fake and not production trust. **Execution has not yet been independently confirmed.**

## Important limitations

1. No independent monotonic anchor service, real key enrollment authority, trust-store distribution, authenticated owner approval or hardware-backed private-key custody exists. All callbacks must be replaced by independently provisioned, continuously revocation-aware services before live use.
2. PREPARE/COMMIT are committed to local SQLite before the external root is necessarily published. An interruption between writes and anchoring is intentionally fail closed; a reliable anchor-publishing outbox/recovery process is not implemented here.
3. A COMMIT does not atomically replace any live issuer key; it neither activates nor invalidates PALACO One keys. Existing signed tokens may remain valid in other verifiers until those external systems enforce revocation and key-generation policy.
4. The optional v28 `trust_key` integration must not use stale external fingerprints, locally echoed roots or test-only callbacks, and must be composed with v29's independently attested lifecycle and current OWNER policy.
5. The first local generation uses a predecessor key identifier as a protocol field, not a proof of a previously trusted key. Real bootstrap needs externally approved initial identity/authority and audited chain-of-custody.
6. A privileged process can replace or roll back the rotation SQLite database. Only an independently secured, authenticated monotonic root can make rollback detectable. This module contains no deployment, background task, real secrets, or production signing functions.

**GO-13 HOLD: no merge to main, real-user identity changes, live key replacement, issuance, automatic recovery, or release authorization.**
