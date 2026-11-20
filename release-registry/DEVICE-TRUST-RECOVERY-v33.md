# PALACO Trusted Evidence v33 — Device Trust & Synchronization Recovery

**DRAFT / GO-13 HOLD. No live key installation, automated recovery, device enrollment or authorization.**

## Added implementation

`device_trust_recovery_v33.py` extends v32's per-module synchronization receipt contract:

- **Cryptographic device acknowledgments.** `DeviceProofVerifier(resolve_device_public_key, current_device_policy)` implements the exact v32 `verify_device(module, statement, proof)` callback. It accepts only canonical, precisely shaped JSON proof envelopes containing a schema, module, registered key ID, SHA-256 of the exact v32 canonical statement and base64 Ed25519 signature. The signed message is a domain-separated canonical object that includes the module and key ID as well as the exact statement digest. A signature for a different challenge, bundle, module or prior receipt cannot be transplanted without failing verification.
- **Independently pinned device identities.** The public key must come from externally authenticated `resolve_device_public_key(module,key_id)`, **never from untrusted proof contents**. A fresh external `current_device_policy(module,key_id,statement_sha256)` must confirm current registration, allowed scope, device/key revocation and sender authorization. Both are required; only literal Boolean `True` from the policy is accepted. Invalid/unknown/revoked keys, unavailable sources, malformed proof and bad signatures fail closed.
- **Read-only interrupted synchronization diagnostics.** `DeviceSyncRecoveryInspector(registry,max_pending=8).inspect(module,verify_sync_head)` validates the v32 receipt chain and requires an independently authenticated exact remote monotonic receipt root, then reports pending challenge count, stale challenge count, excessive pending challenge count, and manual review requirement. Its statuses are `NO_RECEIPT`, `ACKNOWLEDGED_LOCALLY`, `PENDING_EXTERNAL_REVIEW`, `STALE_CHALLENGES`, `EXCESS_PENDING`.
- **No key installation or recovery.** Inspection does **not** consume challenges, retry acknowledgments, sign anything, install a key or grant session/owner authority. All reports remain `authorization: DENY`, `release: HOLD`, `key_installed: false`, `production_release_enabled: false`. The report never exposes challenge secrets or their hashes.

## Regression tests

```sh
python -m unittest discover -s release-registry -p 'test_device_trust_recovery_v33.py' -v
```

31 authored scenarios exercise valid synthetic Ed25519 proof, altered statement, wrong module/key, revoked or unavailable device, non-Boolean policy, malformed/noncanonical/extra fields, invalid signature encoding, pending/stale/excessive/consumed challenges, restart persistence, unavailable/non-Boolean/stale external root, corrupt challenge records, refusal of recovery execution, and a full synthetic v30/v31/v32 cryptographic acknowledgment integration.

**The test code is committed; successful execution has not yet been independently confirmed.** Ephemeral Ed25519 test keys and synthetic external policies do not provide real-world trusted device enrollment.

## Remaining production blockers

1. No PALACO device enrollment, hardware-backed device key custody, independent proof-of-possession registration, revocation provider, controlled issuer rotation or secure device clock. The verifier depends on externally provided trustworthy device key/policy callbacks.
2. No independent authenticated monotonic v32 receipt-root service. A callback that merely echoes the local SQLite root does not establish trusted continuity.
3. v32 challenges still lack an enforced expiration timestamp, request quotas, challenge cleanup and rate limiting. The v33 inspector **detects** excessive/stale challenges but cannot prevent storage exhaustion or replay indefinitely. Fresh short-lived challenge issuance and bounded storage are required before live use.
4. Receipt append, external trust roots and key installation remain non-atomic across v29–v32 databases and devices. A device's cryptographic acknowledgment alone is **not proof a public key was installed**.
5. The v33 verification callback is intentionally free of private-key management. No actual key distribution, deployment, production service, account change or automated recovery is performed.
6. Independent CI/security testing, concurrency/crash/power-loss fault injection, adversarial protocol review, transport authentication, signed epoch consistency and privacy/retention validation are still needed.

**GO-13 HOLD — no merge to main, live identity/device changes, release authorization, key activation or automated recovery.**
