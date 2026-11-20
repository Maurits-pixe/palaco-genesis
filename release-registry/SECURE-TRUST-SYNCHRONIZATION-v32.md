# PALACO Trusted Evidence v32 — Secure Trust Synchronization

**DRAFT / GO-13 HOLD.** No live trust distribution, key installation, authenticated device provider or production authorization has been enabled.

`secure_trust_sync_v32.py` extends v31's public-key candidate protocol with a per-module, local monotonic acknowledgment journal. It **does not** install keys or make a distributed trust root.

## Contract

- `TrustSyncRegistry(path).stage(module, bundle, verify_sync_head, verify_rotation_head, verify_lifecycle_head, check_active_key)` requires a strictly next-in-sequence generation for that module. It independently checks the current remote per-module acknowledgment root and the **current** v31 bundle rotation/revocation/enrollment callbacks. The result is an unprivileged, random, 256-bit challenge; SQLite persists only its SHA-256 digest, module, generation, bundle hash and prior receipt root. It does not authorize installation.
- `acknowledge(module, bundle, challenge, proof, verify_device, verify_sync_head, verify_rotation_head, verify_lifecycle_head, check_active_key)` checks challenge reuse, binding to the exact module and bundle, monotonic generation and checkpoint sequences, and fresh independent trust callbacks. A genuine implementation of `verify_device(module, statement, proof)` MUST verify a current registered device signing key, revocation, proof scope and that the device signed the **exact canonical statement** containing the challenge digest, module, bundle digest and previous receipt root. Only literal `True` is accepted.
- If all callbacks pass, v32 appends a local immutable, domain-separated SHA-256 receipt record and consumes the challenge in the same SQLite transaction. The response is **`device_acknowledged: true`, `key_installed: false`, `authorization: DENY`, `release: HOLD`, `production_release_enabled: false`**.
- `inspect_local(module)` checks local contiguous per-module generations and receipt-hash linkage after restart. This diagnostic view never authenticates trust and cannot be used as the `verify_sync_head` callback.
- Ordinary receipt UPDATE/DELETE operations are blocked by SQLite triggers. A privileged actor can still replace or roll back this entire database.

## Synthetic regressions

```sh
python -m unittest discover -s release-registry -p 'test_secure_trust_sync_v32.py' -v
```

28 synthetic regression scenarios were added: first stage, acknowledgment without installation, one-use challenge, unknown/invalid token, incorrect module, downgrade/generation gap, stale remote sync root, full sequential generation, revoked key, untrusted rotation, false/non-Boolean/unavailable device signature provider, missing callbacks, altered bundle, stale in-flight bundle, independent modules, restart persistence, data tampering, immutable receipt triggers, hashed-only challenge storage and no release/installation API.

**Tests are authored and committed; successful test execution has not been independently verified.** The device verification fixture returns a Boolean and is not an actual cryptographic signature verifier.

## Critical trust and availability limits

1. **No real authenticated device proof implementation** is provisioned. The `verify_device` callback is an external requirement; raw proof strings are not cryptographically validated by this module.
2. Neither v31's bundle self-hash nor v32's acknowledgment receipt self-hash is an independently authenticated signature. Real distribution requires signed manifests, independently pinned trust roots, issuer enrollment and current revocation.
3. Cross-database v29 lifecycle, v30 rotation and v32 receipt updates are **not atomic**. Rechecks do not eliminate time-of-check/time-of-use races; a coordinated signed epoch and independent monotonic consensus source are required.
4. The v32 challenge has no built-in expiry or pending-challenge quota. Deployment must add authenticated issuance/expiry, rate limits, safe cleanup, storage limits and protection against resource exhaustion.
5. Device and server can be out of sync while offline. v32 refuses skipped generations, old bundles and missing external roots rather than automatically trusting cached data. An authenticated reconciliation and disaster-recovery plan remains necessary.
6. No secure network transport, production endpoint, subscriber registry, device hardware custody, user-access policy, real PALACO One session or key installation is implemented.
7. A successfully appended acknowledgment only records a local diagnostic. It cannot provide evidence of physical device installation or permit runtime key acceptance.

**GO-13 HOLD — no merge to main, automatic key activation, production synchronization, live identity modification, receipt issuance or release.**
