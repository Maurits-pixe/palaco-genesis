# PALACO Trusted Evidence v29 — Identity Trust & Session Lifecycle

**DRAFT / GO-13 HOLD — NOT a live PALACO One service.** No owner account has been created, updated, promoted or revoked. No session, signing key or production permission has been issued.

## Added implementation

`identity_session_lifecycle_v29.py` defines a *local candidate* append-only lifecycle ledger and strict v28 identity-verification callbacks.

- `IdentityLifecycleRegistry(path)` stores only **revocation events**: `REVOKE_SESSION`, `REVOKE_DEVICE`, `REVOKE_OWNER` and `REVOKE_SIGNING_KEY`. Each contiguous integer sequence includes an immutable event, previous hash and domain-separated SHA-256 hash-chain head. There are no grant/re-enable operations; repeated revocation of the same kind+target is refused.
- `revoke(kind, target, verify_external_predecessor, verify_publisher)` uses SQLite `BEGIN IMMEDIATE` and requires an independent authenticated monotonic predecessor check, followed by an external currently authorized publisher policy; literal Boolean `True` from both callbacks is necessary. A stale, missing or untrusted predecessor stops publication. The result remains `authorization: DENY`, `release: HOLD`, `production_release_enabled: false`. Neither callback is implemented here.
- `verified_snapshot(verify_external_head)` checks the complete local chain, then requires the current `(sequence,head)` to match a separately administered, independently authenticated monotonic anchor. Even the empty-genesis state must be independently attested; it is never presumed trustworthy. A separate copy of the same SQLite file is **not** an independent source of trust.
- `policy_callbacks(verify_external_head, check_active_key, check_active_owner)` supplies compatible `trust_key(key_id, claims)` and `check_current_owner(subject, session_id, device_id, action, day)` functions for `OwnerIdentityAdapter` v28. A revoked key, session, device or owner denies access. The callbacks also demand separate **current** issuer-key validity and active OWNER role checks, both requiring literal `True`. A local absence of revocation **never** grants an identity.
- Key rotation is a **policy/interface requirement, not an automated operation**. Rotation must independently enroll a newly pinned Ed25519 public key, invalidate the old key via authenticated revocation and ensure every verifier uses an appropriate current key epoch. The module never creates, copies or stores private keys.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_identity_session_lifecycle_v29.py' -v
```

26 synthetic regression scenarios authored covering signed v28 session integration, session/device/owner/key revocation, stale anchor denial, missing and failing trust providers, truthy non-Boolean rejection, duplicate revocation, sequence persistence after restart, invalid IDs and event types, unknown/denied role or key membership, append-only database triggers, deliberate tampering, whole-log rollback detection against a retained external checkpoint, and absence of any grant/issue API.

**The tests are committed; successful execution and independent CI validation have not yet been established.** Synthetic test callbacks that compare a local copied tuple or return True are **never** acceptable as live external attestation or role/revocation services.

## Production blockers and design limitations

1. No independent secured monotonic checkpoint infrastructure, source of authoritative current roles and device/session revocation, privileged event publisher, authentic owner login or PALACO One integration is connected.
2. v29 local SQLite is not protected against privileged file replacement, consistent simultaneous replacement of local databases, hostile schema edits or key compromise. An independent monotonic root with authenticated publication must be provisioned.
3. The revocation event is committed to local SQLite **before** an external checkpoint would necessarily be published. During that gap the verifier fails closed against a stale checkpoint. A production service needs durable publication-outbox, signed anchoring and recovery semantics.
4. Authenticated key enrollment, rotation, epoch binding, rollback-resistant distribution, emergency revocation and proof-of-possession are not yet implemented. A v28 signed bearer token remains theft/replay-sensitive while valid.
5. External role, key and checkpoint callbacks may change during the verification and v25 daily-review database commit. This prototype does **not** claim atomic authorization across systems; independent race/fault-injection tests and real policy transaction design are necessary.
6. Real session verification requires audited OIDC/session issuance, MFA/device-binding, trusted clock and Europe/Amsterdam policy for Dutch working days. No frontend, API endpoint or live login integration is deployed.

**GO-13 HOLD: no merge, production deployment, real account or role changes, key issuance, automated recovery, or release authorization.**
