# PALACO Trusted Evidence v8 — Key Registry & Revocation (candidate)

**DRAFT / GO-13 HOLD.** `key_registry_v8.py` adds a strict snapshot format and a policy-enforcing wrapper around `ed25519_trust_v7.Ed25519TrustAdapter`. No key service, user account, site, release or live data source is connected.

## Registry contract

`{"schema":"palaco-key-registry/v8","version":3,"keys":[{"key_id":"...","public_key_b64":"...","status":"active","scopes":["candidate-a"]}]}`

Only strict fields are accepted. Public keys are raw 32-byte Ed25519 keys in canonical Base64; records have unique key IDs, explicit active/revoked states, and deduplicated scoped permissions. The registry digest is SHA-256 over `PALACO-KEY-REGISTRY-v8:SNAPSHOT\\x00` plus the existing canonical JSON profile. The digest itself **does not authenticate its source**.

## External trust requirements

`AnchoredRegistry(snapshot, scope, get_anchor, check_current)` requires two independently provided callbacks:

- `get_anchor()` must return a trustworthy, monotonic and currently authoritative `(version, snapshot_digest)` from outside the submitted snapshot. Exact mismatch rejects the check, including a rollback to an older registry.
- `check_current(version, scope)` must return literal Boolean True **only** when an independently authenticated policy and revocation authority confirms current validity, freshness, authorized scope and trusted time. A missing/offline/unknown authority or non-Boolean result rejects the check.

For each signature verification, the adapter checks whether a key is marked active for the configured scope, rechecks the external anchor and current policy, and then performs v7 Ed25519 verification. These checks **do not independently prove** that the external callbacks are trustworthy. A snapshot supplied by an attacker must never be allowed to supply its own trusted anchor or policy callback. Do not treat a public-key hash as a trusted signer identity.

For v6 attestation integration, the caller must independently bind the same scope, key ID and canonical signed statement to the exact evidence being assessed. This module does not parse the v6 statement to establish scope by itself.

## Testing

```sh
python -m unittest discover -s release-registry -p 'test_key_registry_v8.py' -v
```

19 synthetic cases have been added: valid fixture, revoked key, scope mismatch, rollback, changed snapshot, stale policy, unexpected truthy policy, offline policy/anchor, unknown key, modified message, duplicate keys and scopes, unexpected fields, bad Base64, Boolean version, missing trust callbacks, stable fingerprint and malformed anchor. The tests use ephemeral in-memory signing keys; no private key is committed. Their execution and GitHub CI success are not asserted by this documentation.

## Unresolved gates

There is **no independently running key registry**, no real revocation service, no clock trust, no verified policy provenance, no signing-key custody, no checkpoint rotation protocol, no independent security review and no anti-rollback guarantee if the anchor itself is compromised. The code does not implement persistence or automatic network synchronization. The separately trusted anchor source and authorization policy must be designed and audited before production use.

**GO-13 HOLD; no merge, deployment, release authorization, account changes, shared login or recovery activation.**
