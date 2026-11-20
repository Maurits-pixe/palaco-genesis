# PALACO Trusted Evidence v31 — Key Rotation Recovery & Trust Distribution

**DRAFT / GO-13 HOLD.** The v31 module is a read-only candidate export and recovery inspection protocol, **not** a deployed key-distribution system, authenticated external trust anchor, key issuer or automatic recovery service.

## Implementation

`key_rotation_distribution_v31.py` consumes the v30 rotation journal and v29 lifecycle revocation journal.

- `KeyRotationDistribution(rotation, lifecycle).recovery_inspection(verify_rotation_head)` checks the full local v30 rotation chain and exact externally attested monotonic `(sequence,head)`. It returns `PENDING_EXTERNAL_REVIEW` during a staged but uncommitted transition, `LOCALLY_COMMITTED` for a fully committed generation or `NO_GENERATION` for genesis. The procedure performs **no COMMIT**, no retry, no key activation and no release.
- `candidate(key_id, public_key, verify_rotation_head, verify_lifecycle_head, verify_active_key)` exports **public Ed25519 key bytes only** in a deterministic JSON-serializable candidate: key ID, current generation, rotation checkpoint sequence/head, lifecycle checkpoint sequence/head, public key, SHA-256 fingerprint and canonical domain-separated bundle digest. It requires a fully committed, non-pending current generation, exact public-key fingerprint matching the v30 COMMIT, independently authenticated exact monotonic heads for **both** v30 rotation and v29 revocation, absence of local key revocation, and a separate current enrollment/revocation check returning literal `True`.
- `inspect_candidate(bundle, verify_rotation_head, verify_lifecycle_head, check_active_key)` enforces exact field shape, canonical SHA-256 integrity, fingerprint, DENY/HOLD status and live independent trust callbacks. An old bundle with an outdated rotation head fails when the external anchor advances, assuming the callback is truly monotonic. A digest does **not** authenticate a bundle by itself.
- Every report explicitly remains `authorization: DENY`, `release: HOLD`, `production_release_enabled: false`. Exported key material does not grant signer authority. A verifier must independently pin the public key before trusting an identity signature.

## Regression tests

```sh
python -m unittest discover -s release-registry -p 'test_key_rotation_distribution_v31.py' -v
```

28 synthetic tests have been added covering genesis refusal, valid local candidate, independent callback requirements, pending PREPARE and recovery inspection, stale/unavailable/false/non-Boolean rotation and revocation roots, revoked signing keys, current enrollment, mismatched keys and public bytes, tampered bundles, old distribution after rotation, deterministic evidence digest, no private-key API, corrupted v30 storage and permanent DENY/HOLD.

**The tests are committed but their execution has not been independently confirmed.** In tests, callback values may be derived from synthetic in-process state. Such callbacks are NOT independently authenticated trust anchors.

## Required production gates

1. Independently managed, authenticated **monotonic** v29/v30 checkpoint providers (not callbacks echoing the submitted local root); atomic publication and consistent key-generation epochs across consumers.
2. External issuer enrollment and revocation, authenticated signature on distributed trust manifests and a secure trust-distribution channel. The bundle's self-contained SHA-256 digest cannot prevent adversarial replacement.
3. Authenticated enrollment of real Ed25519 signing keys, trusted key custody (preferably hardware-backed), key compromise handling, v29 revocation coordination and explicit rotation-rollback/disaster-recovery procedure.
4. Browser/API transport, subscriber device and version acknowledgment, secure caching, expiry, offline synchronization, downgrade protection, replay resistance and signed root distribution.
5. A live PALACO One owner identity provider, permission revocation source, secure sessions and end-to-end v27/v28 integration, with independent security testing of concurrency and failure-injection scenarios.
6. Cross-database consistency between v29 revocations and v30 rotation events remains non-atomic; even repeated checks cannot guarantee linearizable authorization during concurrent changes. A production attested epoch snapshot or consensus-backed protocol is necessary.

**No merge, account modification, live key activation, automatic COMMIT or production release. GO-13 HOLD.**
