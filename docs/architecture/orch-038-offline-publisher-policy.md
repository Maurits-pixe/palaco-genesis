# ORCH-038 — Offline Publisher Trust Preflight

**Status:** DRAFT, stacked on ORCH-037 PR #204.

## Implemented

An explicit in-memory policy preflight for candidate offline manifest publishers. It rejects:
- unknown or revoked local publisher IDs;
- malformed or duplicate trust-registry entries;
- claimed epochs below an independently provisioned minimum;
- absent trusted-time evidence;
- expired claims at or after the claimed expiry.

Seven Rust tests cover positive and negative paths.

## Critical non-claims

Preflight cannot authenticate the claimant, signature or expiry claim. The caller controls `PublisherClaim` until cryptographic verification. No production keyring, trusted secure clock, durable epoch high-water mark, anti-rollback storage or Ed25519 verification exists in this candidate. Registry status can be stale offline; long-term network absence cannot guarantee knowledge of remote revocations.

An accepted preflight remains a non-authoritative intermediate state. It MUST NOT authorize runtime execution, personal data access, a content generation promotion or a READY banner. Combined use with ORCH-037's default-denying verifier still returns DENY.

## Next gate

Implement a reviewed Ed25519 verifier and canonical domain-separated signed message, bind publisher keys to provisioned trust anchors, define offline revocation freshness and trusted time provenance, then verify on actual cold-boot and clock-rollback scenarios. Only after cryptographic and durability review may the system consider a trusted offline content receipt.

**GO** for candidate testing. **HOLD** for merge, personal storage and production.
