# ORCH-053 — Registry checkpoint binding

Derived implementation proposal, stacked on ORCH-052; not canonical authority.

The registry now computes a SHA-256 commitment over domain PALACO-ORCH-053-OFFLINE-REGISTRY-v1, the minimum epoch (u64 big endian), entry count (u64 big endian), and entries sorted by key ID. Each entry contributes key ID (32 bytes), exact public key (32 bytes), registration epoch (u64 big endian), and state (one byte: active=0, revoked=1). Revoked keys are retained. Insertion order has no effect.

checkpoint(revision) passes this digest and the actual minimum epoch into ORCH-052. Revision remains caller supplied. No network, wall clock, new dependencies, filesystem changes, or authority are introduced.

Four additional tests cover insertion order, floor/epoch/membership/revocation binding, stale and forked state comparison, and missing-anchor denial. These are test definitions until CI executes them.

AI-review through three lenses: TRIAS — existing grant and execution boundaries preserved; ORACLE — a hash binds bytes but cannot authenticate policy or protect a rolled-back anchor; MENTOR — removes caller-supplied registry digest from the convenience path and documents its exact encoding. No independent human review claimed.

DRAFT/HOLD for activation: authenticated durable anchor storage, crash/restart integration, replay reservation and governance review remain absent. Existing low-level APIs remain available and require callers to supply trustworthy evidence. Matching an anchor never authorizes recovery. Next engineering transition: design and test durable anchor provenance and restart behavior under the applicable gates. No merge or deployment authorized by this proposal.
