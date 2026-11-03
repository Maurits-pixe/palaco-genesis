# ORCH-042 — Offline Transaction Preflight

**Status:** DRAFT stacked on ORCH-041 PR #208.

## Implementation

A read-only integration check joins:
- candidate generation declaration from ORCH-034;
- reopened bounded journal snapshot from ORCH-041;
- expected chunk count;
- actual filesystem reread and SHA-256 checks through ORCH-040/039/035.

Returns `InspectedCandidate` only if the declared count is consistent, the three journal milestones are present and all public/synthetic pending chunks match their expected size and digest. Five tests cover intact candidate, missing/corrupt chunk, incomplete journal and wrong count.

## Hard limits

- The journal and expectations remain unauthenticated caller inputs; a malicious actor could fabricate all of them.
- `InspectedCandidate` is **not** a durable commit receipt, authenticated source, cryptographic authorization or usable READY state.
- No active-pointer write, atomic rename, power-loss journal or directory fsync is made.
- The module cannot be used with real personal information; encryption and actor isolation are absent.
- No network dependency is added.

## Next action

Specify and implement a secure platform-specific atomic publication mechanism with exclusive directory handles, verified signed manifest, durable high-water mark and post-reboot negative tests. Do not connect this inspection result directly to `GenerationGate::confirm_verified` until the caller is a reviewed, actual durability verifier.

**DRAFT/HOLD** for merge, production, private data and 56-day offline readiness.
