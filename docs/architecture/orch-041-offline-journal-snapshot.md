# ORCH-041 — Offline Recovery Journal Snapshot

**Status:** DRAFT, stacked on ORCH-040 PR #207.

## Implementation

Non-private staging metadata can be recorded in a bounded, create-only local journal snapshot and re-read after process restart. Frame format: versioned magic, event count, strictly ordered milestone byte codes, SHA-256 digest. Staging milestones: STARTED, DATA_SYNCED, HASH_INSPECTED. The module refuses missing/duplicated stages, truncated/corrupted frames, oversized frames and overwrites. Five isolated filesystem tests exercise reopening, truncation, tampering, duplicate files and skipped transitions.

## Limits of evidence

- The snapshot contains **caller-reported** milestones. The module does not itself validate the file's durability or independently observe the writes.
- SHA-256 of a journal is corruption detection, not a MAC or digital signature; a malicious actor with write access can forge an internally consistent snapshot.
- This writes one immutable snapshot, **not** an append-only transactional journal or crash-consistent generation commit.
- File sync is requested; parent-directory sync and actual power-loss tests are not implemented.
- The default-denying signature verifier still blocks trusted provenance; no automatic PROMOTE/READY or personal storage.
- No permissions/ownership hardening or hostile concurrent-writer safety is implemented. Root must be trusted and exclusive.

## Required next transition

1. Bind journal milestones to verified immutable content and trusted manifest signatures.
2. Create a secure transactional generation journal with atomic publication and parent directory sync.
3. Cold-boot and interrupted-power tests; enforce persisted epoch high-water marks.
4. Independently review encryption and isolated key storage before private data.

**Decision: isolated engineering candidate, CI pending; merge, production, private data and offline READY remain HOLD.**
