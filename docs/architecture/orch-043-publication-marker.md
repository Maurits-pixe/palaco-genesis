# ORCH-043 — No-clobber Offline Candidate Marker

**Status:** DRAFT, stacked on ORCH-042 PR #209.

## Implementation

- Public/synthetic-only candidate marker in a trusted local directory, containing sequence and manifest root plus a SHA-256 corruption digest.
- Create-new pending marker, sync file, create final hard-link without replacing an existing final path, request parent directory sync, remove pending name and request directory sync again.
- Reopen marker and detect changed/truncated contents.
- Four isolated filesystem tests for reopened marker, no-replace duplicates, corruption and zero sequence.
- No network connection required.

## Crucial limits

This is a **candidate marker**, not an authenticated or authorized ACTIVE pointer. The caller may fabricate a manifest digest, so a valid marker does not establish trust. A malicious writer with access to the directory may race paths or forge the marker. Parent directory open/sync and hardlink semantics depend on operating system and filesystem; unsupported platforms must fail closed. Hardlink publication may succeed before an I/O failure is reported, so the caller must inspect disk state after ambiguous errors.

There is no reviewed exclusive descriptor-based path handling, trusted keyring, signed manifest, immutable anti-rollback high-water mark, true power-off test, encrypted personal store or 56-day offline acceptance.

## Next valid gate

- Bind marker emission to independently authenticated signed manifests and actual content durability evidence.
- Harden filesystem identity, ownership, symlink and concurrent-write protections.
- Perform real process-kill, power-loss, full-disk, cross-platform and removable-media tests.
- Enable private data only after encryption and key custody review.

**Decision:** engineering and CI only. No merge, production or private content.
