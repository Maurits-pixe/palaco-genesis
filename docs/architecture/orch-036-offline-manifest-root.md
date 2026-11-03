# ORCH-036 — Canonical Offline Manifest Root

**Status:** DRAFT, stacked on ORCH-035 PR #202 and predecessors.

## Implemented now

- Domain-separated, deterministic SHA-256 root over an ordered list of non-private chunk identifiers, byte sizes and chunk SHA-256 values.
- Stable binary encoding with explicit lengths and fixed-size fields.
- Strict increasing identifier order, no duplicates, no path-like identifiers, bounded 4,096 entries and checked size arithmetic.
- Seven regression tests, including forged-root counterexample.
- No network requirement.

This is an **integrity primitive**, not an authenticated signed manifest. An attacker who can modify both the manifest and root can create a valid-looking forged root. Never present this result as verified provenance or a trusted offline-ready receipt.

## Critical missing implementation

1. Trusted signature and source-key policy with key rotation, revocation and offline expiry handling.
2. Bind the signed manifest to the actual ORCH-035 verified chunks and ORCH-034 generation state.
3. Durable private staging directory, safe path handling, fsync + atomic promotion and journal recovery.
4. Real cold-restart / disk-full / power-kill / removable-media tests.
5. Encrypted vault with reviewed key lifecycle before any private or sensitive metadata.
6. Weeks-long airplane-mode acceptance and controlled reconnection.

**Status:** IMPLEMENTED primitive / CI pending / unauthorized production use HOLD. No merge.
