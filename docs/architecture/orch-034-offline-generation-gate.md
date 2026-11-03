# ORCH-034 — Offline Generation Gate

**Status:** DRAFT, stacked on ORCH-033 PR #200, which depends on ORCH-032 PR #199.

## Intended safety behavior

Vacation Mode must never silently replace a previously verified content generation with an unverified or interrupted update. This initial slice implements the **pure Rust selection state machine**, not the durable storage engine.

- Stage a proposed generation without changing the active generation.
- Match the complete generation identity before allowing promotion.
- Abort staging and preserve the last active generation.
- Reject duplicate and rollback sequence numbers within the same in-memory state.
- Reject overlapping stages and zero-sized generations.
- No network, permissions, authority issuance or automatic synchronization.

## Crucial evidence boundary

`confirm_verified` consumes a caller-supplied identifier. It **does not perform a hash check**, verify a signature, flush to disk or validate power-loss durability. An untrusted caller can lie about verification. It must not be connected to a real READY label or a privileged runtime until a reviewed durability/integrity adapter is implemented.

In-memory sequence history disappears on restart. Anti-rollback across reboot requires authenticated durable high-water marks plus recovery tests; it is **not provided here**.

## Remaining build work

1. Implement content-addressed manifest with actual cryptographic hash verification.
2. Secure file handling: private staging directory, bounded writes, filesystem sync and atomic rename or platform-specific equivalent.
3. Reopen and validate on cold boot; recover from incomplete journal without promoting unverified data.
4. Preserve generation history against rollback and compromised snapshots.
5. Integrate approved local encryption before any personal data.
6. Run kill-power/full-disk/reboot/56-day airplane-mode acceptance.

**GO:** candidate engineering and CI tests. **HOLD:** persistent storage, personal information, merge, deployment and authority.
