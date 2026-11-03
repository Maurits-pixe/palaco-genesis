# ORCH-045 — Read-only Orphan Marker Inspection

**Status:** DRAFT, stacked on ORCH-044 PR #211.

## Scope

Read-only inspection of one potentially abandoned public/synthetic generation marker. Three states are exposed:

- `NoPending`: pending name absent.
- `PendingOnly`: pending bytes exist without a published marker.
- `PendingAndPublished`: both names exist.

The result includes a bounded pending size and SHA-256 digest for operator review. No files are changed or removed. An unsupported, oversized, symlinked or unsafe object rejects.

Five tests cover absent pending file, abandoned pending data preservation, hard-linked published marker, oversized file and Unix symlink denial.

## Recovery policy

A detected pending file is not proof of corruption or permission to delete. `PendingAndPublished` does not imply successful original sync, signature validation, current authorization or known-good content. Actual recovery must re-open and verify original authenticated content and durable generation evidence before an authorized human or reviewed policy can move/quarantine any file.

No automatic cleanup, private data, cache promotion or force retry is allowed. The directory path is assumed exclusive and may be vulnerable to hostile TOCTOU races until descriptor-relative I/O is implemented.

## Next steps

1. Human-reviewable quarantine intent/receipt contract (no silent deletion).
2. Separate actual power-kill/full-disk/removable-media and platform tests.
3. Secure signer and key custody plus encrypted private vault.
4. Integration into an offline cockpit only after evidence gates.

**GO:** isolated review/testing. **HOLD:** merge, production, personal storage and unattended cleanup.
