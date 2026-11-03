# ORCH-039 — Offline Public Chunk Staging

**Status:** DRAFT; stacked on ORCH-038 PR #205.

## Implemented scope

- Actual filesystem write of a **public/synthetic** bounded chunk after SHA-256 and length verification.
- `create_new` prevents accidental replacement of an already existing pending file at open time.
- `write_all` and file `sync_all` request persistence of pending file data.
- Re-read pending file, enforce bounded size and verify SHA-256 again.
- Reject unsafe IDs, symlinked root paths, symlinked file targets during re-read, mismatched payloads and duplicates.
- Five tests using isolated temporary directories, including post-write corruption.

## Critical limitations

This is staging, **NOT durable content promotion**. Parent directory fsync, atomic generation commit, crash journal, snapshot rollback, verified cold-boot recovery and platform-specific storage guarantees remain unimplemented. Between metadata checks and open calls, adversarial filesystem mutation may race (TOCTOU); the caller must provide an exclusive trusted directory and no hostile concurrent writers. The staging root is supplied by the caller and no permissions are established here.

No private data, sensitive filenames or personal metadata may be staged. No encryption, authenticated manifest, trusted publisher signature, production key custody, removable-drive handling, concurrent-file lock or network synchronization is included. The API intentionally has no READY or execute transition.

## Required next actions

1. Review and harden directory ownership, platform-specific open flags / descriptor-relative I/O and cross-platform fsync behavior.
2. Implement crash-safe generation activation backed by journal and directory fsync, then test kill/power loss and disk full.
3. Integrate signature verification, durable high-water marks and encryption before any personal data.
4. Run actual offline on-device acceptance for 56 days target.

**Decision: code candidate for isolated public fixtures only. Merge, production, private storage and READY HOLD.**
