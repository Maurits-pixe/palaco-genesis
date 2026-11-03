# ORCH-044 — Offline Candidate Publication Hardening Tests

**Status:** DRAFT; stacked on ORCH-043 PR #210.

## Added negative tests

1. An interrupted `marker_<sequence>.pending` name blocks another create-new publication; content is not overwritten and no final marker is silently created.
2. Eight concurrent attempts for one generation must produce exactly one successful publisher; remaining calls must fail with `AlreadyExists`; the final marker remains readable.
3. On Unix, a symlinked root directory is rejected.

These are filesystem simulation tests, **not real power-loss tests**. No background deletion or repair of orphaned pending files is implemented.

## Security dissent

The current path-based checks are not safe against a malicious actor mutating the directory between checks. Real deployment needs descriptor-relative operations and verified exclusive directory ownership. A leftover pending file causes denial until manual recovery; there is no automated recovery strategy. Hard links and directory fsync may be unsupported on some platforms. The marker remains untrusted and cannot activate a personal generation.

## Next steps

- Run CI at the exact head.
- Review the concurrent test for deterministic outcomes.
- Add a reviewed recovery procedure for orphan files without ever silently deleting user content.
- Test real process interruption and power loss on target OS/storage.
- Finish authentic signature verification, encryption and key custody before personal data.

**GO** for tests and review. **HOLD** for merge and production.
