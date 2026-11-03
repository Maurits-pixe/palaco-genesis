# ORCH-035 — Offline Content Integrity (SHA-256)

**Status:** DRAFT candidate stacked on ORCH-034 PR #201.

## Delivered

A bounded offline chunk-integrity primitive using the existing workspace `sha2` dependency. It verifies both the expected size and SHA-256 digest against in-memory bytes, with an upper bound of 16 MiB per call. No network access is required.

Six tests cover intact data, equal-length corruption, truncation, empty input, oversized declarations, and the critical false-security scenario: a malicious actor can supply both corrupted bytes and a matching digest.

## Security boundary

- SHA-256 is **not encryption**, identity verification, signature validation or provenance.
- A digest comparison is meaningful only when the expected digest arrived through an authenticated manifest and trusted custody path.
- This verifier does **not** read files, prevent symlink races, persist to disk, fsync, atomically promote a generation, or isolate actors.
- A 16 MiB limit is per call. No total pack quota, stream verification or archive decompression guard is implemented in this slice.
- The caller must never treat `Ok(())` as authorization or readiness to use personal data.
- Do not store personal file names or content in the plaintext metadata registry (ORCH-033).

## Next acceptance gate

Implement an authenticated manifest chain and incremental streaming verifier, then filesystem staging and cold-start recovery. Bind successful content verification to a durable receipt and ORCH-034 promotion only after actual durable storage has been checked. Test interrupted writes, tampered manifests, hash mismatch, huge file input, path traversal, backup rollback, low space and device restart.

**GO for reviewable integrity primitive. HOLD for real personal storage, merge, production and offline readiness claims.**
