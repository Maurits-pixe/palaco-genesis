# ORCH-054 — Create-only checkpoint persistence

DERIVED implementation proposal on ORCH-053. Public fixtures only; no authority or trusted storage claim.

Contract: persist an explicit nonzero revision using create_new, write the 88-byte PLANCH01 frame, sync the file and directory. Frame layout: 8-byte magic, big-endian u64 revision and epoch, 32-byte registry digest, 32-byte ORCH-052 commitment. No replacement, cleanup, retry or implicit latest selection. Any error may leave a file. Partial writes block reuse and are retained for inspection.

Read validates regular-file type, exact bounded size, magic, requested revision and commitment. It returns RevocationCheckpoint, never ExternalAnchor. Six tests cover reopen, no-overwrite, partial write preservation, corruption/revision/size rejection, old-state comparison with separately supplied evidence, concurrent creation and Unix symlink rejection.

Trust boundary: caller must exclusively control directory and ancestors; metadata/open TOCTOU against a hostile writer is unresolved. Local snapshots and hashes cannot establish authenticated provenance or monotonicity. Restoring an entire directory can restore old checkpoints. OS sync success and simulated partial files do not prove real crash or power-loss durability. No registry reconstruction, authenticated anchor backend, replay ledger, automatic recovery, network, or execution activation.

AI-review through three lenses: TRIAS — grants and gates unchanged; ORACLE — local file integrity cannot prove trusted freshness, and crash tests are simulated; MENTOR — bounded explicit revision API preserves failed-write evidence and reuses existing checkpoint verification. Dissent: production anti-rollback remains HOLD despite successful fixture tests.

Next transition: specify an independently authenticated monotonic anchor backend and test process termination/restart with that backend. Human independent review and existing GO-13 gate remain required before merge or activation. Implementation checks are recorded against the exact PR head in the PR description.
