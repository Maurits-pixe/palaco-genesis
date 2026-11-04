# ORCH-055 — Checkpoint process termination and restart

DERIVED implementation/test proposal on ORCH-054. Test-only barriers pause the actual persistence path after create, after 24 bytes, and after successful file/directory sync. The parent starts an isolated child test executable, waits for a bounded barrier, force-kills and waits for the writer, then starts a separate reader process. Guard cleanup kills/reaps child processes on errors. No new dependencies, network, production failpoints or execution grants.

Acceptance: zero/24-byte files are denied after process restart, retained verbatim and cannot be overwritten; a synced 88-byte checkpoint reopens in a fresh process with exact fields. Missing external anchor remains MissingAnchor; independently supplied newer fixture anchor detects rollback. The fixture anchor is not an authenticated backend. Existing tests continue to cover corruption, revision mismatch, symlinks and concurrency.

The write is now split after the fixed 24-byte header so the test can stop at a real intermediate write boundary. Errors still preserve the incomplete file. Barriers and child helpers compile only with cfg(test).

Evidence limits: child.kill tests process termination on the CI OS/filesystem, not power loss, kernel crash, device cache behavior or hostile writers. The ready file is test coordination only. No anchor provisioning, authenticated monotonic backend, key revocation persistence or full offline runtime activation is implemented.

AI-review through three lenses: TRIAS — runtime authority unchanged and test failpoints absent from production; ORACLE — true process termination/reopen evidence replaces simulated interruption at three named boundaries, with power loss still unverified; MENTOR — bounded waits and child cleanup prevent abandoned helper processes. Dissent: trusted-anchor provenance remains missing, so production anti-rollback and activation stay HOLD.

Next engineering transition: specify and implement separately provisioned authenticated anchor evidence with identity binding, freshness/rollback policy and restart tests. Existing independent human review and GO-13 gates still apply to merge/activation. Exact-head CI evidence belongs in the PR description.
