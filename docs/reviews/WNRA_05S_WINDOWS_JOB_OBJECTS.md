# WNRA-05S — native Windows Job Object enforcement candidate

**DRAFT / TEST-ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent: WNRA-05R PR #320 at `4318b6aeea9affa90c6020a849275a77c06a4e4a`.

`test_windows_anchor_job_objects.py` calls the native Windows Job Object API through Python `ctypes` for two isolated regression cases. First, it assigns a gated Python parent to a new Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, then lets the parent launch a long-lived child and verifies both process handles become signaled after closing the job. Second, it sets `JOB_OBJECT_LIMIT_PROCESS_MEMORY` to 96 MiB, queries the configured flags and value, and attempts an allocation of 160 MiB inside an assigned local test worker; the allocation must be rejected with `MemoryError`.

These are **Windows-only test fixtures**. The subprocess is created before assignment and held behind an explicit `GO` handshake, so the test's descendant is not created until assignment succeeds. This is not a generalized race-free secure process launcher, and it does not prevent untrusted code from running before assignment. A production implementation would require a separately reviewed suspended-process launcher and handle custody design, security token restrictions, processor policies, descendant escape prevention, and job-bound resource enforcement. CPU-rate quotas are **not** implemented or tested in this candidate. The memory rule is a per-process commit limit, not a measured RSS ceiling or whole-tree memory quota.

The native Windows regression workflow now watches and runs the Job Object test. Exact-head CI must verify `WNRA05S_JOB_TREE` and `WNRA05S_JOB_MEMORY` test logs, both tests `ok`, and existing WNRA-05Q/05R regressions. No `PASS` claim without that evidence. Tests and notes cannot grant authorization, anchor signing, issuance, production admission, release or merge.

**TRIAS:** GO-13 HOLD and AUTHORIZATION DENY. **ORACLE:** exact-head Windows evidence required. **MENTOR:** treat the result as a narrow feasibility test; any hardened process containment requires an independent architecture and threat-model review.

## Initial Windows CI counterexample and correction

The first head `9c2c4c5c779914786c22e5be82f6e68e5f9b83c2` failed the Job Object tree test on Windows run `43152430378`, job `130964539709`: both process handles were signaled, but the test incorrectly asserted a nonzero process exit code (observed 0). The separate 96 MiB memory-limit test passed. This is a test-oracle error, not evidence of a live descendant after job closure. The follow-up adds pre-close `WAIT_TIMEOUT` for the parent and retains post-close `WAIT_OBJECT_0` for parent and descendant; it removes the ungrounded exit-code requirement. The revised head requires a fresh native Windows run, and the first failure remains part of the evidence history.
