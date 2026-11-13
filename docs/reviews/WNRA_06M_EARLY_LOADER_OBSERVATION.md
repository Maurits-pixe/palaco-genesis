# WNRA-06M — bounded early worker module observation

**DRAFT / GO-13 HOLD / AUTHORIZATION DENY.**

Parent WNRA-06L PR #340 at `ab6357fe860d65c66dd007e60e052262dcce46b3`.

WNRA-06L recorded a nonempty Toolhelp module snapshot for the live low-integrity Python control (15 modules) and ERROR_PARTIAL_COPY (299) for both restricted-SID workers after an approximately 400 ms observation delay. This did **not** capture the exact moment of module load failure. WNRA-06M adds a bounded immediate observation cycle after resuming the actual child process (same Python executable, Low integrity RID 4096, Job Object custody) with at most **12 Toolhelp module snapshot attempts**, each followed by a **10 ms process wait**. Sampling begins immediately after `ResumeThread`, and ends upon observed process termination or exhausting the attempts; `time.perf_counter` records relative elapsed milliseconds.

For each policy (`low_only`, `user`, `builtin_users`), `WNRA06M_EARLY` records number of observations, successful module samples, first observed module timestamp, first observed exit timestamp if within sampling, maximum module count, distinct unavailable Toolhelp error codes, and eventual worker exit outcome. The test also emits a `WNRA06M_SUMMARY` that explicitly preserves `root_cause=UNKNOWN`. Reuse of WNRA-06L's parent function ensures verified process PID/image, primary token, suspended Job assignment, resume, and kill-on-close cleanup. The `low_only` control must remain alive and still have a later valid nonempty module snapshot. No process remains running after the test.

## Limits and safety

Toolhelp observations are discrete snapshots, not an ETW loader timeline or exact denied-object trace. Even an early ERROR_PARTIAL_COPY does not distinguish incomplete loader initialization from other process-state or access restrictions. The first observed exit is only an observation **upper bound**, not the time the underlying fault occurred. Module counts do not establish which DLL access was denied. All restricted-SID runtime results are reported as observed, not interpreted as successful execution merely because CI passes. No ACL/audit policy, driver, privilege escalation, production rights, release, merge, enrollment or issuance.

**TRIAS:** HOLD / DENY. **ORACLE:** exact commit, native Windows run/job and WNRA06M markers. **MENTOR:** future causal attribution requires verified process-specific failure events, not inferred from polling.
