# WNRA-06R — bounded early primary-thread and process signal timeline

**DRAFT TEST ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent WNRA-06Q DRAFT PR #345: `d039d46b9738c0c019198f3e0b8274e5330dfad5`.

## Motivation

WNRA-06Q established twelve real worker outcomes for Python and `cmd.exe`, verifying the suspended child process, its actual token, the Job Object boundary and both process and primary-thread exit status. In seven of eight restricted-SID cases the thread and process reported `STATUS_ACCESS_DENIED`; in one, the process was signaled while the thread observation still reported `STILL_ACTIVE`. A single pair of post-exit observations cannot identify whether the thread became signaled before or after the process signal.

## Test-only extension

`verification/provenance/test_windows_anchor_early_thread_process_timeline.py` adds an opt-in `timeline_probe` to the existing WNRA-06N marker fixture. It compares the real child process and primary-thread handles using `WaitForSingleObject(..., 0)` for **at most twelve iterations** immediately after `ResumeThread`. Each pair is timestamped using controller-relative `time.perf_counter()`, and `WaitForSingleObject(process, 5)` avoids tight unbounded polling. The sequence stops early when both handles are signaled. Existing three-second bounded final process waits and Job Object cleanup remain active.

The test launches the same Python and Windows cmd images under `low_only`, `user` and `builtin_users` token policies with marker codes 37 and 53 — 12 process launches total. The low-only positive control must reach both marker values for both images. A process creation refusal is reported by the original fixture without invented signal observations.

Outputs: one `WNRA06R_TIMELINE` line per **created** worker (12 expected on the baseline Windows runner), carrying sample count, first **observed** process/thread signal milliseconds, final process outcome/exit, `event_order_proven=false`, `loader_denial_traced=false`, `root_cause=UNKNOWN` and `authorization=DENY`. Two `WNRA06R_SUMMARY` lines give comparisons across policies.

## Interpretation and security boundaries

Polling two different handles in sequence is **not an atomic observation**, and first observation timestamps are **upper bounds** on detection, not actual thread/process exit timestamps. If the first loop finds both signaled, their chronological order is unknown. Even a thread signal before the process signal does not establish an access-denied loader call, denied object, ACE, missing DLL, or Windows exception stack. A nonmatching marker means user code was not demonstrated, not that a specific initialization API failed.

No ACL, audit policy, kernel tracing driver, privilege grant, global handle inheritance, external network access or production authorization changes. No merge, signing, release, issuance or activation.

**TRIAS:** GO-13 HOLD / DENY. **ORACLE:** exact SHA/run/job and marker lines. **MENTOR:** only process-specific access-failure telemetry, independently reviewed, can support a root-cause claim.
