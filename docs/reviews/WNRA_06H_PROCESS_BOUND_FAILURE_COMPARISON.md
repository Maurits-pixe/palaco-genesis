# WNRA-06H — process-bound runtime failure comparison

**DRAFT TEST-ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent: WNRA-06G DRAFT PR #335, exact base `6e0ed9234e017363c6c630b70192cbf6c142daf5`.

## What changed

A native Windows test `verification/provenance/test_windows_anchor_process_bound_failure.py` starts the **same Python executable and 30-second sleep command** under three separate Low integrity (RID 4096) token policies:

1. `low_only` — `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`, **no restricting SID**, positive baseline.
2. `user` — same token reduction plus the current-user restricting SID.
3. `builtin_users` — same token reduction plus BUILTIN\\Users restricting SID.

All three use `CreateProcessAsUserW(CREATE_SUSPENDED|CREATE_NO_WINDOW)`, `bInheritHandles=False`, Job Object assignment before `ResumeThread`, verified `IsProcessInJob`, PID equality via `GetProcessId`, image path identity via `QueryFullProcessImageNameW`, and real **child primary token** observation (`TokenIntegrityLevel`, `IsTokenRestricted`, bounded enabled privileges).

Outcomes are kept separate:
- `create_blocked` means no process/thread was created; error must be a recognized Win32 denial; no resume.
- `runtime_blocked` means a created, verified worker exited nonzero after resume; its actual `GetExitCodeProcess` value is logged.
- `worker_live` means the verified process was still running at 0.5 s; closing the Job Object then terminated it. This is **required** for the `low_only` control; restricted-SID policy outcomes are observed, not presumed.

The expected evidence is three `WNRA06H_PROCESS` lines and one `WNRA06H_COMPARISON` line, with `same_image=true`, `same_low_integrity=true` and `cause_attributed=false`. If process creation is denied under a restricted-SID policy, it emits `process_bound=false` rather than claiming a verified child image.

## Limits

Process identity and exit status are stronger evidence about **which process actually failed**, but they do **not** reveal its loader's attempted file paths, DACL/mandatory integrity checks, per-file stack traces or an exact failed DLL. An observed `STATUS_ACCESS_DENIED` is a process exit code, not an independently captured access-denied event. This test is a controlled comparison of token policies, not a root-cause attribution or production sandbox.

No ACL, registry, account, audit policy, driver, network policy, SACL, production launcher or authorization modifications. All token, process, thread and Job Object handles are closed in `finally`; no long-lived process is permitted.

## Evidence gate

Native Windows exact-head CI must demonstrate the three variant outcomes, positive live control, image/PID/token checks for created workers, and earlier WNRA-06F/G regression PASS. Failed attempts remain in the GitHub run history. No merge, signing, release, issuance, enrollment, activation or GO-13 transition.

**TRIAS:** HOLD and DENY. **ORACLE:** exact commit/run/job bound. **MENTOR:** loader object attribution requires trusted process-specific trace evidence and a separate policy review before any permission change.
