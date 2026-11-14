# WNRA-06N — dual Python user-code exit markers

**DRAFT TEST ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent: WNRA-06M DRAFT PR #341 at SHA `aae0f36968a84ea262820f4752a9d8ff41de8ad0`.

## Experiment

WNRA-06M observed two restricted SID workers terminating within the first millisecond of its sampling window with `STATUS_ACCESS_DENIED (0xC0000022)`, while the Low Integrity nonrestricting-SID control remained live. Those observations did not distinguish Windows process initialization, interpreter initialization and user script execution.

The new native Windows test `verification/provenance/test_windows_anchor_python_entry_markers.py` launches **the identical Python image** under three Low integrity token policies (`low_only`, `user`, `builtin_users`). For each policy, it runs two separate small Python commands that immediately call `os._exit(37)` or `os._exit(53)`. A matching exit code is evidence that the corresponding Python `-c` user code was reached; the two distinct markers reduce ambiguity from coincidental exit codes. If a worker instead exits with `0xC0000022` or another nonmarker code, it never **demonstrated** user-code execution; that does **not** prove the exact failing loader object, DLL, or Windows function.

Each launch verifies `CreateProcessAsUserW(CREATE_SUSPENDED|CREATE_NO_WINDOW)`, no inherited handles, true child PID and image path, actual primary token Low Integrity and restricted flag, Job Object membership before resume and bounded 3-second waiting. The nonrestricted Low Integrity **positive control must produce both exit markers**, or CI fails. Restricted outcomes are preserved as `create_blocked`, `no_marker_exit`, `user_code_marker`, or `timeout_no_marker`. Job close and fallback process termination are mandatory even when assertions fail.

The six `WNRA06N_ENTRY` markers, and one `WNRA06N_SUMMARY` distinguish the three token policies. No additional files, pipes, network operations, global policy changes or ACL updates are used; the only child code is `import os; os._exit(N)`.

## Evidence boundaries

A nonmatching exit proves only that the controlled exit marker was not observed. It can be caused by Windows loader initialization, Python startup, environment or process policy; it is **not** evidence of a specific denied object. A matching marker proves the user script got far enough to execute `os._exit` and does not establish that other workloads or a production security boundary are valid. The earlier WNRA-06M Toolhelp module snapshots remain separate evidence.

**TRIAS:** HOLD / DENY. **ORACLE:** exact commit, run/job and marker lines. **MENTOR:** if restricted workers do not reach either marker, the follow-up is independently reviewed, process-specific loader-error telemetry, not relaxing token restrictions. No merge, production admission, release, signing, enrollment or authorization.
