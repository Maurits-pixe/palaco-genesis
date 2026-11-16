# WNRA-06Q — observed primary-thread versus process exit codes

**DRAFT TEST ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Stacked on WNRA-06P PR #344, exact parent SHA `f8a0d0bbdd7550b76b577edbf7212089d90b9491`.

## Goal

Earlier WNRA-06N/O/P showed that under two restricting SID variants both Python and Windows cmd.exe fail to reach known exit markers, while the Low-integrity nonrestricting control executes both markers. WNRA-06Q adds an independently observed primary-thread exit state to the same verified process creation. This can sharpen the boundary between process-level termination and the primary thread's state, but does **not** identify a denied loader object.

The new native Windows test `verification/provenance/test_windows_anchor_thread_process_exit.py` runs **12 controlled marker attempts** (2 images × 3 token policies × 2 exit markers). It reuses the verified suspended-process fixture, checks actual PID/image/token and Job membership before resuming, and waits at most 3 seconds. An opt-in `thread_probe=True` records `WaitForSingleObject(hThread, 0)` and `GetExitCodeThread(hThread)` alongside `GetExitCodeProcess(hProcess)` while the original handles are still held. The existing fixture defaults to `thread_probe=False` so prior test behavior and logging remain unchanged.

For every created worker, the `WNRA06Q_EXIT` marker reports tested SID policy, image, expected marker, actual process exit, observed main thread status/exit, image/PID/token verification and `root_cause=UNKNOWN`. A created process with `timeout_no_marker` may report an active primary thread, not a result classified as a failure cause. The positive nonrestricting control for both images must still reach **both** markers; restricted policies are observed without presupposing a successful outcome. A creation failure under a restricted policy is reported by the earlier fixture as `create_blocked` and does not fabricate thread evidence.

## Security and evidence limits

A numeric primary thread exit status does not identify a Windows loader API call, failed DLL, kernel object, denied ACL, SACL event, exception stack or a process-specific security failure event. Even equal thread and process exit codes do not prove a particular loader operation. This is a strictly bounded diagnostic comparison, not a debugger/ETW provider, complete sandbox or production policy authorization.

All test workers remain in kill-on-close Job Objects; token handles and thread/process handles close in `finally`. No ACL, SACL, audit policy, driver installation, privilege grant, merge, release, enrollment, signing or activation.

**TRIAS:** GO-13 HOLD / DENY. **ORACLE:** exact SHA, native run/job and marker evidence required. **MENTOR:** only corroborated process-specific failed access events justify causal attribution or security-policy review.
