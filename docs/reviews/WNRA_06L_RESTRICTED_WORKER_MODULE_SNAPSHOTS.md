# WNRA-06L — restricted-worker process-specific module snapshots

**DRAFT TEST-ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Stacked on WNRA-06K PR #339, exact base `d82cec0dae8d7a76ecd29fd36851c35e36ac4c97`.

## Direct evidence added

WNRA-06K's imported DLLs and already loaded modules originated in the **trusted test controller**, not the failing restricted worker. WNRA-06L adds `verification/provenance/test_windows_anchor_process_module_snapshot.py` to inspect the actual worker process by PID. Three separately launched workers run the **same** Python executable and sleep command under Low Integrity RID 4096:

- `low_only`: reduced privileges without restricting SID — positive live execution control.
- `user`: restricted current-user SID.
- `builtin_users`: restricted BUILTIN\\Users SID.

The native Windows fixture uses the prior suspended `CreateProcessAsUserW` and kill-on-close Job Object custody. Before resuming, it verifies PID via `GetProcessId`, actual image via `QueryFullProcessImageNameW`, the child's real primary token and Job membership. It calls `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, pid)` and enumerates `Module32FirstW`/`Module32NextW` with a hard cap of 1024 modules, immediately before and approximately 400 ms after resumption.

Distinct snapshot states are `observed` (positive module count) and `unavailable` (recognized Windows errors such as ERROR_PARTIAL_COPY, ERROR_BAD_LENGTH or ERROR_INVALID_PARAMETER). Unrecognized errors fail the test; module enumeration does not invent paths when unavailable. Positive `low_only` control must remain alive with a readable, nonempty post-resume module snapshot. Restricted workers can be `create_blocked`, `runtime_blocked` (nonzero exit code), or `worker_live` with actual child attributes verified. All created workers are Job-terminated before cleanup.

Outputs: three `WNRA06L_WORKER` lines and one `WNRA06L_SUMMARY`. Each successful process-creation marker includes snapshot availability, module counts, Win32 snapshot errors, exact exit code, `loader_denial_traced=false`, `cause_attributed=false` and `authorization=DENY`.

## Critical evidence boundary

Toolhelp is a **point-in-time module list**, not an event stream of DLL load attempts or a captured access denial. A failed worker may exit before the after-snapshot can be collected; an unavailable snapshot does not prove no module was mapped. A successful module snapshot cannot identify an earlier `STATUS_ACCESS_DENIED` operation. It neither identifies the denied object/ACE nor verifies a complete sandbox. The root cause remains UNKNOWN until independently observed process-specific access-failure telemetry supports attribution.

No ACL, SACL, audit policy, kernel driver, privilege escalation, production admission or release changes. No merge, activation, issuance or enrollment.

**TRIAS:** GO-13 HOLD / AUTHORIZATION DENY. **ORACLE:** exact commit + native Windows run + job logs required. **MENTOR:** preserve competing hypotheses and avoid weakened access policy without causal evidence.
