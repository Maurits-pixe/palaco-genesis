# WNRA-06D — restricted-SID executable-image access comparison

**DRAFT TEST CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.**

Parent: WNRA-06C DRAFT PR #331 at exact SHA `a5b693c1ec6a2cf2548b5f5c8d20e24e75a19d97`.

## Motivation

WNRA-06B/06C demonstrated `STATUS_ACCESS_DENIED (0xC0000022)` after resuming both Python workers under a Low-integrity restricted token with either the current-user SID or `BUILTIN\\Users`. Neither variant yielded a running worker. The precise denied resource was not identified, and must not be invented.

## New experiment

The native Windows fixture `test_windows_anchor_restricted_sid_image_probe.py` adds two scenarios on top of the unchanged token restriction and Job Object fixture:

- `image_kind=windows_cmd, variant=user`
- `image_kind=windows_cmd, variant=builtin_users`

The same SID policy, `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`, Low integrity RID 4096, `CreateProcessAsUserW(CREATE_SUSPENDED)`, Job Object assignment, live child token checks, `ResumeThread`, bounded liveness observation, and kill-on-close remain. The alternate image is the operating-system `System32\\cmd.exe` with a bounded `ping -n 30 127.0.0.1 >NUL` command, contrasted against the earlier Python `import time;time.sleep(30)` worker. No external network connection is required; ping uses loopback only.

The diagnostic output classifies `create_blocked`, `runtime_blocked` (nonzero early exit), or `worker_live_then_job_terminated`. A **CI PASS** means the bounded experiment worked; only the third outcome proves that the named worker remained live. Even if cmd works and Python does not, that contrast does **not** identify a specific DLL, filesystem ACE or denied loader resource. `STATUS_ACCESS_DENIED` is a process exit code, not proof of the underlying file path.

## Remaining investigation

A verified path-level cause would need appropriately scoped, read-only Windows audit tracing (e.g. selected object-access audit events or a trusted process-monitor trace with permission), explicit file/DLL path evidence and independent code review. This PR does not install tracing drivers, enable global audit policy, modify ACLs, grant new privileges, or change production authorization. The comparison broadens diagnostic evidence only.

**TRIAS:** HOLD / DENY. **ORACLE:** exact commit + native Windows job + per-image result. **MENTOR:** if both images fail, do not weaken restricted SID policy without a trace showing the actual denial. No merge, release, activation or enrollment.
