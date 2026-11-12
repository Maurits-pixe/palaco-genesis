# WNRA-06F — actual Windows object-open evidence under restricted SID impersonation

**DRAFT TEST-ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent: WNRA-06E DRAFT PR #333, exact base SHA `8390069e7f1b6c1bf81d21a4818c3ebba8f0f6ea`.

## Evidence gap

WNRA-06E's `AccessCheck` outcomes for four known Windows image files were derived from file DACLs and did **not** exercise actual file opens. The existing restricted-SID worker failed at runtime with `STATUS_ACCESS_DENIED (0xC0000022)` in four combinations, with no proven path-level origin. A static DACL prediction and an actual object-open result can differ due to additional access checks, token policies, or filesystem behavior.

## New test

The file `verification/provenance/test_windows_anchor_restricted_sid_object_open.py` creates the same two Low-integrity restricted SID tokens (`user` and `builtin_users`), duplicates each as a security-impersonation token, and calls `ImpersonateLoggedOnUser` around **only one** read-only `CreateFileW` operation. The impersonation is always reverted via `RevertToSelf` in `finally` before any logging, Python file operations, other test assertions, or handle cleanup.

Files tested: Python executable, Windows `cmd.exe`, `ntdll.dll`, and `kernel32.dll`. For each file and variant, test `FILE_GENERIC_READ` and `FILE_GENERIC_EXECUTE` using `OPEN_EXISTING` and sharing with all file access modes. No write/disposition/creation rights are requested. Each access is compared with the prior `AccessCheck` result and logged as:

`WNRA06F_OBJECT variant=... image=... operation=read|execute dacl_allow=... opened=... winerror=... actual_open=true authorization=DENY`

The test does not hard-code which files must open: an unsuccessful actual open with a nonzero Windows error is valid diagnostic evidence, not a test failure. An invalid test setup, failed Windows token impersonation, failed reversion, a missing file, or an inconsistent API result fails CI.

## Interpretive limits

This is an **actual named-file open** in the context of a temporarily impersonated restricted token, but it is **not a process loader trace** or proof of which file the child process attempted to access before it returned `0xC0000022`. It does not inspect the full transitive DLL dependency graph, per-directory access, mapped-section creation, the process token's other resources, or system audit events. A success opening one file does not prove that the image can be loaded or executed; a denial on a named file is only candidate evidence. Any discrepancy between `AccessCheck` and `CreateFileW` requires independent investigation.

No ACL or audit policy changes, drivers, external network calls, process elevation, account changes, signing, release, enrollment, production issuance or authority transition.

## Required exact-head evidence

Native Windows workflow must show 16 `WNRA06F_OBJECT` rows (2 SID variants × 4 files × 2 operations), including actual open outcomes and Win32 errors, plus the prior WNRA-06D/E cases. **CI PASS** means the evidence collection passed; successful execution of the restricted-SID worker remains **BLOCKED** until a live worker is actually demonstrated.

**TRIAS:** HOLD / DENY. **ORACLE:** commit/run/job scoped. **MENTOR:** resource-level fault attribution needs independently reviewed loader/audit tracing before any security policy changes.
