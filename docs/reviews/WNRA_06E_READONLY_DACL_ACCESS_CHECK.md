# WNRA-06E — read-only Windows restricted-SID DACL access matrix

**DRAFT TEST-ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent WNRA-06D PR #332 at exact SHA `d14dd919c684c139edc1aec5191e9f94d348b72d`.

## Scope of new evidence

WNRA-06D observed `0xC0000022` for both Python and Windows cmd, with either current-user or BUILTIN\\Users restricting SID. This is a process exit code, not a traced file-level denial. The new `verification/provenance/test_windows_anchor_readonly_access_check.py` asks a **narrower question**: according to Windows `AccessCheck`, can the named restricted-token fixture obtain the read and execute DACL rights on selected known image files?

It creates a restricted token via `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` for each previously tested SID, applies Low integrity RID 4096, confirms `IsTokenRestricted` and `TokenRestrictedSids`, duplicates the token as a query-only **impersonation token** for `AccessCheck`, and reads the owner/group/DACL security descriptor using `GetNamedSecurityInfoW`. For each variant, it evaluates `FILE_GENERIC_READ` and `FILE_GENERIC_EXECUTE` on:
- The Python executable used by the test runner;
- Windows System32 `cmd.exe`;
- Windows System32 `ntdll.dll`;
- Windows System32 `kernel32.dll`.

It logs `WNRA06E_ACCESS variant=... image=... dacl_execute=... dacl_read=... accesscheck_only=true authorization=DENY`. The explicit test checks API success and expected token configuration; the **access decision is evidence data, not a fixed expected value**. No ACL is modified, and no SACL/audit policy or tracing driver is enabled. Any native Windows API failure is a test failure.

## Security interpretation

Windows `AccessCheck` over a file's security descriptor is an **offline DACL evaluation**. It is *not* the kernel's observed file-opening failure, a stack trace of the failed loader operation, full mandatory-integrity policy evaluation, or a reliable reconstruction of all image loader accesses. A `dacl_execute=false` or `dacl_read=false` result identifies a plausible **candidate** for a read/execute restriction, not proof that a specific process failed at that exact file path. The listed files are a deliberately small sample; transitively loaded DLLs and filesystem directories are outside this test. No inference of which ACL ACE is culpable without further independently verified tracing.

## Required evidence

The exact-head Windows regression must show both SID variants and all four named paths (eight `WNRA06E_ACCESS` rows), as well as passing WNRA-06B/C/D regressions. The outcome of WNRA-06D restricted-SID worker execution remains **BLOCKED** until a live worker is observed; CI PASS on AccessCheck alone does not reverse it.

**TRIAS:** HOLD / DENY. **ORACLE:** commit/run/job scoped, do not overstate evidence. **MENTOR:** request independent read-only object-access telemetry and policy review before making any ACL changes.

No merge, release, deployment, activation, signing, issuance, enrollment, or production admission.
