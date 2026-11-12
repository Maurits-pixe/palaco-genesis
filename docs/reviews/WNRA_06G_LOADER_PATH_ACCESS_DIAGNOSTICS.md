# WNRA-06G — restricted-SID path and supplementary loader-file diagnostics

**DRAFT TEST CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.**

Parent WNRA-06F PR #334 at exact commit `e0906f4a362926e1b21fdb0ad62dc001b5f638bf`.

## Observation gap

WNRA-06F demonstrated actual read-only `CreateFileW` access outcomes for Python, `cmd.exe`, `ntdll.dll` and `kernel32.dll` under user-only and BUILTIN\\Users restricting SIDs. User-SID restrictions denied the named files, while BUILTIN\\Users allowed all eight requested operations. The independently created worker under both policies still terminated with `0xC0000022`. This does not establish a specific failed loader path.

## WNRA-06G new probes

The new Windows-only `test_windows_anchor_restricted_sid_loader_path.py` reuses verified restricted-SID tokens, Low integrity RID 4096 and the read-only impersonation-scoped `CreateFileW` helper. It records **20** controlled operations:

- Three directories (`SystemRoot`, `System32`, Python executable parent), each with `FILE_READ_ATTRIBUTES` and `FILE_TRAVERSE`, opened using `FILE_FLAG_BACKUP_SEMANTICS`.
- Two supplementary Windows loader/runtime files (`System32\\kernelbase.dll` and `System32\\ucrtbase.dll`), each with `FILE_GENERIC_READ` and `FILE_GENERIC_EXECUTE`.
- All five resources are checked under both previous variants (`user`, `builtin_users`), yielding 2 × (3 × 2 + 2 × 2) = **20** `WNRA06G_PATH` evidence rows, with `opened`, Win32 error and `authorization=DENY`.

The previous helper now accepts an optional `CreateFileW` flags argument. Existing file-only tests retain their previous flags and outputs. All impersonations are reverted immediately, before controller assertions, Python I/O or handle cleanup. No file writes, ACL updates, system-wide audit changes, tracing driver installation, global token privilege adjustment or process authorization.

## Explicit limits on causal attribution

These operations are **direct test-controller file/directory opens** under impersonation; they are **not** captured opens issued by the restricted worker's actual Windows loader. Explicit `FILE_TRAVERSE` access on a directory also does not reproduce every part of Windows path traversal (notably `SeChangeNotifyPrivilege` behavior), and `FILE_GENERIC_EXECUTE` does not demonstrate successful DLL section mapping. `kernelbase.dll`/`ucrtbase.dll` are diagnostic samples, not a complete or proven loader dependency graph. A denied open is a candidate only. Even an allowed open cannot establish that a worker's previous `0xC0000022` came from another particular file.

Only an independently verified process-specific read-only trace, exact file/object identity and relevant access-mask evidence could support definitive loader-resource attribution.

## Exact-head native Windows evidence gate

The Windows workflow must show 20 `WNRA06G_PATH` records and successful new test execution, plus previous WNRA-06D/E/F regressions. CI PASS means this narrow probe ran; worker runtime remains **BLOCKED** until independently observed alive under a restricted-SID policy. Preserve any failed runs as counterexamples and correct on a new head.

**TRIAS:** GO-13 HOLD / AUTHORIZATION DENY. **ORACLE:** exact commit/run/job evidence. **MENTOR:** no ACL relaxation without verified causal proof and a separate policy review.

No merge, activation, deployment, release, issuance or enrollment.
