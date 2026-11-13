# WNRA-06K — API-set import classification and loaded-module evidence

**DRAFT / GO-13 HOLD / AUTHORIZATION DENY.**

Parent WNRA-06J PR #338, exact base commit `4494441f5582b864a4d965b02793733f94814c9d`.

## What is measured

WNRA-06J parsed PE direct imports from the GitHub Windows runner's Python executable and `System32\\cmd.exe`. Many cmd imports are API-set contracts and cannot be resolved by assuming a file of the same name is present in System32. The new Windows-only `test_windows_anchor_api_set_module_view.py` explicitly classifies direct import names beginning with `api-ms-win-` or `ext-ms-win-` as **API-set contracts**, separate from ordinary named DLL imports.

For each direct import, `GetModuleHandleW` is used to query whether the name is **already loaded in the trusted test controller process**. When a borrowed module handle exists, `GetModuleFileNameW` records its real on-disk path; no `LoadLibrary` call is made. A bounded sample (max twelve distinct already loaded paths) is checked with actual read and execute `CreateFileW` operations under the previous two low-integrity restricted-SID tokens, using the existing scoped impersonation fixture.

## Evidence and gates

- `WNRA06K_IMPORT image=python|cmd` counts imports, API-set contract names, ordinary DLL names and controller loaded matches.
- `WNRA06K_CONTRACT` shows up to six contract names per image with `resolution=UNVERIFIED` rather than inventing a host DLL.
- `WNRA06K_MODULE` reports real independent object-open outcomes for selected controller-loaded module paths, including relevant Win32 errors.
- At least one direct-import name must be found loaded in the controller; API failures or invalid paths fail CI.
- Existing WNRA-06I/J regressions remain required on the exact commit.

## Critical interpretation limits

The controller's `GetModuleHandleW` lookup is **not** a Windows loader trace of the failing restricted worker. It cannot resolve all API-set contracts or prove a module was used in the other process. Absence of a matching module handle does not prove the DLL is absent from Windows, and a matching module name can be loaded via different paths in another process. The direct import table omits dynamically loaded and delay-load dependencies. The sample's `CreateFileW` check does not prove successful DLL section mapping, and **no exact cause of the earlier `0xC0000022` worker exit is attributed**.

No ACL modification, audit-policy changes, new module loads, tracing drivers, external network calls, production authorization, release or issuance. All token handles are closed and impersonation is immediately reverted.

**TRIAS:** HOLD / DENY. **ORACLE:** exact commit/run/job required. **MENTOR:** genuine worker-loader provenance requires independently reviewed, process-specific event evidence before any access-policy changes.
