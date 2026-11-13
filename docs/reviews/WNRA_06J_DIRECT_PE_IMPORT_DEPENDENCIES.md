# WNRA-06J — direct PE import dependency access, test-only

**DRAFT / GO-13 HOLD / AUTHORIZATION DENY.**

Stacked above WNRA-06I PR #337, exact base `3c46e40695fe1a9529ca2450dea6e20b54db802e`.

## New code

`verification/provenance/test_windows_anchor_direct_pe_import_access.py` parses on-disk **direct** import tables of the Windows runner's `python.exe` and `System32\\cmd.exe` via bounded standard-library PE parsing. Parsing validates DOS/PE signatures, optional-header bounds, section sizes, RVA backing and NUL-terminated ASCII DLL names. Neither the imported DLLs nor the target executable is executed for discovery. At most twelve existing DLL files per image are sampled, selected from the executable's immediate directory or System32. Unresolved import names are counted, not invented or silently declared safe.

For each sample, the fixture performs actual read-only `CreateFileW(FILE_GENERIC_READ)` and `CreateFileW(FILE_GENERIC_EXECUTE)` opens under the two earlier Low-integrity restricted-SID variants (`user` and `builtin_users`). Temporary impersonation is reverted immediately. It logs `WNRA06J_IMPORT` for each image and `WNRA06J_DEPENDENCY` for each sampled import/variant, with actual error codes and `cause_attributed=false`.

The corresponding Windows workflow triggers on changes and executes the test. The existing WNRA-06I positive worker-control and blocked restricted-SID worker comparisons remain required.

## Strict limits

The PE import directory provides only **static direct imports**. This code does not resolve API-set schemas, the process's effective DLL search order, side-by-side activation, known DLLs, dynamically loaded modules, delay-load imports, forwarded exports or section-image mappings. The selected path is a test candidate and **not** proof Windows chose that file when loading the worker. A successful `CreateFileW` open does not demonstrate successful `SEC_IMAGE` mapping. A denial in the fixture does **not** establish the original worker's `0xC0000022` cause. Root cause remains UNKNOWN without process-specific tracing.

No writes, ACL changes, audit policy changes, driver installs, production process execution, merges, release, issuance or authorization.

**TRIAS:** HOLD / DENY. **ORACLE:** bind native Windows results to exact commit/run/job; preserve failures. **MENTOR:** compare concrete static dependency candidates to independent process-specific loader telemetry before proposing any ACL change.
