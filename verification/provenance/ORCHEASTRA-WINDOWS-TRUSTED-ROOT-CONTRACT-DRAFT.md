# ORCHEASTRA — Windows trusted-root and junction boundary (DRAFT)

Date: 2026-11-10 (Europe/Amsterdam). Base: PR #265 head `f7c51c2b8ff14bd5f05c619f8086a9515a61f609`.

## Evidence and unresolved vulnerability

The existing Windows `CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT)` candidate protects the *final* component and checks its opened handle. PR #265 validated a post-open pathname swap and closing of a rejected reparse handle on the Windows runner. It does **not** establish a trusted parent-directory boundary: ancestor junctions or symlinks may be traversed before the final handle opens. No trusted-root containment guarantee is implemented.

## Proposed contract (not implemented)

1. Accept a trusted-root capability only from an explicitly authorized caller. Neither process working directory nor repository name implies authority. Preserve the present trusted-input CLI behavior as a separate mode until call sites are reviewed.
2. Accept only a relative child path under that root; reject absolute paths, drive letters, UNC/device paths, empty and dot components, parent traversal, mixed-separator ambiguity, and unreviewed normalization. Never rely on string-prefix containment.
3. Open the trusted root as a directory handle. Traverse descendants using a **reviewed handle-relative, no-reparse mechanism** so pathnames cannot redirect through parent junctions. Sequential `GetFileAttributesW` then `CreateFileW` is check-then-use and is insufficient.
4. Evaluate native `NtCreateFile` with a `RootDirectory` handle and `OBJ_DONT_REPARSE` or a documented equivalent; verify supported Windows behavior and errors before relying on this proposal. This is a design option, not an asserted API guarantee.
5. Keep final regular-file validation, 20 MiB limit-plus-one reads, and file data bound to the same opened handle. Close root/intermediate/final handles exactly once on every exit. On denial, never produce partial SBOM/evidence.
6. Fail closed for any ancestor reparse point, unauthorized root, traversal escape, unsafe replacement, unsupported path syntax or unknown native result.

## Mandatory regression matrix

| Input or event | Required outcome |
| --- | --- |
| Normal relative file under authorized root | ACCEPT exact bytes |
| Absolute, drive, UNC/device, dot-dot, malformed path | DENY |
| Final symlink or junction | DENY |
| Parent junction to directory outside root | DENY; no external bytes |
| Parent symlink even when target inside root | DENY by default |
| Parent rename/swap during handle-relative traversal | DENY or remain bound inside root |
| Final path replaced after file opened | Original handle bytes only |
| Root missing/revoked/non-directory, pipe/device | DENY without hanging |
| 20 MiB / 20 MiB + 1 | ACCEPT / DENY |
| Open, inspect and read errors | Close handles once; no partial evidence |
| Linux/POSIX provenance suite | Existing behavior maintained |

Real Windows runner tests must exercise real junctions and report setup problems as FAIL, not silently skip mandatory cases. Deterministic interleaving tests are useful but do not constitute exhaustive race proof.

## Gates

Specification only. No native ancestor traversal implementation or root authority was added. No merge, signing, release or production authority. Upstream PRs #263, #264, #265 and their evidence remain unchanged. A separate implementation candidate plus native negative tests and security review is necessary. Any successful CI on this document checks repository compatibility only, not native trusted-root protection.

## Three-lens AI review (not independent)

- **TRIAS:** GO-13 HOLD, authorization DENY; no capability implies authority.
- **ORACLE:** Prior Windows CI confirms tested final-handle scenarios, not ancestor-junction containment. Trusted-root containment NOT VERIFIED.
- **MENTOR:** Select the real caller/root authority contract, then test and implement one handle-relative traversal slice. Maintain the fail-closed boundary.

Disposition: DRAFT SPECIFICATION / ROOT CONTAINMENT NOT IMPLEMENTED / HOLD.
