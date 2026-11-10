# ORCHEASTRA Windows native relative-open design — WNRO-001

**Status:** DRAFT, DESIGN ONLY, GO-13 HOLD, authorization DENY.  
**Baseline:** PR #270 at `b1e12ebf2280ed0f3b975f3f15c6678733c1e417`.  
**Scope:** controlled, disposable PALACO build/test root only. No consumer-provided root, production SBOM integration, signing or deployment.

## Evidence-backed operating system primitives

Microsoft documents that `NtCreateFile` accepts an `OBJECT_ATTRIBUTES.RootDirectory` directory handle and an `ObjectName` relative to that handle. Its `FILE_OPEN_REPARSE_POINT` option attempts to open a reparse point itself rather than resolving it in the normal manner. These statements do **not** prove that arbitrary multi-component names are contained, or that a directory handle was selected by an authorized caller.

- https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntcreatefile
- https://learn.microsoft.com/windows/win32/fileio/reparse-point-operations
- https://learn.microsoft.com/windows/win32/fileio/reparse-points-and-file-operations

## Proposed test-only capability boundary

1. The *trusted test harness* creates a fresh, isolated temporary build root and retains ownership. The harness never treats a caller's `--metadata` string, `Path.parent`, current working directory or environment variable as authority.
2. Open that exact test root as a directory handle. Record handle lifetime and file identity. Explicitly check that the final root object is a directory and not itself a reparse point. Its ancestors' trust still follows from the *controlled harness origin*; opening an arbitrary user-supplied path would not establish root authority.
3. Pass only a basename accepted by `validate_windows_metadata_basename`. Any separator, drive/UNC prefix, ADS or device syntax fails before native access. Never take a path and silently strip its parent.
4. In an isolated native adapter, use `NtCreateFile` with `OBJECT_ATTRIBUTES.RootDirectory = <held root handle>` and `ObjectName = <validated single component>`, `FILE_OPEN_REPARSE_POINT`, `FILE_NON_DIRECTORY_FILE`, read-only access, open-existing disposition, and documented share flags. Do not combine a user-controlled path with the root handle.
5. Validate returned-handle attributes and type. Reject reparse points, directories and devices; close every partially acquired handle on errors. Transfer ownership of an accepted OS handle exactly once to the reading layer; preserve the existing byte cap and SHA-256 binding to bytes actually read.
6. Keep the root handle open throughout the child open and read. Moving or renaming the root after handle acquisition must not expand the selected object, though this still requires a native regression test.
7. On missing `NtCreateFile`, an unexpected status, a handle-ownership mismatch or unsupported filesystem semantics, **fail closed**. No fallback to `CreateFileW(root_path + basename)`.
8. Hardlinks: a file hardlinked into the root can reference bytes whose other pathname is outside it. Handle-relative namespace containment alone is not an assurance of content provenance; test/build isolation and file production provenance remain separate controls.

## API sketch (NOT executable production code)

```text
BuildRootTestAuthority.create_disposable() -> owned_directory_handle
validate_windows_metadata_basename(name) -> single_component
native_open_relative(owned_directory_handle, single_component)
    -> checked_readonly_regular_file_handle | DENY
bounded_read(checked_readonly_regular_file_handle, MAX_METADATA_BYTES)
    -> bytes + SHA256
```

The existing `windows_build_root_test_adapter.py` must continue returning `PermissionError` until the test-only native open exists and passes its own negative runtime fixtures. Do not alter `generate_sbom.py` or `windows_metadata.py` under this design PR.

## Required proof matrix for a separate implementation candidate

| ID | Negative/positive condition | Expected outcome | Here |
| --- | --- | --- | --- |
| NRO-01 | real regular metadata basename in harness root | identical bounded bytes and correct digest | NOT EXECUTED |
| NRO-02 | traversal, UNC, drive and ADS names | reject before OS open | existing lexical suite only; native NOT EXECUTED |
| NRO-03 | root directory becomes junction before initial handle acquisition | reject or fail closed; do not claim trust | NOT EXECUTED |
| NRO-04 | root pathname replaced after handle acquisition | stay anchored to opened root identity | NOT EXECUTED |
| NRO-05 | final component is symlink, mount point or other reparse type | reject returned handle | NOT EXECUTED |
| NRO-06 | final name swapped after opening | read original opened file object only | NOT EXECUTED |
| NRO-07 | denied ACL, inaccessible native API or invalid/closed handle | DENY, no pathname fallback, no leaks | NOT EXECUTED |
| NRO-08 | outside sentinel reached through a parent junction fixture | inaccessible via basename-only root-relative open | NOT EXECUTED |
| NRO-09 | hardlink to outside-origin file | explicitly document provenance limitation; no unearned content trust | NOT EXECUTED |
| NRO-10 | max-byte overflow, directory and non-disk handles | reject and close | NOT EXECUTED |
| NRO-11 | test-only adapter is not reachable from ordinary SBOM CLI | negative static import/interface check | NOT EXECUTED |
| NRO-12 | native Windows CI on implementation head | record run/job IDs and all statuses | NOT EXECUTED |

Never characterize the earlier PR #270 junction-fixture PASS as a verified NRO-08. That test intentionally refuses to open **all** files.

## AI review using three lenses, not three independent reviewers

- **TRIAS:** the selected scope is a disposable test root; a test handle is not authorization for arbitrary filesystem roots or SBOM runtime. Stop at DRAFT.
- **ORACLE:** Microsoft's API contract supports relative file naming from a directory handle. Root selection trust, hardlink content provenance and the actual no-escape behavior require their own empirical evidence.
- **MENTOR:** implement the smallest native test-only opener in a fresh candidate, keep fail-closed defaults, and collect exact Windows jobs and adversarial fixture logs before even proposing production wiring.

**Decision:** DESIGN PREPARED / NATIVE CONTAINMENT NOT EXECUTED / HOLD / DENY.  
**Next transition:** reviewed design -> isolated Windows native test-only opener -> adversarial Windows CI -> separate security review. Merge, signing, release and production runtime remain blocked by GO-13 and their distinct authorization gates.
