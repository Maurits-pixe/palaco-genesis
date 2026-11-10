# ORCHEASTRA Windows atomic metadata open contract — DRAFT

Date: 2026-11-10 (Europe/Amsterdam). Upstream review: PR #262 at `db5aa86b4c4442c9ad53870585a900d1b47339fb`.

## Problem and evidence boundary

Current `read_bounded_metadata(path)` uses `O_NOFOLLOW` where supported, otherwise `os.open` and a later `os.stat(path, follow_symlinks=False)` comparison with `os.fstat(fd)`. PR #261 proved 15 Windows tests PASS (2 POSIX skips). This validates the tested cases, **not an atomic no-follow guarantee** against hostile concurrent pathname swaps. PR #262 documented the remaining risk. Both are DRAFT and GO-13 HOLD.

## Required invariant

For untrusted metadata paths, the data bytes consumed by the SBOM generator must originate from a regular, bounded file opened through an OS-level mechanism which does not traverse a final reparse point/symlink, with no check-then-open pathname race. The source must be bound to the opened handle; limit-plus-one reads still enforce `MAX_METADATA_BYTES`. A failed check MUST fail closed without partial evidence output or authority claim.

## Windows implementation candidate, NOT IMPLEMENTED

Use a reviewed native Windows handle-opening boundary:

1. Open with Windows `CreateFileW` using an explicit sharing policy, `OPEN_EXISTING`, and `FILE_FLAG_OPEN_REPARSE_POINT` so final-component reparse points can be inspected rather than followed.
2. Inspect the returned handle for regular-file type and reparse-point attributes using handle-based Windows APIs. Reject every reparse tag unless a specifically reviewed allowlist exists (default: deny).
3. Validate a stable handle identity and bound file size; read only through that handle, retaining the 20 MiB cap and limit-plus-one test.
4. Convert to a Python file descriptor **only if** handle ownership and binary-mode semantics are reviewed; close exactly once on every success/error path.
5. Resolve parent-directory reparse behavior and trusted-root constraints separately. `FILE_FLAG_OPEN_REPARSE_POINT` alone does not guarantee protection against parent-directory traversal.

No native API wrapper, privileged operation or release authorization is introduced by this contract. The current fallback remains as implemented and its limitation must be disclosed.

## Acceptance matrix for a separate hardening candidate

| Case | Required outcome |
| --- | --- |
| Ordinary Cargo metadata regular file | PASS, correct bytes |
| Final symbolic link | DENY, no data returned |
| Windows junction or other reparse-point final component | DENY |
| Parent-directory junction when trusted root is required | DENY or verified containment; specify exact policy |
| Rename/swap during open | No accepted symlink traversal; adversarial test required |
| File replaced after opening | Reads stay bound to opened handle, no path re-open |
| Nonregular file (pipe/device/directory) | DENY without hang |
| 20 MiB exact / 20 MiB + 1 | ACCEPT / DENY |
| Truncation or growth during read | Deterministic bounded outcome or DENY |
| Open/inspect/read errors | Handle closed exactly once; no partial evidence |
| Linux/POSIX path | Existing `O_NOFOLLOW` and FIFO checks remain PASS |
| Windows runner | Native job must run and individual tests cannot silently skip mandatory cases |

## Review gates

- Spec and tests: review first; Python standard-library/native binding choice and ownership semantics must be approved before implementation.
- Negative tests must exercise native Windows handles, not solely mock `O_NOFOLLOW=0`.
- CI must include the native Windows job and the Linux provenance suite; record exact head SHA/run IDs.
- Artifact integrity/reconstruction is separately checked and remains unsigned/non-attestational.
- Any base/head changes after review require a new bound review, not reuse of prior PASS.

## Three-lens AI review (not independent reviewers)

- **TRIAS:** DRAFT specification only; GO-13 HOLD and authorization DENY. No implementation/merge/release.
- **ORACLE:** Remaining race risk is evidenced by sequential path/FD checks; an atomic Windows guarantee is NOT VERIFIED. Existing Windows tests cover only their observed cases.
- **MENTOR:** Implement the native handle boundary in one small candidate with explicit ownership, error and reparse tests, then independently review. Do not replace the existing evidence.

Disposition: SPECIFICATION DRAFT / WINDOWS ATOMIC OPEN NOT IMPLEMENTED / SECURITY CLAIM HOLD.
