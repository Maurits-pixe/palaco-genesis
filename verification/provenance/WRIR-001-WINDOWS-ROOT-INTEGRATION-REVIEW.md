# ORCHEASTRA Windows trusted-root integration review — WRIR-001

Status: DRAFT / REVIEW ONLY / GO-13 HOLD / authorization DENY  
Date: 2026-11-10  
Repository: `Maurits-pixe/palaco-genesis`  
Reviewed base: `94f29a7f936b245553a751b970a52d977febd649` (PR #268)  
Scope: Windows Cargo metadata input to the unsigned SBOM generator. No implementation, merge, signing, release, or runtime authorization is granted by this review.

## Observed boundaries

| Boundary | Evidence at reviewed base | Assessment |
| --- | --- | --- |
| Lexical single-component name | `verification/provenance/windows_metadata_name.py` checks separators, drive/UNC/ADS syntax, devices, controls and trailing ambiguity | IMPLEMENTED and previously Windows-CI-tested as an independent function; **not called by SBOM entry point** |
| Final metadata file | `verification/provenance/windows_metadata.py:open_regular_file(path)` uses `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT`, checks file type and attribute tag, transfers handle | IMPLEMENTED final-component gate; **not an ancestor containment gate** |
| Input boundary | `verification/provenance/generate_sbom.py:main()` accepts unrestricted `--metadata` as a `Path`, then `read_bounded_metadata(args.metadata)` | CLI currently supplies an arbitrary path; root provenance and authorization not established |
| Trusted root | No independently authorized, caller-owned, already-open directory capability flows through this API | UNKNOWN / BLOCKED for contained Windows open |
| Native ancestor traversal | Current `CreateFileW(os.fspath(path), ...)` still resolves parent components by name | Cannot assert protection against ancestor junction substitution |
| Output authorization | Evidence manifest explicitly says `signed: false`, `release_authorized: false` | Must remain so; no promotion from successful tests |

This is a source-level review; no new Windows runtime behavior was executed for WRIR-001.

## Integration contract proposed for a *future* implementation

1. A separately governed caller identifies and authorizes the trusted root **before** accepting untrusted metadata names. Its provenance and permitted scope must be testable. `cwd`, a user-supplied `--metadata` parent, a path normalization result, or a relative `Path.parent` are **not** trusted-root authority.
2. The input is a single filename validated by `validate_windows_metadata_basename`. No auto-fallback from a rejected path to its basename; reject entire path arguments.
3. The root must be held as a native directory handle with a documented owner and lifetime. Any subsequent child open must resolve relative to that handle under Windows semantics, prohibit reparse traversal at *every* traversed component, and fail closed if a required OS facility is unavailable. A string concatenation or a final-only `FILE_FLAG_OPEN_REPARSE_POINT` is insufficient.
4. Check the final file on the *opened handle* as a regular, non-reparse disk file. Keep size-bounded reading and close-on-error semantics. Avoid re-resolving a pathname after opening.
5. Keep metadata SHA-256 bound to the bytes read through the checked handle. Preserve the unsigned evidence format and `release_authorized: false`; root containment alone does not prove Cargo graph integrity or grant signing authority.
6. Maintain a separately reviewed POSIX contract; do not silently alter the current POSIX `--metadata` interface when adding Windows-only restrictions.
7. No runtime wiring until a responsible owner approves root source, Windows API strategy, supported Windows versions and explicit input migration. This review proposes these requirements, not that governance decision.

## Acceptance matrix for the implementation candidate

| Test ID | Fixture and adversarial action | Required result | Execution here |
| --- | --- | --- | --- |
| WRIR-01 | valid basename under an authorized root | bounded exact bytes read and hash match | NOT EXECUTED |
| WRIR-02 | filename with traversal, drive, UNC or ADS syntax | reject before any filesystem access | NOT EXECUTED |
| WRIR-03 | root ancestor swapped to a junction before child open | no escape outside authorized root | NOT EXECUTED |
| WRIR-04 | parent component replaced with junction during traversal | fail closed or remain within original root capability | NOT EXECUTED |
| WRIR-05 | final file switched to symlink/reparse after lexical validation | reject reparse; close handle | NOT EXECUTED |
| WRIR-06 | final file replaced by another regular file after open | read originally opened handle only | NOT EXECUTED |
| WRIR-07 | missing/revoked root authority or unavailable native API | reject; no fallback to path-based open | NOT EXECUTED |
| WRIR-08 | oversized, directory, pipe or device input | reject, without hanging or descriptor leak | NOT EXECUTED |
| WRIR-09 | ordinary POSIX evidence generation unchanged | existing regression suite passes | NOT EXECUTED for this review |
| WRIR-10 | Windows CI on *implementation head* runs negative junction fixtures | tests PASS with run/job IDs, not inherited from #268 | NOT EXECUTED |

Tests with intentionally attacker-controlled junctions require an isolated Windows test environment, a deterministically constructed outside sentinel, and exact observed outcomes. Do not infer success from a lexical unit-test PASS.

## Decision and ownership gaps

- **ROOT-AUTH-01 (BLOCKER):** Who supplies the trusted directory handle? Which policy states that this caller may select this root? Neither #268 nor current CLI provides such evidence.
- **API-STRATEGY-02 (BLOCKER):** Demonstrate the actual OS-supported handle-relative open method and its per-component non-reparse guarantee; specify Windows versions and error behavior.
- **INPUT-MIGRATION-03 (OPEN):** Document whether the supported Windows interface changes from `--metadata path` to `--trusted-root capability + --metadata-name basename`. No silent reinterpretation of existing path inputs.
- **EVIDENCE-04 (BLOCKER):** Produce independent negative tests and their Windows CI logs on the implementation head.
- **GOVERNANCE-05 (BLOCKER):** Explicit authority to merge, sign or release remains absent; GO-13 HOLD persists.

## AI review using three distinct lenses (not independent reviewers)

- **TRIAS:** Capability is not authority. Lexical validation and a trusted directory *path string* cannot approve root choice. Stop before runtime wiring until ROOT-AUTH-01 and API-STRATEGY-02 are resolved.
- **ORACLE:** The inspected source establishes the exact current call graph and the final-component-only check. PR #268 unit-test evidence cannot be reused as Windows junction evidence. All WRIR execution tests are NOT EXECUTED.
- **MENTOR:** Build next as an isolated, reviewable Windows-only adapter after the authority contract is signed off, with focused junction/race fixtures. Preserve the portable generator and unsigned evidence semantics.

## Gate outcome

WRIR-001 is a reviewable specification candidate, **not** a verified runtime integration.  
Decision: **HOLD / DENY** for runtime claims, merge, signing and release.  
Next permissible transition: DRAFT integration review → explicit root-source/API design decision → separately scoped Windows adapter with negative regression tests → evidence-based review. Any authority-bearing transition requires its own proper approver.
