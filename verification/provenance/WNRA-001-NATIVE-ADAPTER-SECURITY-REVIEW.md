# WNRA-001 — Security review of native Windows test adapter (DRAFT)

**Date:** 2026-11-10  
**Repository:** `Maurits-pixe/palaco-genesis`  
**Reviewed immutable head:** `d6d2ce2e08902ef078e728e90945a7daaa7cfbff` (PR #273)  
**Proposed review branch:** `codex/orcheastra-native-adapter-security-review-20261110`, stacked on `codex/orcheastra-native-root-race-tests-20261110`  
**Scope:** experimental test-only trusted-root fixture and native NT root-relative open.  
**Decision:** **DRAFT / SECURITY REVIEW OPEN / GO-13 HOLD / AUTHORIZATION DENY**. No merge, signing, release, production integration, publication or deployment.

## 1. Evidence and claims

Read directly at reviewed head:
- `verification/provenance/windows_native_relative_test_open.py` (native `NtCreateFile`, `RootDirectory`, handle checks, CRT transfer, bounded read).
- `verification/provenance/windows_build_root_test_adapter.py` (disposable root; `read_metadata` explicitly denies all real reads).
- `verification/provenance/windows_metadata_name.py` (lexical single-component validator).
- `verification/provenance/test_windows_native_relative_open.py` (positive, invalid names, lifecycle, junction, missing file cases).
- `verification/provenance/test_windows_native_relative_races.py` (deterministic rename/replace of child path and root path).
- `.github/workflows/orcheastra-windows-metadata.yml` (Windows runner and test invocations).

At the reviewed head, GitHub Actions reported success for:
- ORCHEASTRA Windows metadata regression: run **42880725976**; includes two deterministic replacement races that returned original handle-backed bytes.
- PALACO CI: run **42880726134**.
- Citadel A1 interoperability: run **42880726283**.
- PALACO SBOM Evidence Candidate: run **42880726252**.

These are **CI PASS for named controls on this head only**. They do **not** establish adversarial filesystem containment, signed provenance, production authority, or release readiness. This review document adds no execution of new Windows tests.

## 2. Security findings and disposition

### WNRA-01 — UTF-16 native string length mismatch — NEEDS FIX / regression (HIGH)

`read_fixture_metadata_relative` constructs `_UnicodeString` with `Length = len(basename.encode("utf-16-le"))` but `MaximumLength = (len(basename) + 1) * 2`. Python `len` counts Unicode code points, while native Windows `UNICODE_STRING` length is in bytes of UTF-16 code units. A permitted non-BMP character such as U+1F600 uses a surrogate pair. Thus `MaximumLength` is smaller than `Length + 2` and may even be smaller than `Length` for multiple supplementary characters. The lexical validator does not reject these characters.

**Required test:** Windows-only fixture `"😀.json"` and a longer name with multiple supplementary scalars; verify correct reading or a deterministic, explicit pre-open rejection. **Required fix:** calculate both fields from the **same encoded UTF-16LE representation**, include one UTF-16 NUL unit in `MaximumLength`, validate the USHORT byte limit, and preserve the buffer for the entire call. No production integration before retest.

### WNRA-02 — transferred native handle/CRT descriptor ownership — NEEDS NEGATIVE TEST (MEDIUM)

After `msvcrt.open_osfhandle(child_handle, ...)` returns a descriptor, the code transfers ownership and then calls `os.fdopen(fd, "rb")`. If `os.fdopen` fails before its context manager begins, the descriptor is not explicitly closed by the outer `finally`; `child_handle` was already set to `None`. Successful transfer, early I/O exceptions, invalid fd and CRT conversion error paths need targeted mocked failure injection, confirming **exactly one** close per resource and no leaks/double close.

**Required test/fix:** inject `os.fdopen` failure, short-read and oversized-content failure; track descriptor and native handle lifecycle. Do not infer leak-free behavior from successful-path CI alone.

### WNRA-03 — root-capability issuance and scope — BLOCKS production (HIGH)

`type(fixture) is BuildRootTestAdapter` and `TemporaryDirectory` prove the experimental API accepts only its own disposable fixture class; they do not authenticate an external caller or authorize a chosen filesystem directory. `CreateFileW(str(fixture.root), ...)` is still a **path-based root acquisition** before relative child access. Root lifecycle and provenance must be supplied by a controlled build worker, with owner, lease, namespace, volume and ACL policy independently reviewed. `BuildRootTestAdapter.read_metadata` appropriately remains fail-closed.

**Required gate:** production capability issuance and disposal contract, threat model for hostile users/build jobs and shared temp roots, Windows ACL and handle-inheritance review, explicit separation of test and production imports. No generic root-path input.

### WNRA-04 — hardlinks, mutation after open, and provenance — UNVERIFIED (HIGH)

`FILE_OPEN_REPARSE_POINT` plus `FileAttributeTagInfo` checks address reparse objects at the **opened handle**, and race fixtures cover namespace renames. They do not prove the underlying file was created within the authorized root: an attacker may create an NTFS hardlink to a file elsewhere on the same volume, or mutate the opened file's contents **in place** while `_SHARE` allows READ | WRITE | DELETE. A handle-anchored open prevents path substitution but does not by itself prove byte immutability or content-origin authorization.

**Required negative fixtures:** authorized temporary volume with a deliberately created outside-root hardlink (if filesystem/privileges support it; report SKIP distinctly), synchronized in-place writes while reading, and an explicit immutable-snapshot or provenance contract. No claim that `FILE_OPEN_REPARSE_POINT` rejects hardlinks.

### WNRA-05 — link variants, error cleanup and portability — OPEN (MEDIUM)

Current junction fixture can SKIP when `mklink /J` is unavailable; a SKIP must not be counted as proof. Expand cases for file symbolic link, root junction/symlink, dangling target, denied ACL, malformed native status, Windows path-name edge cases, cleanup exceptions and simultaneous open/close. Keep the checks constrained to disposable fixtures. A Linux-only invocation cannot verify Windows NT semantics.

**Required reporting:** assert/record executed versus skipped tests per Windows CI job, resource cleanup, volume/filesystem, and test-runner privileges. Do not silently broaden the supported platform or authority.

## 3. What is established and what is not

| Concern | Evidence at reviewed head | Disposition |
| --- | --- | --- |
| Native `RootDirectory`-relative open under disposable fixture | Source + native Windows CI | IMPLEMENTED / bounded CI PASS |
| Reject parent traversal and lexical separators | Source + Windows tests | CI PASS for tested names |
| Post-open path rename does not retarget child handle | Deterministic Windows race CI | CI PASS for two tested races |
| Native non-BMP Unicode length correctness | Source shows mismatch; no dedicated regression | REVIEW FINDING / NOT EXECUTED |
| Descriptor-close behavior on `fdopen` failure | No negative injection test | UNVERIFIED |
| Hardlink origin and in-place-write integrity | No applicable proof | UNVERIFIED |
| Production trusted-root capability | No production issuer, policy, authority or review | BLOCKED / DENY |
| GO-13 release/merge | Gate not granted | HOLD |

## 4. AI review across three lenses

**TRIAS — constitutional / authority boundary.** Test-only surface and `read_metadata` deny gate are preserved. A disposable `TemporaryDirectory` is not a trusted production capability; no inference of authority or release from passing CI. **Decision: production integration blocked.**

**ORACLE — evidence / falsifiability.** Four named workflows succeeded at the frozen head, but the UTF-16 length inconsistency is directly observable from source; resource ownership and content provenance have untested failure modes. **Decision: positive tests retain their narrow PASS; broader claims UNVERIFIED.**

**MENTOR — implementation clarity.** Resolve WNRA-01 first as the smallest standalone hardening candidate with non-BMP Windows regression; then WNRA-02 failure-injection close test, then WNRA-04 adversarial hardlink/content-mutation exploration. Keep follow-up modifications separated from this frozen review evidence.

This is one assistant's **three-lens AI review**, not three independent reviewers or human approval.

## 5. Proposed bounded next transition

`DRAFT security review (this document)` → `separate DRAFT WNRA-01 UTF-16 hardening candidate`, based on this exact reviewed head, with positive and negative native Windows tests, CI-bound head and reviewable diff. That transition is suitable for preparation under GO; **merge, signing, release, production wiring, runtime authority and changing GO-13 HOLD remain forbidden** until explicit applicable gates and authorized human review.
