# ORCHEASTRA PR #261 — cross-platform evidence review (DRAFT)

Date: 2026-11-10 (Europe/Amsterdam). Repository: `Maurits-pixe/palaco-genesis`.

## Immutable reviewed object

- PR: https://github.com/Maurits-pixe/palaco-genesis/pull/261 (OPEN / DRAFT at review).
- Base branch: `codex/orcheastra-portable-nofollow-hardening-20261110`, base SHA `f35132b1fd9ef482fd87cffe0273cbd0b5786fb4`.
- Reviewed PR head SHA: `cc2307da146abfffc56b16a81d363704c1f94a5e`.
- PR #261 changes only `.github/workflows/orcheastra-windows-metadata.yml` and `verification/provenance/test_generate_sbom.py`; code hardening lives in the stacked PR #260 and earlier PRs.
- Earlier PRs and frozen evidence are not modified by this review.

## Run binding and outcomes

| Check | Run | Result |
| --- | --- | --- |
| PALACO CI | 42784393366 | SUCCESS |
| PALACO SBOM Evidence Candidate | 42784393434 | SUCCESS |
| Citadel A1 interoperability | 42784393384 | SUCCESS |
| ORCHEASTRA Windows metadata regression | 42784393455 | SUCCESS |

Windows job `129721895984` on native `windows-latest`, CPython 3.12.10: 17 tests discovered, 15 PASS, 2 SKIP. Skipped: POSIX FIFO behavior and native `O_NOFOLLOW` behavior. The portable fallback symlink rejection, path replacement rejection, normal regular-file acceptance and opened-descriptor regression all PASS on Windows.

Historic failed run `42783699563` (head `05568b74a3199b5f124d138c75372142fe5b0ce8`) is preserved. It failed because the old `os.fstat` test mock omitted `st_dev` and `st_ino`; test fixture fix is part of the reviewed head.

## Unsigned SBOM evidence

- SBOM workflow run: `42784393434`; artifact ID `13747532427` (`palaco-spdx-unsigned`).
- Archive SHA-256 (GitHub metadata and independent local hash agree): `e341787f557589be4cef411f5813fce948ce855ef1a792bd0b91b74120c32f6e`.
- Embedded evidence commit: `85f44204e05e1a29e19f308aa7c754227a364972` (PR merge-test context, not the PR head).
- Existing `verification/provenance/verify_artifact.py` returned exit 0 with `Unsigned SBOM artifact: integrity and reconstruction checks PASS (not an attestation)` when supplied that archive hash and evidence commit.
- Embedded fields `signed=false`, `release_authorized=false`. No claim of signature, independent attestation or production authorization.

## Remaining risk and evidence limits

1. **Atomicity:** on platforms without `O_NOFOLLOW`, `os.open` followed by `os.stat(path, follow_symlinks=False)` plus device/inode comparison detects the tested cases but is not an atomic open-without-follow guarantee. Rapid pathname substitution and restoration between these calls is not exhaustively ruled out. A stronger platform-specific open primitive or constrained trusted input location is needed before hostile-path assurance is claimed.
2. **Platform coverage:** the two skipped POSIX-only tests remain NOT EXECUTED on Windows. This is expected, not PASS. Windows coverage is limited to the tests actually executed.
3. **Workflow scope:** the Windows workflow runs the `test_generate_sbom.py` suite only, not the complete repository on Windows. The PALACO CI Rust checks were performed by separate Linux jobs.
4. **Authority:** green CI and reconstructed unsigned artifact do not authorize merge, release, deployment or signing.

## AI review according to three lenses (not independent reviewers)

- **TRIAS:** Scope and GO-13 boundaries are preserved. Decision: HOLD for merge/release; DENY production authority.
- **ORACLE:** The exact head, four success runs, Windows per-test outcomes, failed earlier run and unsigned artifact are traceable. Dissent: full atomic no-follow semantics are unproven on Windows.
- **MENTOR:** Keep the small Windows regression gate; next useful candidate is a focused Windows-specific atomic path-open or trusted-directory contract, with adversarial negative tests. Avoid broad refactoring until that contract is chosen.

**Disposition:** REVIEW DOCUMENTED / CI PASS / LIMITED WINDOWS RUNTIME PASS / UNSIGNED ARTIFACT RECONSTRUCTION PASS / RELEASE HOLD. No merge, signing, certification, deployment or authority transition.
