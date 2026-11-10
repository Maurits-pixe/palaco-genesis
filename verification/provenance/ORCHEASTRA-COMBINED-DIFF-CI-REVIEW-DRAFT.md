# ORCHEASTRA — combined diff and CI boundary review (DRAFT)

Date: 2026-11-10. Repository: `Maurits-pixe/palaco-genesis`.
Decision: **GO-13 HOLD**, release and authority **DENY**.

## Exact GitHub comparison

- Baseline: `6ca294d2f6361a60b353e7bdf335886c5c616fd3` (the recorded #229 base, not an assertion about current `main`).
- Tip: PR #249 head `4e90767465292396fd49deb507450fba4d3b2c49`.
- GitHub compare: `ahead`, **51** commits ahead, **0** behind; merge base equals the stated baseline.
- Compare enumerates **13** changed files: one workflow, four review/guide Markdown documents, four implementation scripts, three unit-test scripts and one end-to-end test script.
- `.github/workflows/orchestrator-sbom.yml` is new, with 59 added lines and no deletion. The only existing file modified within this comparison is `verification/provenance/README.md` (105 additions, 2 deletions); other 12 files are added.

## Workflow and implementation inspection

Read directly at the exact tip:

- Workflow triggers: `pull_request` and `workflow_dispatch`; permission `contents: read`.
- Checkout and upload-artifact actions are commit-pinned; the Rust toolchain action is commit-pinned. Note that Rust channel `stable` is **not a pinned compiler version**.
- Workflow executes local unittests, installs `spdx-tools==0.8.3`, generates evidence from `cargo metadata --locked --format-version 1`, runs internal verifier, `pyspdxtools`, local ZIP round-trip, and uploads the unsigned artifact.
- The `GITHUB_SHA` (PR merge checkout) is explicitly distinguished in the step summary from `github.event.pull_request.head.sha`.
- Generator includes duplicate JSON-key rejection, rejection of nonfinite JSON constants, package/resolve coverage checks, and deterministic JSON output.
- The workflow and documentation explicitly prohibit treating unsigned evidence as an attestation or authority decision.

These are **source-inspection observations**, not proof of every transitive
dependency behavior, each action's runtime internals, or code-security approval.

## CI bound to the exact tip

GitHub Actions runs queried for `4e90767465292396fd49deb507450fba4d3b2c49`:

| Workflow | Run ID | Observed conclusion |
| --- | --- | --- |
| PALACO CI | `42760562172` | SUCCESS |
| PALACO SBOM Evidence Candidate | `42760562004` | SUCCESS |
| Citadel A1 interoperability | `42760562009` | SUCCESS |

All three were `completed`. Run-level success was observed, but individual
step logs and exact validator console output have **not** been independently
downloaded as part of this check. Artifacts for this #249 tip have **not**
been independently downloaded or reconstructed. The previous #246 artifact
PASS must not be recycled as #249 artifact proof.

## Three-lens AI review

- **TRIAS:** limited read-only review and documentation are within scope;
  GO-13 HOLD and the #235 non-DRAFT exception remain blockers.
- **ORACLE:** exact GitHub compare and tip-bound workflow-run metadata support
  the above observations. Full diff-level adversarial analysis, step logs,
  fresh hosted-artifact digest, and current-main comparison remain open.
- **MENTOR:** the next smallest complete proof step is to collect the #249
  workflow job/step records and hosted artifact, then independently verify
  the latter's digest and reconstruction against the actual CI checkout SHA.

**No merge, signing, release, endorsement, or production authority.**
