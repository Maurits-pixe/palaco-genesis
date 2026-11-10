# ORCHEASTRA — PR #256 CI and hosted artifact review (DRAFT)

Date: 2026-11-10. Repository: `Maurits-pixe/palaco-genesis`.
Governance: **GO-13 HOLD; authorization DENY**.

## Exact candidate and workflow identities

- PR #256: OPEN / DRAFT / not merged, stacked on PR #255 head branch
  `codex/orcheastra-pr254-ci-artifact-review-20261110`.
- Candidate head SHA: `f7ae845567b2270ec8cb45de05e8c621a1622fc0`.
- GitHub pull-request CI merge commit: `834aaa298073996b68a07f65a619e0216414bcf1`.
- PALACO CI run `42772628451`: SUCCESS.
- Citadel A1 interoperability run `42772628466`: SUCCESS.
- PALACO SBOM Evidence Candidate run `42772628400`: SUCCESS.
- SBOM job `129683734182`: SUCCESS. GitHub lists successful generator testing,
  SPDX validator installation, evidence generation, pre-upload ZIP round-trip,
  unsigned review-identity publication and artifact upload steps.

## Independent check of hosted unsigned artifact

- Artifact `13742198140`, name `palaco-spdx-unsigned`.
- Listed size: 27,260 bytes, not expired; expiration
  `2027-02-08T07:03:28Z`.
- The workflow artifact's head SHA equals PR #256's exact head SHA above.
- Reported artifact ZIP digest:
  `sha256:f8ed228b8852d4cc18edc116f01b27ad898c30f4fffcdbd46d5e85c5a53b08f7`.
- ZIP downloaded by artifact ID; local `sha256sum` matched exactly:
  `f8ed228b8852d4cc18edc116f01b27ad898c30f4fffcdbd46d5e85c5a53b08f7`.
- Offline verification executed with exit code `0`:

```sh
python verification/provenance/verify_artifact.py \
  --artifact palaco-ci-256-artifact.zip \
  --archive-sha256 f8ed228b8852d4cc18edc116f01b27ad898c30f4fffcdbd46d5e85c5a53b08f7 \
  --commit 834aaa298073996b68a07f65a619e0216414bcf1
```

Observed output:
`Unsigned SBOM artifact: integrity and reconstruction checks PASS (not an attestation)`.

## Scope, remaining uncertainty and three-lens AI review

PR #256 binds the early Cargo metadata size check to the *opened file
descriptor* using `os.fstat`, and retains a bounded limit-plus-one read to
reject growth. Local provenance unittest suite: 28/28 PASS, including negative
simulations of a descriptor reporting oversized input and of growth following
an underreported descriptor size. This does not establish exhaustive runtime
race freedom or hostile-filesystem security.

- **TRIAS:** technical evidence does not authorize merge, signing, release,
  production execution or a GO-13 gate change. PR #235's non-DRAFT governance
  discrepancy is not resolved by this review.
- **ORACLE:** exact-head workflow conclusions and step metadata, artifact ID,
  matched local digest, and offline reconstruction support a bounded technical
  PASS. Raw job logs and independent human review were not assessed.
- **MENTOR:** preserve historical PRs and evidence; next inspect the cumulative
  stacked diff and any remaining risky non-regular metadata input behavior
  before considering a separate technical acceptance decision.

**Decision:** DRAFT artifact review candidate only. Verified named integrity
and reconstruction checks **PASS**. GO-13 **HOLD** / authorization **DENY**.
No merge, signing, attestation, release or activation.
