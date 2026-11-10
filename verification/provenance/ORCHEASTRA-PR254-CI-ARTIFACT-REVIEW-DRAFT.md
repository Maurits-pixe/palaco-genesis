# ORCHEASTRA — PR #254 CI and artifact review (DRAFT)

Date: 2026-11-10. Repository: `Maurits-pixe/palaco-genesis`.
Governance: **GO-13 HOLD; authorization DENY**.

## Exact checked identities

- PR #254 is OPEN / DRAFT, not merged; base branch:
  `codex/orcheastra-pr252-ci-artifact-review-20261110`.
- Checked head: `f385f914b0e2d5e33e85215b5409d58bb5d29eda`.
- GitHub PR merge commit bound into CI artifact reconstruction:
  `bca4a72be05526222fce866464393f31e36ac258`.
- PALACO CI run `42769553642`: SUCCESS.
- Citadel A1 interoperability run `42769553296`: SUCCESS.
- PALACO SBOM Evidence Candidate run `42769553485`: SUCCESS.
- SBOM job `129673873232`: SUCCESS. Its published step records individually
  indicate SUCCESS for generator tests, independent SPDX validator install,
  candidate generation, pre-upload ZIP round-trip, review identities, and
  unsigned artifact upload.

## Downloaded hosted artifact and independent offline check

- Artifact ID `13740439994`, name `palaco-spdx-unsigned`.
- GitHub-listed size: 27,261 bytes; not expired; expiration
  `2027-02-08T06:35:41Z`.
- Artifact workflow binds `head_sha` to the exact PR #254 head above.
- GitHub-reported SHA-256:
  `73ba9c966d52bdd0f080052a4287b22f502ad0438512ddc466690096ee70c793`.
- Downloaded ZIP by exact artifact ID; local `sha256sum` returned the same
  `73ba9c966d52bdd0f080052a4287b22f502ad0438512ddc466690096ee70c793`.
- Executed locally with exit status `0`:

```sh
python verification/provenance/verify_artifact.py \
  --artifact palaco-ci-254-artifact.zip \
  --archive-sha256 73ba9c966d52bdd0f080052a4287b22f502ad0438512ddc466690096ee70c793 \
  --commit bca4a72be05526222fce866464393f31e36ac258
```

Verifier output:
`Unsigned SBOM artifact: integrity and reconstruction checks PASS (not an attestation)`.

## Scope and evidence limits

PR #254 adds a bounded 20 MiB Cargo metadata file read (pre-stat, then
limit-plus-one read) and a boundary/oversize regression test. Earlier local
provenance unittest suite reported 27/27 PASS; current GitHub generator test
step and broader CI are SUCCESS. This review independently checked the hosted
ZIP's integrity and reconstruction, **not** independent real-world runtime
security, external human approval, signing, attestation, release or activation.
Raw CI job logs were not independently reviewed; the observed step metadata
is not a substitute for raw logs. The outstanding #235 non-DRAFT status
discrepancy remains open for governance review.

## Three-lens AI review

- **TRIAS:** the evidence belongs to the exact PR #254 candidate; the
  verification does not lift GO-13 HOLD, DENY, or authorize merge/sign/release.
- **ORACLE:** three exact-head workflow conclusions, a successful SBOM job,
  hosted artifact identity, matching local digest and offline reconstruction
  support the technical PASS; raw logs and human review remain unverified.
- **MENTOR:** preserve the original PRs and artifacts. Review the bounded-read
  race behavior and negative-test coverage as a separate technical acceptance
  decision, and address the #235 DRAFT discrepancy through governance.

**Decision:** DRAFT evidence supplement only. Technical artifact controls
**PASS**; authorization **DENY**; GO-13 **HOLD**. No merge, signing or release.
