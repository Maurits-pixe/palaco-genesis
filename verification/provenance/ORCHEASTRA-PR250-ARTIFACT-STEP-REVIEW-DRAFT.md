# ORCHEASTRA — PR #250 hosted artifact and CI step verification (DRAFT)

Date: 2026-11-10. Repository: `Maurits-pixe/palaco-genesis`.
Decision: **GO-13 HOLD; authorization DENY**.

## Exact observed identity

- PR #250 head: `6f97e7d157952b7df07c9d88d83bc5773393ca22`.
- GitHub's PR merge commit for this check: `535a94e4fd296d0e6893a91f92ec6fb0251e2469`.
- PALACO CI run `42761586890`: completed SUCCESS.
- SBOM Candidate run `42761586567`: completed SUCCESS.
- Citadel A1 interoperability run `42761586690`: completed SUCCESS.
- The SBOM job `129648273146` returned SUCCESS. GitHub step metadata
  separately recorded SUCCESS for generator tests, pinned validator install,
  candidate generation (including `pyspdxtools`), preupload ZIP verification,
  identity summary and artifact upload.

## Hosted artifact, independent bytes and reconstruction

- Artifact ID `13737114448`, `palaco-spdx-unsigned`.
- Listed ZIP size: 27,260 bytes; expiration: 2027-02-08.
- GitHub artifact digest:
  `sha256:0bd96be679e26a71a25ec2a623b7ce81a5816c739e4b4dc671f2cba86aebc757`.
- Independently downloaded the ZIP by the artifact ID.
- Local `sha256sum` returned exactly
  `0bd96be679e26a71a25ec2a623b7ce81a5816c739e4b4dc671f2cba86aebc757`.
- The offline verification command used the *PR merge commit*, not the head:

```sh
python verification/provenance/verify_artifact.py \
  --artifact palaco-ci-250-artifact.zip \
  --archive-sha256 0bd96be679e26a71a25ec2a623b7ce81a5816c739e4b4dc671f2cba86aebc757 \
  --commit 535a94e4fd296d0e6893a91f92ec6fb0251e2469
```

Observed exit code `0` and result:
`Unsigned SBOM artifact: integrity and reconstruction checks PASS (not an attestation)`.

## Limits and advisory three-lens review

- **TRIAS:** source and generated evidence remain unsigned and non-authoritative;
  no GO-13 release transition can follow from this result.
- **ORACLE:** archive digest, offline reconstruction and GitHub job/step statuses
  were inspected. Raw CI log content and upstream validator console text were
  **not** independently retrieved; step-level SUCCESS is GitHub metadata.
- **MENTOR:** independently review the full combined source diff, inspect raw
  CI logs if required, resolve the #235 non-DRAFT exception, then record an
  identified human GO-13 decision.

This is a new candidate receipt, not a replacement for prior artifacts.
No merge, release, signing, issuance or production execution is authorized.
