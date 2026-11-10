# ORCHEASTRA — PR #252 CI and artifact review (DRAFT)

Date: 2026-11-10. Repository: `Maurits-pixe/palaco-genesis`.
Governance: **GO-13 HOLD; authorization DENY**.

## Exact checked identities

- PR #252 DRAFT head: `ab58747f8e2d77819f4cb3fd1e4a388fdc132e8d`.
- CI pull-request merge commit expected in evidence:
  `0960e82ea7e884aba821fc4639bff18097ede08e`.
- PALACO CI run `42762774492`: SUCCESS.
- PALACO SBOM Evidence Candidate run `42762774553`: SUCCESS.
- Citadel A1 interoperability run `42762774695`: SUCCESS.
- SBOM job `129652152952`: SUCCESS. GitHub step records show SUCCESS
  for generator tests, independent validator install, evidence generation,
  pre-upload ZIP round-trip, summary and upload.

## Independently verified hosted artifact

- Artifact ID: `13738555878`, name `palaco-spdx-unsigned`.
- Listed size: 27,261 bytes; expires 2027-02-08.
- GitHub-reported SHA-256:
  `cd4357fcd05ef19bf14d80a5cb266dc9a2ed4040e9cd7718473932d47e02b302`.
- ZIP downloaded by exact artifact ID. The local `sha256sum` matched the
  reported digest exactly.
- Executed offline verifier:

```sh
python verification/provenance/verify_artifact.py \
  --artifact palaco-ci-252-artifact.zip \
  --archive-sha256 cd4357fcd05ef19bf14d80a5cb266dc9a2ed4040e9cd7718473932d47e02b302 \
  --commit 0960e82ea7e884aba821fc4639bff18097ede08e
```

Exit code `0`, output:
`Unsigned SBOM artifact: integrity and reconstruction checks PASS (not an attestation)`.

## Three-lens AI review and remaining boundaries

- **TRIAS:** this is a technical candidate receipt; no approval, signing,
  merge, release or production execution is authorized.
- **ORACLE:** exact-head CI results, job step metadata, downloaded ZIP digest
  and reconstruction PASS are verified. Raw job log text and external human
  assessment were not independently reviewed.
- **MENTOR:** next review should focus on the nested `dep_kinds` contract,
  combined diff, negative regression adequacy, and outstanding #235
  non-DRAFT governance discrepancy.

Historical artifacts and PRs are preserved. **GO-13 HOLD / DENY**.
