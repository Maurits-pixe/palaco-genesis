# ORCHEASTRA — PR #258 CI and hosted artifact review (DRAFT)

Date: 2026-11-10. Repository: `Maurits-pixe/palaco-genesis`.
Governance: **GO-13 HOLD; authorization DENY**.

## Exact candidate identities

- PR #258: OPEN / DRAFT / not merged, stacked on PR #257 head branch
  `codex/orcheastra-pr256-ci-artifact-review-20261110`.
- Exact PR #258 head SHA: `a3eaf6e3f5abedce4e04534f673908898b7b8408`.
- GitHub pull-request merge commit for evidence reconstruction:
  `e53c4f6c2244e650bd8da41229e806a582ee0a61`.
- GitHub reported `mergeable: true` at review time. This is not authorization.

## Exact-head GitHub Actions observations

- PALACO CI run `42774898998`: SUCCESS.
- Citadel A1 interoperability run `42774899055`: SUCCESS.
- PALACO SBOM Evidence Candidate run `42774899242`: SUCCESS.
- SBOM job `129690999704`: SUCCESS. The returned step metadata records
  success for generator testing, independent SPDX validator install,
  candidate generation, ZIP round-trip, unsigned identity publication and
  artifact upload. Raw job logs were not independently inspected.

## Hosted unsigned artifact verification

- Artifact ID: `13742888988`, name `palaco-spdx-unsigned`, size 27,260 bytes.
- Artifact not expired; listed expiration: `2027-02-08T07:23:01Z`.
- Artifact workflow head SHA matched the exact PR #258 head above.
- GitHub-reported SHA-256:
  `4d02f6cdb612126c66797c2389fe938d14d752b363551d05b7ba3cf4385d9b3b`.
- Downloaded ZIP by artifact ID, and local `sha256sum` matched that digest.
- Offline check executed with exit status `0`:

```sh
python verification/provenance/verify_artifact.py \
  --artifact palaco-ci-258-artifact.zip \
  --archive-sha256 4d02f6cdb612126c66797c2389fe938d14d752b363551d05b7ba3cf4385d9b3b \
  --commit e53c4f6c2244e650bd8da41229e806a582ee0a61
```

Observed output:
`Unsigned SBOM artifact: integrity and reconstruction checks PASS (not an attestation)`.

## Scope and three-lens AI review

PR #258 proposes a nonregular-input hardening of the Cargo metadata reader:
descriptor-based `S_ISREG`, supported `O_NONBLOCK`/`O_NOFOLLOW` flags, and
descriptor cleanup while retaining the 20 MiB input bound. Local provenance
tests reported 30/30 PASS, including platform-gated FIFO and symlink cases.
Those tests and CI do not constitute exhaustive platform security validation.

- **TRIAS:** exact-head technical controls pass, but GO-13 HOLD and DENY are
  unchanged. No merge, signing, release or production execution authorized.
- **ORACLE:** workflows, job step metadata, artifact identity, local matching
  SHA-256 and offline reconstruction support the listed bounded PASS claims.
  Raw logs, additional platforms and human approval remain unverified.
- **MENTOR:** next inspect cumulative stacked changes, Windows/other platform
  semantics and the still-open #235 DRAFT governance discrepancy before any
  technical acceptance decision.

**Decision:** separate DRAFT evidence supplement; checked controls PASS.
**GO-13 HOLD / authorization DENY.** No merge, signing or release.
