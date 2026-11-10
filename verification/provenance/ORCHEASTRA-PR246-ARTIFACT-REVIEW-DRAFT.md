# ORCHEASTRA — PR #246 hosted artifact verification (DRAFT)

Date: 2026-11-10. Decision: **GO-13 HOLD**. Authorization: **DENY**.
This supplements the earlier stacked review without rewriting it.

## Exact object checked

- Repository: `Maurits-pixe/palaco-genesis`.
- PR #246 head: `5cbdb4ae2b4fdc8ef6d1be6f98b82630d49bbb09`.
- GitHub Actions workflow `PALACO SBOM Evidence Candidate`, run `42758547869`: SUCCESS.
- Hosted artifact ID: `13736647410`; name: `palaco-spdx-unsigned`.
- Reported ZIP size: 27,258 bytes; reported expiry: 2027-02-08.
- GitHub-reported SHA-256: `38d57a762b9c00e6d75cf9b8b6701d96197da845e8c9858718213c2495245bdd`.
- CI PR merge/checkout commit expected in evidence: `5007048fd775ba5988348ec57bfae272b1116d50`, **not** the PR head.

## Independent local reconstruction

The hosted ZIP was downloaded by artifact ID. The local `sha256sum` was
`38d57a762b9c00e6d75cf9b8b6701d96197da845e8c9858718213c2495245bdd`,
an exact match to the reported GitHub artifact digest.

The offline command used was:

```sh
python verification/provenance/verify_artifact.py \
  --artifact palaco-ci-246-artifact.zip \
  --archive-sha256 38d57a762b9c00e6d75cf9b8b6701d96197da845e8c9858718213c2495245bdd \
  --commit 5007048fd775ba5988348ec57bfae272b1116d50
```

Observed exit code: `0`. Verifier output:
`Unsigned SBOM artifact: integrity and reconstruction checks PASS (not an attestation)`.

The prior open action to download and reconstruct the #246 hosted artifact is
thus **technically checked**. This does not establish the correctness of the
underlying dependency selection, an external signature, or reviewer consent.

## Remaining review boundaries

- Review combined stack ancestry, workflow semantics, the full diff and
  independent evidence against `main` immediately before any decision.
- Record the SPDX validator version and exact CI step outputs separately.
- Address the #235 `draft: false` discrepancy in the governance review.
- Obtain identified independent human review and an explicit GO-13 decision.
- Do not merge, sign, release, issue authority, or reinterpret CI PASS as approval.

**Status: DRAFT — technical artifact verification PASS; GO-13 HOLD.**
