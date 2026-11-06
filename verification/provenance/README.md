# PALACO SBOM evidence — review guide

This directory builds an **unsigned candidate**, not a trusted provenance
attestation or release permit. It is used by the draft SBOM evidence PR and
does not change runtime authority.

## Review boundary

- Input: `cargo metadata --locked --format-version 1`, a 40-character commit SHA,
  and the commit timestamp.
- On a `pull_request` workflow, `GITHUB_SHA` may identify GitHub's temporary
  **merge commit**, while the artifact listing's `workflow_run.head_sha`
  identifies the PR **head commit**. These are different identities. Use the
  `commit` actually recorded in `evidence.json` for artifact reconstruction,
  and separately confirm it matches the run's checkout/`GITHUB_SHA` from logs.
  Never substitute the PR head SHA as the verifier's `--commit` argument.
- Output: deterministic `sbom.spdx.json` (SPDX 2.3 Cargo package/dependency
  inventory), `evidence.json` (digests and explicit non-authority flags), and
  a copy of the raw Cargo metadata in the uploaded CI artifact.
- Internal verifier: checks the commit binding, digests, structural references,
  negative authority claims, and re-derives the SBOM from Cargo metadata.
- Separate implementation: pinned upstream `spdx-tools` parses and validates
  the generated SPDX JSON in CI.
- Excluded: source-file inventory, independently corroborated build materials,
  artifact signing, release attestation, vulnerability assessment, and approval.

The SPDX package license comes from Cargo metadata. The legacy dual-license
choice `MIT/Apache-2.0` is rendered as `MIT OR Apache-2.0`; this is a syntax
normalization, not a legal determination.

## Reproduce the candidate locally

Run from the repository root with Rust/Cargo and Python 3 installed:

```bash
python3 -m unittest discover -s verification/provenance -p 'test_*.py'
REVIEW_DIR=$(mktemp -d)
cargo metadata --locked --format-version 1 > "$REVIEW_DIR/cargo-metadata.json"
COMMIT=$(git rev-parse HEAD)
EPOCH=$(git show -s --format=%ct "$COMMIT")
python3 verification/provenance/generate_sbom.py \
  --metadata "$REVIEW_DIR/cargo-metadata.json" \
  --commit "$COMMIT" --source-epoch "$EPOCH" \
  --output-dir "$REVIEW_DIR/sbom"
python3 verification/provenance/verify_evidence.py \
  --metadata "$REVIEW_DIR/cargo-metadata.json" \
  --commit "$COMMIT" --output-dir "$REVIEW_DIR/sbom"
```

To independently validate the SPDX format, use the same version pinned in
`.github/workflows/orchestrator-sbom.yml` and run:

```bash
pyspdxtools -i "$REVIEW_DIR/sbom/sbom.spdx.json"
```

The generated `REVIEW_DIR` is local to the review session; preserve its exact
path in the review notes if needed. The commands above are instructions, not
proof that a human review was executed.

## GO-13 human review checklist

1. Record the PR URL, exact head SHA, base SHA, workflow file revision, and
   whether the PR remains draft. Re-check after any commit; do not reuse older
   green runs for a new head. Also record the checkout/merge commit separately.
2. Inspect the full diff for workflow permissions, dependency pin, Cargo input
   coverage, license-expression handling, and fail-closed behavior.
3. Check that **all** required workflow runs succeeded on that exact head.
   Capture run IDs and relevant job/step results, including upstream validation.
4. Download the artifact associated with that run. Record its GitHub artifact
   ID and archive SHA-256. Recompute and compare manifest digests using the
   downloaded bytes and preserved metadata; distinguish an archive digest
   from the digest of the SPDX document itself.
   Run the **read-only** ZIP verifier without extracting the archive:

   ```bash
   python3 verification/provenance/verify_artifact.py \
     --artifact /path/to/downloaded-artifact.zip \
     --archive-sha256 EXPECTED_64_HEX_SHA256 \
     --commit EXACT_40_HEX_EVIDENCE_COMMIT
   ```

   Obtain `EXPECTED_64_HEX_SHA256` from the GitHub Actions artifact metadata
   for the chosen run, independently of the downloaded ZIP. Obtain the evidence
   commit from `evidence.json`, then independently bind it to the workflow
   checkout SHA; it may differ from the PR head SHA. The verifier
   rejects unexpected entries, duplicate names, oversized entries, digest
   mismatches and inconsistencies between Cargo metadata and SPDX content.
5. Confirm the evidence contains `signed: false` and
   `release_authorized: false`. Any claim of signature, authenticity, or
   production authority requires a different, separately governed process.
6. Review the historical failure and subsequent correction rather than
   treating earlier failed CI as if it never happened.
7. Record the human reviewer identity, observations, dissent, and decision
   through the existing GO-13 path. **Do not infer approval from this guide,
   CI success, a PR comment, or AI triad commentary.**

### AI review lenses (advisory only)

- **TRIAS:** Scope remains evidence-only; no automatic merge or activation.
- **ORACLE:** Identify exact head/run/artifact and missing trusted provenance.
- **MENTOR:** Keep the reproduction instructions and failure history usable
  for the appointed human maintainer.

Status model: `CANDIDATE` → `CI EVIDENCE COLLECTED` → `HUMAN REVIEW PENDING`.
Merge, release and production remain **HOLD** until separately authorized.
