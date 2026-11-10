# ORCHEASTRA PR #266 — trusted-root readiness review (DRAFT)

Date: 2026-11-10 (Europe/Amsterdam). Repository: Maurits-pixe/palaco-genesis.

## Exact review binding

- Upstream: PR #266, base PR #265 head `f7c51c2b8ff14bd5f05c619f8086a9515a61f609`.
- PR #266 head: `5807b5152ea3150d3f80e5e350312a24ea5f566d`.
- Changed file: `verification/provenance/ORCHEASTRA-WINDOWS-TRUSTED-ROOT-CONTRACT-DRAFT.md` only; no executable code was changed.
- PALACO CI run `42855807567`: SUCCESS.
- Citadel A1 interoperability run `42855807483`: SUCCESS.
- PALACO SBOM Evidence Candidate run `42855807651`: SUCCESS.
- Windows native metadata workflow did not run for this documentation-only head. Earlier PR #265 Windows run `42800100273` is evidence for the previous head only.
- No new artifact digest, signature or cryptographic attestation has been independently verified here.

## Implementation decision record — unresolved

A root-contained metadata operation must not silently broaden the current `--metadata` input. Before implementation the responsible caller must define:

1. Which operation supplies the trusted-root capability and how that capability is authorized or revoked.
2. Whether the input is a single relative basename or may contain subdirectories; simpler **basename-only** input is the default security proposal, not canonical policy.
3. Which Windows-native, handle-relative API is approved for refusing all ancestor junctions and reparse components; `CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT)` is insufficient on its own.
4. What the behavior is if the trusted-root capability is absent: preserve old mode only for an explicitly trusted legacy caller, otherwise fail closed.
5. How errors and denied inputs map to CLI exit codes without partial output or misleading PASS/evidence claims.

Do not infer a trusted root from CWD, repository path or environment variables. Do not claim that `Path.resolve`, post-open `GetFinalPathNameByHandleW`, or sequential parent `stat` checks alone prevent a race. Any native API wrapper must have documented ownership and error mapping reviewed before execution.

## Required negative test dossier (NOT EXECUTED on this head)

- Real parent junction outside authorized root rejected.
- Parent symlink even when target is inside root rejected under default policy.
- Parent component replace/swap interleaving does not access external target.
- Malformed paths (UNC, device prefixes, absolute, parent traversal, separators, trailing names) rejected.
- Root revocation/non-directory/missing capability fail closed.
- All native handles released exactly once on every error path.
- Basename normal file, exact 20MiB, 20MiB+1 and Linux regression remain compatible.

These are proposed acceptance cases, **not PASS evidence**.

## Three-lens AI review (not independent reviewers)

- **TRIAS:** Specification stays within DRAFT scope; no root capability has been authorized. GO-13 HOLD, authorization DENY. Proposed implementation transition remains blocked pending caller authority contract.
- **ORACLE:** Three named CI runs passed for PR #266's document head. No new Windows-native execution on that head and no proof of ancestor-junction containment. Security guarantee NOT VERIFIED.
- **MENTOR:** Resolve the basename-versus-subpath interface and responsible trusted-root caller first; only then build the smallest separate implementation candidate and run real Windows junction negatives. Avoid premature native API commitments.

Disposition: REVIEW DRAFT / SPECIFICATION CI PASS / ROOT-CONTAINMENT IMPLEMENTATION BLOCKED / NO MERGE OR RELEASE.
