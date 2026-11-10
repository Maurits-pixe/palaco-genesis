# ORCHEASTRA — GO-13 stacked evidence review (DRAFT)

Date: 2026-11-10. Status: **HOLD**. This is a reviewer handoff,
not human approval, a signed attestation, release authorization, or a merge plan.

## Scope and immutable observations

- Repository: `Maurits-pixe/palaco-genesis`.
- Stacked sequence (base to tip):
  `#229 → #231 → #232 → #235 → #236 → #237 → #238 → #239 → #240 → #241 → #242 → #243 → #244 → #245 → #246`.
- All listed PRs were observed **open and unmerged** on 2026-11-10.
- All were observed **DRAFT except #235**, which was observed open but
  `draft: false`. This is a governance discrepancy for a human reviewer;
  no PR state is changed by this dossier.
- The exact reviewed tip is `#246`, head commit
  `5cbdb4ae2b4fdc8ef6d1be6f98b82630d49bbb09`, based on the #245 branch.
- GitHub Actions on this head: PALACO CI run `42758547717` SUCCESS,
  PALACO SBOM Evidence Candidate run `42758547869` SUCCESS, and
  Citadel A1 interoperability run `42758547926` SUCCESS.
- The complete local provenance unittest suite: **26 methods PASS**.
  These tests do not establish independent human approval.

## Control map

| PR | Control | Review emphasis |
| --- | --- | --- |
| #229 | Deterministic unsigned SPDX inventory | Scope, artifact provenance, non-authority flags |
| #231 | Reference rejection and pinned actions | Unknown IDs, immutable action refs |
| #232 | Mandatory resolve graph | Missing, empty, malformed graph rejection |
| #235 | Complete package-to-node coverage | Duplicates, missing nodes; verify draft-state discrepancy |
| #236 | Detailed/flat dependency agreement | Cargo aliases and dependency kinds |
| #237 | Cargo format-1 and root checks | Real workspace compatibility |
| #238 | ZIP-size/digest validation | Archive entry and resource limits |
| #239 | Duplicate JSON key rejection | Parser ambiguity and reconstruction |
| #240 | Offline end-to-end test | Synthetic fixture is not independent production evidence |
| #241 | Real CI pre-upload ZIP round-trip | Distinguish local ZIP from hosted artifact |
| #242 | CI merge/head SHA visibility | Avoid wrong commit identity during review |
| #243 | Reject non-finite JSON | Strict JSON interoperability |
| #244 | Cargo package/input type checks | Fail-closed malformed metadata |
| #245 | Bound CLI artifact disk read | Reject over-limit before allocation |
| #246 | Reject malformed evidence structures | Top-level, package, relation type validation |

## Independently examined artifact (historical reference)

For #241 workflow run `42754680139`, artifact ID `13734528766`, GitHub's
reported archive SHA-256 was
`3f3488c5b7e4d0b94b00003e267cb7fbd53580361db9fb3c045ae3b1330dc1d5`.
The downloaded ZIP independently matched that digest and the offline verifier
passed with CI merge commit `543922801b0984c8585836271a9de86fe436fac2`.
The PR head `620ad824e10526fad49b5b3ef0e4b29e3dcd9adb` is a different
identity and was correctly rejected as the expected evidence commit.
This artifact belongs to **#241**, not the current #246 head; do not reuse it
as proof of #246's artifact integrity.

## GO-13 review gates still open

1. Verify exact base/head SHA ancestry again immediately before review.
2. Resolve or explicitly record the #235 non-DRAFT state; do not infer
   authorization from its state.
3. Review the combined diff against `main`, including workflow triggers,
   checkout semantics, pinned dependencies, and provenance policy.
4. Download the **#246** artifact, compare its digest with the trusted Actions
   artifact listing, and verify against its recorded CI checkout/merge commit.
5. Record the SPDX validator version, actual CI step evidence, test results,
   and retention/expiry of the new artifact.
6. Obtain independent human review with reviewer identity, dissent, and a
   recorded GO-13 decision. CI PASS does not imply this decision.
7. Signing, merge, release, and production authority remain separately gated.

**Decision: HOLD. Authorization: DENY.**
