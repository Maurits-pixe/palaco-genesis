# ORCHEASTRA — exact stacked PR ancestry and governance state (DRAFT)

Date: 2026-11-10. Repository: `Maurits-pixe/palaco-genesis`.
Evidence source: current GitHub pull request metadata queried for every PR below.
Decision: **GO-13 HOLD / authorization DENY**.

## Verified linear base/head continuity

The following PR order was read from GitHub:

`#229 → #231 → #232 → #235 → #236 → #237 → #238 → #239 → #240 → #241 → #242 → #243 → #244 → #245 → #246 → #247 → #248`.

- Every one of these **17** PRs was OPEN and `merged: false`.
- For all **16** consecutive edges, the next PR `base` branch equals the
  preceding PR `head` branch, and its `base_sha` equals the preceding
  PR `head_sha`: **PASS for exact observed metadata continuity**.
- The first PR #229 targets `main` at
  `6ca294d2f6361a60b353e7bdf335886c5c616fd3`.
- The final PR #248 targets #247's branch at
  `ec9c726763e383790b3faef96b68f254a481d9a7` and has head
  `2cbd79d937a7c932b1c44a2d16bea81809bc07a9`.
- This confirms reported branch/commit alignment at observation time, **not**
  cryptographic ancestry, mergeability, combined diff review, or a durable
  frozen reference. Recheck before human decision.

## Governance exception — PR #235

- PR #235 `codex/orchestrator-resolve-node-coverage-20261109` was
  `state: open`, `merged: false`, but **`draft: false`**.
- Its base is #232's branch at
  `8f5907f5d8babac74641c19cf14f90048e4daf54` and head is
  `1b96ab0a42c3b337ca24aac9f82ec3e5f129f0e3`.
- All other 16 PRs were observed `draft: true`.
- Do not infer reviewer approval, permission to merge or change authority
  from the non-DRAFT flag. A human owner/reviewer must either document the
  intentional state with an explicit gate rationale or explicitly authorize
  a separate state correction. This review does **not** change PR #235.

## Three-lens AI review (not independent human review)

- **TRIAS:** intact metadata chain does not supersede GO-13; the non-DRAFT
  exception and unreviewed combined diff preserve HOLD.
- **ORACLE:** the exact branch/SHA equalities were observed from primary
  GitHub metadata. True git ancestry, CI run binding for #248 and independent
  human review remain not established by this check.
- **MENTOR:** keep the historical PRs and evidence intact; provide reviewers
  with this small chain receipt and resolve the #235 governance discrepancy
  before any transition.

**Next permitted action:** independent combined-diff and governance review;
repeat head/base and CI checks at the decision snapshot. No merge, signing,
release, production execution or authority issuance is authorized.
