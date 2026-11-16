# ORCHEASTRA — admission gate v0.1

Status: **DRAFT / HOLD**. This package does not authorize, schedule, or execute operations.

## Placement

The module `palaco_runtime::orcheastra` is a pure, offline-capable admission
assessment. It is not a replacement for PALACO One identity verification,
TRIAS authority, evidence provenance, Citadel execution boundaries, or the
runtime revalidation step.

## Decision contract

- `ObserveOnly`: authenticated read-only inspection, with no mutation authority.
- `Proposed`: a proposed mutation has met all supplied gate signals,
  **not** a command to execute it.
- `Blocked(reason)`: mutation is forbidden; the reason is reportable to audit.

Precedence: revocation > HOLD > identity > operation-specific requirements.
Mutation requires *all* of: verified identity, verified authority,
verified evidence, scope match, current state/policy, and explicit Citadel
execution disposition. The upstream caller must substantiate these signals
with verified artifacts; booleans alone are **not** security proof.

## Integration sequence (not yet wired)

1. Verify signed identity, scoped authorization and evidence in their
   respective trust domains.
2. Check revocation and GO-13 / environment HOLD from the authoritative source.
3. Revalidate policy/state snapshot and the Citadel boundary.
4. Pass the resulting verified signals to `evaluate_admission`.
5. Log the decision, policy version and evidence references in PALACO Audit.
6. Only after a separate last-moment runtime revalidation may an executor act.

No caller is permitted to interpret `Proposed` as a capability token.
Network calls, issuance, signing, deployment and repository merges remain
outside this module.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p palaco-runtime
cargo test --workspace
```

The PR remains draft until these commands pass in CI and human review
approves the trust-boundary integration.

## Runtime-bound proposal adapter (v0.2 candidate)

The `evaluate_runtime_proposal(plan, context, claims)` adapter consumes the
existing `RuntimePlan` instead of trusting caller-supplied Citadel/context
flags alone. It verifies the original policy and state identifiers, rejects
backdated observations, checks current validity, and calls `revalidate`.

Both externally verified claims and runtime-derived checks must succeed.
The adapter still returns only `Proposed`; it does not invoke the in-memory
Citadel commit gate, issue tokens, perform IO or authorize real operations.

New regression coverage includes: valid proposal, active HOLD,
non-executable governance scope, mismatched state snapshot and expired
validity window. CI execution and independent review are still required.
