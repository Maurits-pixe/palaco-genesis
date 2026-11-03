# ORCH-047 — Recovery intent receipt and approval boundary

Status **DRAFT / HOLD**. Extends ORCH-046 #213 without changing its evidence.

## Contract

A caller may record an operator's stated choice: defer, reject, or request that a separately authorized reviewer assess quarantine of a matching *pending-only* marker.

The domain-separated SHA-256 statement binds candidate sequence, observation classification, intent, opaque actor reference and caller nonce. It is **not** an authenticated signature, trusted time receipt, proof of human presence, replay-resistant ledger or verified approval.

No filesystem API exists in the module. The resulting `execution_allowed` is always false. RequestQuarantineReview does **not** quarantine, delete, rename or activate a file.

## Denial rules

- No request for quarantine on mismatching evidence, unknown evidence, invalid inspection, no pending marker, or pending-plus-published.
- Reject any review with an execution flag already set.
- Reject zero sequence, blank actor reference or blank nonce.
- No decision can bypass independent actor authentication, nonce replay controls, fresh inspection, publisher signature verification, trusted time, race-safe filesystem implementation and the competent human approval gate.

## Test and trust limit

Five isolated Rust tests target deterministic statement binding and denial cases. A successful CI run proves only this pure code at its exact revision. Power-cut operation, multi-week offline persistence, encrypted private memory and cryptographically bound human approval remain unimplemented.

AI review lenses: TRIAS keeps recovery execution HOLD; ORACLE treats the receipt as unauthenticated evidence; MENTOR recommends the next independent boundary: a separately testable authenticated approval verifier, without enabling mutation.
