# ORCH-030 — Trusted Identity Verification Gate

**Status:** DRAFT contract candidate  
**Authority:** None. This specification does not enable authentication, issue a grant, merge, deploy, or authorize execution.  
**Dependency:** ORCH-029 actor/grant consistency contract (PR #194); ORCH-028 disposition integrity (PR #193). Both remain independently reviewable.

## Problem

ORCH-029 compares the declared actor with the subject recorded in an AuthorizationGrant. Equality does not authenticate the actor. The existing ExecutionBoundary constructor builds a default empty IdentityHandle. The runtime must never interpret a caller-supplied identity string or a structurally valid grant as proof of authentication.

## Trust boundary

A future adapter must verify an identity credential with an explicitly configured trusted authority. ORCHEASTRA consumes only a resulting, proof-bound attestation after independent validation of the adapter and provider configuration. The default behavior without a configured and verified adapter is **HOLD**.

No implementation is allowed to derive trusted status from:
- a client-supplied boolean such as `authenticated: true`;
- an unverified JWT payload or its `sub` claim;
- the equality of two identity strings;
- a cached authentication outcome with unknown expiry or revocation state;
- CI success, ORCH-028 validation, or ORCH-029 consistency alone.

## Proposed verification input

- `actor`: stable subject and acting surface;
- `credential_ref`: opaque reference, never plaintext credential in logs;
- `issuer` and `audience`: explicit trusted configuration identifiers;
- `authenticated_at`, `not_after`, `observed_at`: trusted temporal evidence;
- `authentication_event_id`: replay-detectable provenance identifier;
- `provider_policy_revision`: immutable reference to accepted policy;
- `revocation_epoch`: trusted monotonic revocation marker;
- `decision_context`: PALACO state snapshot and policy version.

The attestation must bind all fields and the exact requested action context; its digest must be independently reproducible.

## Decision outcomes

- `VERIFIED`: provider proof, actor, audience, freshness, policy and revocation checks all succeed. This is **identity verification only**, not execution authorization.
- `DENIED`: a mandatory claim is demonstrably invalid, mismatched or revoked.
- `HOLD`: provider, trusted time, required evidence, policy, revocation state, or verifier is unavailable.
- `INCONCLUSIVE`: evidence is present but conflicting or unverifiable.

The operational execution gate requires, independently:

`identity VERIFIED + actor/grant binding PASS + scope PASS + TRIAS authorization current + revocation check PASS + kernel revalidation PASS`.

Anything else remains in SafeState.

## Offline behavior

An offline client may display a previously verified subject label, but may not mint, refresh or extend authentication authority. Offline mutating execution remains HOLD unless a separately approved, bounded offline capability with trusted time and monotonic revocation evidence is implemented and independently reviewed. Clock rollback or restored snapshots must never revive expired or revoked credentials.

## Negative acceptance matrix

| ID | Scenario | Required result |
| --- | --- | --- |
| ORCH030-N01 | No trusted provider configured | HOLD |
| ORCH030-N02 | Self-asserted actor without credential proof | HOLD |
| ORCH030-N03 | Invalid signature / tampered credential | DENIED |
| ORCH030-N04 | Wrong issuer or audience | DENIED |
| ORCH030-N05 | Actor differs from proof subject | DENIED |
| ORCH030-N06 | Credential expired or not yet valid | DENIED/HOLD |
| ORCH030-N07 | Credential revoked or revocation epoch stale | DENIED/HOLD |
| ORCH030-N08 | Clock rollback / no trusted time | HOLD |
| ORCH030-N09 | Replay of consumed authentication event | DENIED |
| ORCH030-N10 | Restored old snapshot | HOLD |
| ORCH030-N11 | Provider unavailable | HOLD |
| ORCH030-N12 | Valid identity but insufficient grant scope | DENIED at execution gate |
| ORCH030-N13 | Valid identity but missing TRIAS decision | HOLD at execution gate |
| ORCH030-N14 | Valid identity but changed state/policy revision | HOLD pending revalidation |

## Engineering sequencing

1. Select the canonical identity authority and credential type through a separate governance decision.
2. Define a verifier adapter with explicit trust-store, issuer, audience, time and revocation inputs.
3. Implement the negative matrix and immutable evidence receipts.
4. Integrate ORCH-029 only after adapter verification and explicit trusted context binding.
5. Integrate the runtime/kernel execution gate separately, with crash recovery, concurrency and offline tests.
6. Require exact-commit CI evidence, independent security review and human release authority.

## Current release gate

`ORCH-030 = DESIGN_DRAFT / PROVIDER_UNSELECTED / NO_RUNTIME_AUTHORITY / HOLD`.
