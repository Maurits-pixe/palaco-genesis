# ORCH-048 — Offline recovery approval verification preflight

Status: **DRAFT / HOLD / REVIEW ONLY**. Stacked on ORCH-047 (#214).

## Boundary

Requires a typed verification interface for authenticated operator approval plus a separately implemented durable nonce-replay checker. Default implementation denies both. Trusted monotone time and minimum publisher/governance policy epoch must come from an independently trusted caller.

A passing fixture produces only `ReadyForSeparateHumanReview`; no filesystem operation, durable nonce reservation, authority delegation or active generation promotion exists.

## Important missing guarantees

There is **no production signature verifier** (the trait does not carry signature bytes), no key registry or revocation integration, no monotone trusted clock implementation and no atomic persistent nonce reservation. The `FixtureVerifier` in unit tests must never be shipped as trust evidence. Consequently this cannot be treated as an approval gate for execution, only as an interface preflight specification.

All real recovery execution remains HOLD until independent review and a distinct implementation that verifies signed bytes, binds trusted policy, consumes replay nonces atomically and rechecks the exact on-disk marker.

Five tests cover default denial, missing/expired time, stale epoch/replay rejection, forbidden execution flag/intent, and a fixture-only review result.

TRIAS: no grant or filesystem authority. ORACLE: mock success is not cryptographic verification. MENTOR: implement signature-byte binding and durable replay ledger as new reviewed candidates before considering any executor.
