# PALACO Master Orchestrator — Readiness contract (candidate)

**Status:** DRAFT, no execution or release authority.

The runtime `RuntimePlan::execution_ready(at, context)` and kernel
`KernelCycle::execution_ready(at, context)` are read-only preflight checks.
They do not trigger execution, grant an authorization, persist a decision,
or replace the constitutional admission and execution boundaries.

## Fail-closed semantics

1. Runtime readiness requires current validity `Valid` at the supplied UTC
   timestamp, an exact match with the recorded decision context, and
   constitutional revalidation `Confirmed` for that context.
2. Kernel readiness also requires its local disposition `Execute`; it delegates
   to runtime readiness and cannot override a runtime `SafeState` or `Escalate`.
3. Expired, pending, revoked, insufficient or safe-state validity returns
   `Ok(false)`. Revalidation errors remain explicit `Err(...)` for auditability.
4. A `true` value is *not* an execution capability. Real execution must check
   its authority and state again at the point of use (TOCTOU prevention).

## Evidence before merge

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-features`
- Architecture Validation and relevant provenance/SBOM checks
- Human review under GO-13; no automatic merge or production deployment

The current development container lacks the Rust toolchain; these checks are
pending and no PASS claim is made.
