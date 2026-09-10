# palaco-genesis

PALACO Genesis is the Rust workspace baseline for the PALACO platform.

## Repository layout

```text
.
├── .github/workflows/        # CI workflows
├── crates/                   # Rust workspace crates
│   ├── palaco-foundation/    # Constitutional foundation layer
│   ├── palaco-eventbus/      # Event transport boundary
│   ├── palaco-harbor/        # Intake and ingress layer
│   ├── palaco-quay/          # Coordination boundary
│   ├── palaco-citadel/       # Execution boundary layer
│   ├── palaco-federation/    # Federated domain contracts
│   ├── palaco-intelligence/  # Intelligence domain contracts
│   ├── palaco-evolution/     # Evolution domain contracts
│   ├── palaco-types/         # Foundational shared types
│   ├── palaco-errors/        # Shared error contracts
│   ├── palaco-events/        # Domain event contracts
│   ├── palaco-evidence/      # Evidence chain contracts
│   ├── palaco-oracle/        # Analysis and advisory layer
│   ├── palaco-trias/         # Governance and authority layer
│   ├── palaco-knowledge/     # Versioned knowledge contracts
│   ├── palaco-runtime/       # Runtime orchestration contracts
│   ├── palaco-audit/         # Audit trail layer
│   └── palaco-observatory/   # Observability and reporting layer
├── runtime/
│   └── palaco-kernel/        # Runtime kernel crate
├── docs/
│   ├── architecture/
│   ├── books/
│   ├── foundation/
│   └── reference/
├── Cargo.toml
└── rust-toolchain.toml
```

## Validation

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
