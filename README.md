# palaco-genesis

PALACO Genesis is a Rust monorepo workspace for the PALACO platform.

## Repository layout

```text
.
├── .github/workflows/        # CI workflows
├── crates/                   # Rust workspace crates
│   ├── palaco-types/         # Foundational shared types
│   ├── palaco-errors/        # Shared error contracts
│   ├── palaco-events/        # Domain event contracts
│   ├── palaco-evidence/      # Evidence chain contracts
│   ├── palaco-oracle/        # Analysis and advisory layer
│   ├── palaco-trias/         # Governance and authority layer
│   ├── palaco-knowledge/     # Versioned knowledge contracts
│   ├── palaco-citadel/       # Execution boundary layer
│   ├── palaco-runtime/       # Runtime orchestration layer
│   ├── palaco-audit/         # Audit trail layer
│   └── palaco-observatory/   # Observability and reporting layer
├── docs/
│   ├── architecture/         # Architecture and workspace references
│   ├── books/                # PALACO publication hierarchy
│   ├── foundation/           # Baseline and foundational documents
│   └── reference/            # Repository and contributor references
├── Cargo.toml                # Workspace manifest
└── rust-toolchain.toml       # Rust toolchain pinning
```

## Layering order

The workspace is organized from foundational crates to execution-facing crates:

1. `palaco-types`
2. `palaco-errors`
3. `palaco-events`
4. `palaco-evidence`
5. `palaco-oracle`
6. `palaco-trias`
7. `palaco-knowledge`
8. `palaco-citadel`
9. `palaco-runtime`
10. `palaco-audit`
11. `palaco-observatory`

## Validation

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
```

## Documentation

- `/home/runner/work/palaco-genesis/palaco-genesis/docs/foundation/engineering-baseline-v1.md`
- `/home/runner/work/palaco-genesis/palaco-genesis/docs/architecture/core-workspace-notes.md`
- `/home/runner/work/palaco-genesis/palaco-genesis/docs/reference/repository-structure.md`
