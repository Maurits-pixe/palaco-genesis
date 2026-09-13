# palaco-genesis

PALACO Genesis is a Rust monorepo workspace for the PALACO platform.

## Repository layout

```text
.
├── .github/workflows/        # CI workflows
├── crates/                   # Rust workspace crates
│   ├── palaco-types/         # Foundational shared types
│   ├── palaco-constitution/  # Constitutional identity/authority/provenance rules
│   ├── palaco-errors/        # Shared error contracts
│   ├── palaco-events/        # Domain event contracts
│   ├── palaco-evidence/      # Evidence chain contracts
│   ├── palaco-oracle/        # Analysis and advisory layer
│   ├── palaco-trias/         # Governance and authority layer
│   ├── palaco-knowledge/     # Versioned knowledge contracts
│   ├── palaco-citadel/       # Execution boundary layer
│   ├── palaco-runtime/       # Runtime orchestration layer
│   ├── palaco-audit/         # Audit trail layer
│   ├── palaco-observatory/   # Observability and reporting layer
│   └── palaco-rio-core/      # RIO interaction and orchestration contracts
├── specs/                    # Canonical PALACO specifications
├── engine/                   # ENGINE COMPLEET assembly boundaries
├── services/                 # Service assembly placeholders
├── apps/                     # Surface application placeholders
├── database/                 # Database assembly placeholders
├── verification/             # Verification assembly placeholders
├── docs/
│   ├── architecture/         # Architecture and workspace references
│   ├── books/                # PALACO publication hierarchy
│   ├── foundation/           # Baseline and foundational documents
│   └── reference/            # Repository and contributor references
├── Cargo.toml                # Workspace manifest
└── rust-toolchain.toml       # Rust toolchain pinning
```

## Layering order

The workspace is organized from foundational crates to execution-facing crates, with RIO core layered above the constitutional and execution contracts:

1. `palaco-constitution`
2. `palaco-types`
3. `palaco-errors`
4. `palaco-events`
5. `palaco-evidence`
6. `palaco-oracle`
7. `palaco-trias`
8. `palaco-knowledge`
9. `palaco-citadel`
10. `palaco-runtime`
11. `palaco-audit`
12. `palaco-observatory`
13. `palaco-rio-core`

## Canonical assembly

- `/specs` holds canonical specifications for ENGINE COMPLEET, RIO, MEMORY, IDENTITY, PROVENANCE, AUTHORITY, TRIAS, and PVB-011.
- `/engine`, `/services`, `/apps`, `/database`, and `/verification` reserve the repository assembly that will consume the Rust constitutional core over time.

## Validation

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
```

## Documentation

- `docs/foundation/engineering-baseline-v1.md`
- `docs/architecture/core-workspace-notes.md`
- `docs/reference/repository-structure.md`
