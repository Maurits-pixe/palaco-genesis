# palaco-genesis

PALACO Genesis is the Rust workspace baseline for the PALACO platform.

## Repository layout

## Repository bootstrap roadmap

De specificatie voor de GitHub repository-bootstrap is vastgelegd in
[`docs/pri-045-github-repository-bootstrap.md`](docs/pri-045-github-repository-bootstrap.md).

## Repository Infrastructure

- Content hub: `content/`
- Language hub: `languages/`
- Infrastructure guide: `docs/REPOSITORY_INFRASTRUCTURE.md`

```text
.
├── .github/workflows/        # CI workflows
├── crates/                   # Rust workspace crates
│   ├── palaco-foundation/    # Temporal validity and evidence foundation
│   ├── palaco-eventbus/      # Event transport boundary
│   ├── palaco-harbor/        # Intake and ingress layer
│   ├── palaco-quay/          # Coordination boundary
│   ├── palaco-citadel/       # Execution boundary layer
│   ├── palaco-federation/    # Federated domain contracts
│   ├── palaco-intelligence/  # Intelligence domain contracts
│   ├── palaco-evolution/     # Evolution domain contracts
│   ├── palaco-constitution/  # Constitutional identity/authority/provenance rules
│   ├── palaco-types/         # Foundational shared types
│   ├── palaco-errors/        # Shared error contracts
│   ├── palaco-events/        # Domain event contracts
│   ├── palaco-evidence/      # Evidence chain contracts
│   ├── palaco-oracle/        # Analysis and advisory layer
│   ├── palaco-trias/         # Governance and authority layer
│   ├── palaco-knowledge/     # Versioned knowledge contracts
│   ├── palaco-runtime/       # Runtime orchestration contracts
│   ├── palaco-audit/         # Audit trail layer
│   ├── palaco-observatory/   # Observability and reporting layer
│   └── palaco-rio-core/      # RIO interaction and orchestration contracts
├── runtime/
│   └── palaco-kernel/        # Runtime kernel crate
├── specs/                    # Canonical PALACO specifications
├── engine/                   # ENGINE COMPLEET assembly boundaries
├── services/                 # Service assembly placeholders
├── apps/                     # Surface application placeholders
├── database/                 # Database assembly placeholders
├── verification/             # Verification assembly placeholders
├── docs/
│   ├── architecture/
│   ├── books/
│   ├── foundation/
│   └── reference/
├── Cargo.toml
└── rust-toolchain.toml
```

## Layering order

The workspace is organized from foundational crates to execution-facing crates, with the runtime kernel and RIO core layered above the shared constitutional and runtime contracts:

1. `palaco-foundation`
2. `palaco-constitution`
3. `palaco-types`
4. `palaco-errors`
5. `palaco-events`
6. `palaco-evidence`
7. `palaco-oracle`
8. `palaco-trias`
9. `palaco-knowledge`
10. `palaco-citadel`
11. `palaco-runtime`
12. `palaco-audit`
13. `palaco-observatory`
14. `palaco-rio-core`
15. `palaco-kernel`

## Canonical assembly

- `/specs` holds canonical specifications for ENGINE COMPLEET, RIO, MEMORY, IDENTITY, PROVENANCE, AUTHORITY, TRIAS, and PVB-011.
- `/engine`, `/services`, `/apps`, `/database`, and `/verification` reserve the repository assembly that will consume the Rust constitutional core over time.

## Validation

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
