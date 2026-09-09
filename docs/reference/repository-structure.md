# Repository structure

This repository follows a standard Rust workspace layout.

## Principles

- Keep all Rust crates under `crates/`.
- Keep CI configuration under `.github/workflows/`.
- Keep long-form governance and architectural material under `docs/`.
- Order workspace members from low-level shared contracts to high-level execution and observability crates.

## Workspace layers

### Foundation
- `palaco-types`
- `palaco-errors`
- `palaco-events`
- `palaco-evidence`

### Institutional
- `palaco-oracle`
- `palaco-trias`
- `palaco-knowledge`

### Execution
- `palaco-citadel`
- `palaco-runtime`
- `palaco-audit`
- `palaco-observatory`
