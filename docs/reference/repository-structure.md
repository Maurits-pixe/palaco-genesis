# Repository structure

This repository follows a standard Rust workspace layout.

## Principles

- Keep all Rust crates under `crates/`.
- Keep CI configuration under `.github/workflows/`.
- Keep long-form governance and architectural material under `docs/`.
- Order workspace members from the PALACO foundation layer through runtime-facing crates.

## Workspace layers

### Genesis foundation
- `palaco-foundation`
- `palaco-eventbus`
- `palaco-harbor`
- `palaco-quay`
- `palaco-citadel`
- `palaco-federation`
- `palaco-intelligence`
- `palaco-evolution`

### Shared contracts
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
