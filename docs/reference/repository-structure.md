# Repository structure

This repository follows a standard Rust workspace layout.

## Principles

- Keep all Rust crates under `crates/`.
- Keep canonical specifications under `specs/`.
- Keep CI configuration under `.github/workflows/`.
- Keep long-form governance and architectural material under `docs/`.
- Order workspace members from the PALACO foundation layer through runtime-facing crates.
- Use top-level `engine/`, `services/`, `apps/`, `database/`, and `verification/` directories for repository assembly boundaries.

## Workspace layers

### Genesis foundation
- `palaco-foundation`
- `palaco-eventbus`
- `palaco-harbor`
- `palaco-quay`
- `palaco-federation`
- `palaco-intelligence`
- `palaco-evolution`

### Shared contracts
- `palaco-constitution`
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
- `palaco-rio-core`
- `palaco-kernel`

## Canonical assembly

- `specs/` — canonical PALACO specifications
- `engine/` — ENGINE COMPLEET assembly layout
- `services/` — service boundary layout
- `apps/` — user-facing surface layout
- `database/` — data and persistence layout
- `verification/` — verification and evidence layout
