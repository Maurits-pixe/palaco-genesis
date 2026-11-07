# Repository structure

This repository follows a standard Rust workspace layout.

## Principles

- Keep shared Rust domain crates under `crates/` and the kernel under `runtime/`.
- Keep the standalone AETHER service workspace under `services/aether-engine/`;
  it has its own Cargo lockfile and must be validated separately.
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
- `apps/neo-launcher/`, `apps/aether-frontend/`, `apps/bastion-frontend/` —
  local Vue applications, each with its own npm lockfile
- `services/aether-engine/`, `services/bastion-core/` —
  local Rust cryptography and Node.js command-journal services
- `database/` — data and persistence layout
- `verification/` — verification and evidence layout
