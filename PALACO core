# PALACO Core

> *Build with Wisdom. Protect with Trust. Grow with Evidence.*

## 🛡️ Over PALACO
PALACO is een geavanceerd softwareframework gebouwd in de programmeertaal **Rust**, ontworpen met een absolute focus op modulaire integriteit, strenge type-veiligheid en gelaagde beveiligingsarchitectuur.

## ⚙️ Engineering Standaarden
Dit project volgt strikte engineering-gates:
- **Geen `unsafe` code:** Expliciet verboden op workspace-niveau (`unsafe_code = "forbidden"`).
- **Stricte Lints:** `clippy` weigert onbehandelde errors, panics of unwarps (`deny`).
- **Reproduceerbare Builds:** Vastgelegd via Cargo workspaces en geautomatiseerde CI/CD pipelines.

## 🚀 Workspace Structuur
- `crates/palaco-types` — Fundamentele datatypes en primitieven
- `crates/palaco-errors` — Gecentraliseerde foutafhandeling
- `crates/palaco-kernel` — Kernlogica en lifecycle management
- `crates/palaco-eventbus` — Asynchrone en synchrone gebeurtenisdistributie
- `crates/palaco-runtime` — Uitvoeringsomgeving en scheduler

## 🚦 Build & Verificatie
Voer de volgende commando's uit om de workspace lokaal te valideren:
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
