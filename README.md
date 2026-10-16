# 🏛️ PALACO-CITADEL

**Een ecosysteem voor cryptografie en commandovoering, gebouwd op PALACO Genesis.**

Deze monorepo bevat de bestaande Rust-workspace van PALACO Genesis en reserveert
de integratiegrenzen voor NEO, AETHER en BASTION.
**Deze drie applicaties zijn nog niet geïmplementeerd in deze repository.**
Encryptie, moduleverificatie en D-013-conformiteit zijn ontwerpdoelen, geen
productiegaranties. De repository bevindt zich in een alpha-fase.

## 🏗️ Architectuur

- **👁️ NEO:** geplande Vue-launcher die modules controleert via
  `/.well-known/palaco-app.json` en expliciet vertrouwde origins.
- **🔐 AETHER:** geplande Rust-service met `ring` voor AES-256-GCM en
  `rusqlite` voor opslag. Deze dependencies zijn nog niet toegevoegd.
- **🛡️ BASTION:** gepland Node.js/Socket.io-commandocentrum met server-side
  autorisatie en transactionele D-013-mutaties.

Zie [architectuur](docs/ARCHITECTURE.md),
[D-013](docs/D-013-PROTOCOL.md) en de bestaande
[repository-bootstraproadmap](docs/pri-045-github-repository-bootstrap.md).

## 🚀 Quick Start

### Bestaande Rust-workspace

Installeer Rust via rustup; `rust-toolchain.toml` bepaalt de toolchain.

```bash
git clone https://github.com/Maurits-pixe/palaco-genesis.git
cd palaco-genesis
cargo build --workspace
cargo test --workspace
```

### Geplande applicaties

De launchmappen bevatten nu alleen placeholders. Voeg eerst de echte projecten
toe en installeer hun dependencies per map. De Rust-service moet een uitvoerbaar
Cargo-project zijn; elk Node/frontend-project moet een `dev`-script aanbieden.
Gebruik een ondersteunde Node.js-LTS-versie en Bash 4.3+ voor het startscript.

```bash
./scripts/start-all.sh
```

Het script controleert vooraf alle manifests en stopt nu dus met een duidelijke
melding, zonder gedeeltelijk services te starten. Als een gestart proces stopt,
worden ook de overige processen en hun subprocessen beëindigd.

Ngrok is optioneel voor lokale HTTPS-tests zodra de applicaties bestaan.
Configureer dan expliciet vertrouwde HTTPS-origins in NEO en de API-origins in de
frontends. Publiceer geen services met echte gegevens zonder authenticatie.
Commit nooit tokens, privésleutels, lokale databases of `.env`-bestanden.

## 📂 Structuur

```text
apps/
  neo-launcher/       # Gepland: Vue-launcher
  aether-frontend/    # Gepland: crypto-UI
  bastion-frontend/   # Gepland: command-UI
services/
  aether-engine/     # Gepland: uitvoerbare Rust-service
  bastion-core/      # Gepland: Node.js-service
scripts/start-all.sh
docs/ARCHITECTURE.md
docs/D-013-PROTOCOL.md
crates/              # Bestaande Rust-workspacecrates
runtime/             # Bestaande palaco-kernel
specs/               # Canonieke PALACO-specificaties
```

De bestaande `engine/`, `database/`, `verification/`, apps en servicegrenzen
blijven behouden. Zie ook de
[bestaande workspace-indeling](docs/reference/repository-structure.md).

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

Bijdragen: houd wijzigingen gericht, voeg tests toe voor gewijzigd gedrag en
voer bovenstaande controles uit voordat je een pull request indient.
Bewaar gedeelde Rust-domeinlogica in `crates/`; plaats applicatieassemblage in
`apps/` en `services/`.

## 🔒 Veiligheid & D-013

Het [D-013-ontwerpcontract](docs/D-013-PROTOCOL.md) vereist server-side
tijdsvalidatie en atomaire mutaties. De huidige Rust-contracten zijn geen bewijs
dat de toekomstige BASTION-service dit protocol al afdwingt.

## 📄 Licentie en publicatie

Zie [LICENSE](LICENSE) voor de MIT-licentie. Bestaande Rust-packagemetadata
declareert `MIT OR Apache-2.0` en is ongewijzigd.

Publicatie-instellingen worden niet door deze bestanden gewijzigd. Controleer
voor een publieke release de repositoryzichtbaarheid, licenties, secrets en
implementatiestatus. Voeg desgewenst topics `rust`, `cybersecurity`, `vue`,
`nodejs`, `encryption`, `monorepo` en `d-013` toe en pin de repository op je profiel.
Publiceer `v1.0.0 - Genesis` pas nadat de beschreven applicaties en
veiligheidsclaims aantoonbaar werken.
