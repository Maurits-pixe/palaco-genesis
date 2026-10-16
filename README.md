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

### Werken in Visual Studio Code

Open de **rootmap** van je lokale clone via **File → Open Folder** (of `code .`
vanuit die map). Installeer Rust met rustup en zorg dat `cargo` in je PATH staat;
de bestaande `rust-toolchain.toml` selecteert stable, rustfmt en Clippy.
Herstart VS Code na het installeren van de toolchain indien nodig.

De workspace beveelt **rust-analyzer** en **GitHub Pull Requests** aan via
Extensions → `@recommended`. Installatie vereist je eigen bevestiging.
Rust-bestanden gebruiken rust-analyzer voor opmaak bij opslaan en Clippy voor
editorcontroles. Gegenereerde mappen worden uitgesloten van zoeken en watching.

Gebruik **Terminal → Run Task**:

| Taak | Doel |
| --- | --- |
| `PALACO: build` | Workspace bouwen met het lockbestand; standaard buildtaak |
| `PALACO: format check` | Opmaak controleren zonder bestanden te wijzigen |
| `PALACO: clippy` | Alle targets linten; warnings zijn fouten |
| `PALACO: test` | Workspace-tests; standaard testtaak |
| `PALACO: validate` | Format, Clippy, tests en build achtereenvolgens uitvoeren |

De taken werken vanuit de geopende rootmap op Windows, macOS en Linux en
vereisen geen Bash. Ze worden niet automatisch bij het openen uitgevoerd.
Vertrouw de workspace alleen nadat je de repository hebt gecontroleerd.
Er is geen start-/debugconfiguratie voor de nog ontbrekende NEO-, AETHER- en
BASTION-applicaties.

Voor GitHub-review of optioneel GitHub Copilot meld je jezelf in VS Code aan
met een GitHub-account met de benodigde toegang. Een Microsoft-aanmelding voor
Settings Sync koppelt deze cloudsessie niet aan je editor. Deze configuratie
meldt niemand aan en bevat geen accounts, tokens of lokale absolute paden.

Bijdragen: houd wijzigingen gericht, voeg tests toe voor gewijzigd gedrag en
voer bovenstaande controles uit voordat je een pull request indient.
Bewaar gedeelde Rust-domeinlogica in `crates/`; plaats applicatieassemblage in
`apps/` en `services/`.

### Bijdragen en review

1. Bespreek grotere wijzigingen eerst in een issue. Gebruik de bug- en
   featureformulieren; meld beveiligingsproblemen niet publiek.
2. Werk op een eigen branch of fork. Houd wijzigingen en bijbehorende tests
   bij elkaar en wijzig geen ongerelateerde onderdelen.
3. Voer de validatie hierboven uit. Gebruik daarnaast
   `cargo build --workspace --locked` voor een build met de vastgelegde dependencies.
4. Controleer je diff op secrets, persoonsgegevens en gegenereerde bestanden.
   `.gitignore` verwijdert geen eerder getrackte bestanden of Git-geschiedenis.
5. Beschrijf in je pull request wat verandert, welke controles zijn uitgevoerd
   en welke beperkingen blijven bestaan. Een maintainer beoordeelt de wijziging;
   bijdragen worden niet automatisch samengevoegd.

Houd communicatie respectvol en technisch onderbouwd. Maak duidelijk onderscheid
tussen ontwerp, referentie-implementatie en bewezen productiegedrag.

## 🔒 Veiligheid & D-013

Het [D-013-ontwerpcontract](docs/D-013-PROTOCOL.md) vereist server-side
tijdsvalidatie en atomaire mutaties. De huidige Rust-contracten zijn geen bewijs
dat de toekomstige BASTION-service dit protocol al afdwingt.

### Een kwetsbaarheid melden

Deze alpha biedt geen productiebeveiligingsgarantie of afgesproken responstijd.
Gebruik geen echte sleutels, financiële gegevens of andere gevoelige data in
demonstraties.

Meld mogelijke kwetsbaarheden **niet** in publieke issues of pull requests.
Gebruik op GitHub de tab **Security → Report a vulnerability** als private
vulnerability reporting is ingeschakeld. Ontbreekt die optie, vraag dan via een
issue uitsluitend om een privé-meldkanaal, zonder technische details, logs,
exploitcode of gevoelige gegevens. Wacht op dat kanaal voordat je details deelt.

Een privémelding bevat bij voorkeur de betrokken commit, impact, minimale
reproductiestappen met fictieve gegevens en een mogelijke oplossing. Bij
gelekte credentials: trek ze onmiddellijk in of roteer ze; alleen het bestand
verwijderen is niet voldoende.

## 📄 Licentie en publicatie

Zie [LICENSE](LICENSE) voor de MIT-licentie. Bestaande Rust-packagemetadata
declareert `MIT OR Apache-2.0` en is ongewijzigd.

Publicatie-instellingen worden niet door deze bestanden gewijzigd. Controleer
voor een publieke release de repositoryzichtbaarheid, licenties, secrets en
implementatiestatus. Voeg desgewenst topics `rust`, `cybersecurity`, `vue`,
`nodejs`, `encryption`, `monorepo` en `d-013` toe en pin de repository op je profiel.
Publiceer `v1.0.0 - Genesis` pas nadat de beschreven applicaties en
veiligheidsclaims aantoonbaar werken.

### Publicatiechecklist voor de maintainer

Dit is een voorbereiding, geen bewijs dat de onderstaande GitHub-instellingen
al zijn ingeschakeld.

- [ ] Controleer rechten en herkomst van alle code en documenten. Los vóór
  publicatie de licentiepresentatie op: de root bevat nu alleen de MIT-tekst,
  terwijl Rust-packages `MIT OR Apache-2.0` declareren. Bevestig met de
  rechthebbenden de bedoelde licenties en voeg zo nodig de bijbehorende teksten
  toe; verander bestaande licenties niet stilzwijgend.
- [ ] Controleer de volledige te publiceren Git-geschiedenis, branches, tags,
  artifacts en voorbeelddata op secrets, persoonsgegevens en materiaal dat
  niet openbaar mag worden. Roteer gevonden credentials vóór publicatie.
- [ ] Controleer GitHub Actions op de exacte releasecommit en voer alle
  relevante tests uit. Een lokale geslaagde build bewijst niet dat CI groen is.
- [ ] Activeer private vulnerability reporting en, waar beschikbaar,
  dependency alerts, secret scanning en push protection in de
  beveiligingsinstellingen van GitHub.
- [ ] Stel een ruleset in voor de standaardbranch: pull-requestreview,
  geslaagde vereiste statuschecks en blokkeren van force-pushes/verwijdering.
  Selecteer checknamen uit echte workflowruns; de twee Rust-workflows hebben
  verschillende validatiejobs.
- [ ] Controleer repositorynaam, beschrijving, topics en standaardbranch.
  Wijzig de zichtbaarheid alleen na expliciete goedkeuring en bovenstaande
  controles; deze wijziging maakt de repository niet openbaar.
- [ ] Kies een prereleaseversie die overeenkomt met de packagemetadata
  (momenteel `0.1.0-alpha.1`). Controleer bestaande tags en releases voordat
  een nieuwe, onveranderlijke tag op de beoordeelde commit wordt gemaakt.
- [ ] Maak eerst een conceptrelease met samenvatting, exacte commit,
  uitgevoerde controles, bekende beperkingen en upgrade-instructies.
  Markeer een alpha als **prerelease**, niet als stabiele `v1.0.0`.
- [ ] Laat een maintainer het concept beoordelen en publiceer het daarna
  handmatig. Publiceer geen binaries of packages die niet afzonderlijk
  zijn gebouwd, getest en gecontroleerd.

NEO, AETHER en BASTION blijven bij deze voorbereiding placeholders.
Een eventuele alpha-release betreft de aanwezige Rust-workspace en
ontwerpdocumentatie, niet een werkend cryptografisch commandoplatform.
