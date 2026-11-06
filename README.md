# palaco-genesis

PALACO Genesis is the Rust workspace baseline for the PALACO platform.

## Repository layout

## Repository bootstrap roadmap

De specificatie voor de GitHub repository-bootstrap is vastgelegd in
[`docs/pri-045-github-repository-bootstrap.md`](docs/pri-045-github-repository-bootstrap.md).

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

## CI Workflows

- `ci.yml` — standaard validatie op push/PR
- `benchmark.yml` — benchmark target validatie
- `security.yml` — dependency audit + cargo-deny policy checks
- `coverage.yml` — coverage artefact generatie
- `release.yml` — release-readiness, binary build (`palaco-citadel-contracts`), checksum/manifest generatie en optionele GitHub release-publicatie
- `document-exchange.yml` — validatie van relatieve documentatielinks
- `pages.yml` — GitHub Pages deployment (optioneel met custom domain via `PAGES_CUSTOM_DOMAIN`)
- `metrics.yml` — dependency metrics vergelijking met artifact output
- `baseline-metrics.yml` — periodieke baseline + metrics report artifact generatie
- `automation-integrity.yml` — valideert workflow YAML via `.github/scripts/validate-workflows.py`, dwingt permissions/concurrency-group/timeout/runner/checkout-security policy af (workflow root alleen met toegestane top-level keys `name`, `on`, `permissions`, `concurrency`, `jobs`, `env`, `defaults`; verplichte niet-lege én unieke workflow `name`, verplichte niet-lege top-level `on` triggerdefinitie met alleen toegestane triggers (`workflow_dispatch`, `push`, `pull_request`, `schedule`) en bij lijstvorm alleen unieke niet-lege strings, `schedule` alleen als niet-lege lijst met unieke `cron`-only mappings en geldige `cron` waarden (exact 5 velden), `workflow_dispatch` alleen als mapping (`{}` of met `inputs`) met alleen toegestane trigger-key `inputs` en met gevalideerde input-schema’s (alleen toegestane keys `description`/`required`/`default`/`type`/`options`, input-namen volgens `^[A-Za-z_][A-Za-z0-9_-]*$`, geldige `type`, boolean `required`, `default` als type-consistente scalar en niet-lege string waar van toepassing, en `choice.options` als unieke niet-lege strings, alleen bij `type: choice` met default uit options), `push`/`pull_request` alleen als mapping met alleen toegestane trigger-keys en expliciete `branches` incl. `main` of `master`, waarbij alle ingestelde filterlijsten (`branches`, `branches-ignore`, `tags`, `tags-ignore`, `paths`, `paths-ignore`, `types`) niet-lege lijsten van unieke niet-lege strings moeten zijn, exclusieve filterparen (`branches`/`branches-ignore`, `paths`/`paths-ignore`, `tags`/`tags-ignore`) niet samen mogen voorkomen, en `pull_request.types` alleen toegestane PR events mag bevatten, `concurrency` alleen als mapping met keys `group`/`cancel-in-progress` waarvan `group` een niet-lege string moet zijn en `cancel-in-progress` verplicht `true` is, `env` op workflow/job/step als mapping met niet-lege string keys en string values wanneer gezet (en in `release.yml` verplicht `env.CARGO_TERM_COLOR: always`), `defaults` op workflow/job alleen met key `run` en `defaults.run` alleen met keys `shell`/`working-directory` als niet-lege strings wanneer gezet, `if` op job/step als niet-lege string wanneer gezet, jobs keys moeten niet-lege strings zijn en job-ID’s moeten matchen met `^[A-Za-z_][A-Za-z0-9_-]*$`, jobs mogen alleen toegestane job-keys gebruiken (`name`, `runs-on`, `steps`, `timeout-minutes`, `needs`, `if`, `permissions`, `strategy`, `env`, `defaults`, `continue-on-error`, `environment`), `job.environment` moet (indien gezet) een niet-lege string of mapping met alleen `name`/`url` zijn (waarbij `name` verplicht niet-leeg is), `needs` op jobs alleen als niet-lege string of niet-lege lijst van unieke niet-lege strings zonder self-dependency én met bestaande job-referenties, `strategy` op jobs als mapping met alleen `fail-fast`/`max-parallel`/`matrix`, waarbij `fail-fast` boolean is, `max-parallel` een positieve integer, `matrix` een niet-lege mapping, matrix-dimensies (behalve `include`/`exclude`) niet-lege lijsten met geldige scalarwaarden (string/number/boolean) moeten zijn, en `matrix.include`/`matrix.exclude` (wanneer gezet) niet-lege lijsten van niet-lege mappings met niet-lege string-keys en scalarwaarden zijn, `steps` moet een niet-lege lijst zijn, elke step moet een mapping zijn en alleen toegestane step-keys gebruiken (`name`, `id`, `if`, `continue-on-error`, `uses`, `run`, `with`, `env`, `working-directory`, `shell`), step `id` moet (indien gezet) matchen met `^[A-Za-z_][A-Za-z0-9_-]*$` en uniek zijn binnen de job, step `shell` moet (indien gezet) een niet-lege string zijn en alleen op `run`-steps staan, step `with` als mapping met niet-lege string-keys en scalarwaarden wanneer gezet en alleen op `uses`-steps, verplichte niet-lege én unieke job `name` per workflow, verplichte niet-lege én unieke step `name` per job, elke step precies één van `run`/`uses` met niet-lege stringwaarden, `working-directory` op steps als niet-lege string wanneer gezet en alleen op `run`-steps, `continue-on-error` op job/step alleen als boolean en nooit `true`, least-privilege permissions incl. release-uitzondering (top-level `permissions` als mapping met niet-lege string-keys en niet-lege string-values (`read`/`write`/`none`); job `build-binaries` moet exact `needs: release-readiness` zetten en job `publish-release` moet expliciet alleen `permissions.contents: write` zetten, exact `needs: build-binaries` zetten, een `if`-guard met `github.event.inputs.release_tag` bevatten die expliciet `github.event.inputs.release_tag != ''` bevat (spaties toegestaan), en `release.yml` moet jobs `build-binaries` en `publish-release` bevatten plus als enige trigger verplichte `workflow_dispatch` met uitsluitend input `release_tag` (`type: string`, `required: false`, zonder `default`)), `runs-on: ubuntu-latest`, integer timeouts verplicht en max 60 min (en in `release.yml` exact 30 per job), checkout zonder persisted credentials op `actions/checkout@v4`, externe `uses` met expliciete `@ref`, geen floating action refs zoals `@main`/`@master`, geen `pull_request_target` trigger), en controleert shell- én Python-scriptsyntax (bash -n, shellcheck, py_compile)
- `workflow-lint.yml` — lint alle GitHub workflow-definities met actionlint
- `palaco-ci.yml` — uitgebreide PALACO baseline pipeline
- `citadel-a1.yml` — Citadel A1 contractverificatie
- `registry-contract.yml` — registry contract checks

## GitHub Pages + custom domain

De `pages.yml` workflow publiceert `docs/` naar GitHub Pages en maakt een optionele `CNAME` aan op basis van:
- `workflow_dispatch` input `custom_domain` (als gezet), anders
- repository variable `PAGES_CUSTOM_DOMAIN`.

### Setup

1. Zet in GitHub bij **Settings → Pages** de source op **GitHub Actions**.
2. (Optioneel) Voeg repository variable `PAGES_CUSTOM_DOMAIN` toe met je domeinnaam.
3. (Optioneel) Overschrijf voor één handmatige run via workflow input `custom_domain`.
4. Trigger `pages.yml` via **Run workflow** of push naar `main`/`master`.

## CI metrics

De `metrics.yml` workflow draait `.github/scripts/compare-metrics.sh` en publiceert `metrics/metrics-report.md` als artifact.
