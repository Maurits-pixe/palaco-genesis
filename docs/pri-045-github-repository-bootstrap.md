# PRI-045 — GitHub Repository Bootstrap

*Document ID:* PRI-045  
*Status:* Ready for Implementation

Met PRI-045 verschuift PALACO van een verzameling specificaties naar een *direct bouwbare repository*. Het doel is dat een nieuwe ontwikkelaar de repository kan klonen en met enkele standaardcommando's een reproduceerbare build kan uitvoeren.

---

## Doel

De repository moet:

* reproduceerbaar zijn;
* direct compileerbaar zijn;
* CI/CD-ready zijn;
* governance ondersteunen;
* uitbreidbaar blijven voor toekomstige crates.

---

## Repositorystructuur

```text
palaco/
│
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── LICENSE
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── GOVERNANCE.md
├── ROADMAP.md
├── ARCHITECTURE.md
├── RELEASE.md
│
├── .cargo/
│   └── config.toml
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── security.yml
│   │   ├── benchmark.yml
│   │   ├── release.yml
│   │   └── evidence.yml
│   │
│   ├── ISSUE_TEMPLATE/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── CODEOWNERS
│
├── crates/
├── runtime/
├── docs/
├── specs/
├── engine/
├── services/
├── apps/
├── database/
├── verification/
└── tests/
```

---

## Workspacecontract

Alle crates vallen onder één centrale workspace.

```text
Workspace

↓

Kernel

↓

Runtime

↓

Storage

↓

EventBus

↓

Consensus

↓

Security

↓

CLI

↓

Bench

↓

SDK
```

Hiermee ontstaat een heldere afhankelijkheidsstructuur waarin hogere lagen afhankelijk zijn van stabiele fundamenten.

---

## Eerste ontwikkelervaring

Een nieuwe ontwikkelaar zou met de volgende standaardstappen aan de slag moeten kunnen:

```bash
git clone ...

cargo build
cargo test
cargo fmt --check
cargo clippy --workspace
cargo bench
```

Een belangrijk doel van PRI-045 is dat deze opdrachten zonder handmatige configuratie uitvoerbaar zijn.

---

## GitHub Governance

De repository bevat onder meer:

* CODEOWNERS
* SECURITY.md
* CONTRIBUTING.md
* issue templates
* pull request template
* release policy

Zo wordt niet alleen de code, maar ook de ontwikkelworkflow gestandaardiseerd.

---

## CI/CD-baseline

Elke pull request doorloopt dezelfde keten:

```text
Formatting
    │
Linting
    │
Compilation
    │
Unit Tests
    │
Integration Tests
    │
Security Scan
    │
Benchmarks
    │
Evidence Generation
    │
Release Candidate
```

Deze sluit aan op de eerder gedefinieerde release gates en het Release Evidence Package.

---

## Acceptatiecriteria

PRI-045 is afgerond wanneer:

| Onderdeel                        | Doel |
| -------------------------------- | ---- |
| Workspace initialiseert          | ✅   |
| Alle crates bouwen               | ✅   |
| GitHub Actions starten succesvol | ✅   |
| Basisdocumentatie aanwezig       | ✅   |
| Governancebestanden aanwezig     | ✅   |
| Releaseworkflow voorbereid       | ✅   |

---

## Route na PRI-045

Na het repository-bootstrap is de focus niet langer de architectuur, maar de *referentie-implementatie*. Een logische implementatiereeks is:

| PRI     | Onderwerp                                                                                  |
| ------- | ------------------------------------------------------------------------------------------ |
| PRI-046 | Consensus Engine (werkende implementatie van leader election, log replication en quorum)   |
| PRI-047 | Distributed Storage Integration (consensus koppelen aan palaco-storage)                    |
| PRI-048 | Cluster Simulator & Chaos Framework (reproduceerbare multi-node tests)                     |
| PRI-049 | End-to-End Validation & Evidence Automation (volledige releaseketen)                       |
| PRI-050 | Core v2.0 Reference Release Candidate (eerste complete, bouwbare referentieversie)         |

### Advies voor de volgende fase

Tot nu toe ligt de nadruk sterk op architectuur, documentatie en governance. Dat is een solide basis. De grootste waarde ontstaat nu door de referentie-implementatie daadwerkelijk bouwbaar te maken.
