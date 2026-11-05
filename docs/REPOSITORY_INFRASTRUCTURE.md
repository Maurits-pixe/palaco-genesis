# PALACO Repository Infrastructure

## Doel
Deze repository is ingericht als centrale verzamelpoel voor alle PALACO content en programmeertalen.

## Baseline indeling
- `content/` voor alle kennis, specificaties en operationele documentatie
- `languages/` voor code per programmeertaal
- `.github/workflows/` voor CI/CD, security, coverage, benchmark en release automatisering
- `.github/baselines/` voor prestatie-, coverage- en build-baselines
- `.github/scripts/` voor vergelijking en baseline-updates

## Werkwijze
1. Voeg nieuwe content toe in `content/` in de juiste submap.
2. Voeg nieuwe code toe onder de juiste taalmap in `languages/`.
3. Werk CI/CD of baseline tooling centraal bij in `.github/`.
4. Houd README's actueel zodat teams snel instappen.

## Volgende uitbreidingen
- Migratieplan van bestaande Rust workspace naar `languages/rust/`
- Standaard templates per taal voor lint/build/test
- Automatische PR-rapportage met `.github/scripts/compare-metrics.sh`
