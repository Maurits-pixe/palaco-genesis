# CI Guide

## Local CI commands

Run the same checks as CI:

```bash
cargo fmt --all -- --check
cargo clippy --all --all-targets -- -D warnings
cargo build --all --verbose
cargo test --all --verbose
cargo bench --all --no-run
cargo bench --all
cargo tarpaulin --all --out Xml --timeout 300
```

## Reports and interpretation

- `ci.yml`: formatting, linting, build, and tests.
- `benchmark.yml`: benchmark execution and Criterion artifacts in `target/criterion/`.
- `coverage.yml`: generates `cobertura.xml` and uploads to Codecov.
- `security.yml`: runs `cargo audit` and `cargo deny` policy checks.
- `release.yml`: builds release binaries and attaches `target/release/**` for tags `v*`.

## Baseline management

Baseline files live in `.github/baselines/`:

- `performance.json`
- `coverage.json`
- `build-metrics.json`

Use scripts:

```bash
.github/scripts/compare-metrics.sh
CURRENT_COVERAGE_PERCENT=78.3 CURRENT_BUILD_TIME_SECS=41 CURRENT_BINARY_SIZE_MB=6.4 CURRENT_DEPENDENCY_COUNT=128 .github/scripts/update-baselines.sh
```

## Release process

1. Create and push a semver tag like `v0.1.0`.
2. `release.yml` runs automatically.
3. Verify generated artifacts in the GitHub Release page.
