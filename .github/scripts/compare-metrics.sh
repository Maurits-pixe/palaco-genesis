#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINES_DIR="$BASE_DIR/baselines"

perf_file="$BASELINES_DIR/performance.json"
cov_file="$BASELINES_DIR/coverage.json"
build_file="$BASELINES_DIR/build-metrics.json"

main_coverage=$(jq -r '.main.coverage_percent // 0' "$cov_file")
current_coverage=${CURRENT_COVERAGE_PERCENT:-$main_coverage}
coverage_delta=$(awk "BEGIN { printf \"%.2f\", ($current_coverage - $main_coverage) }")

main_build=$(jq -r '.main.build_time_secs // 0' "$build_file")
current_build=${CURRENT_BUILD_TIME_SECS:-$main_build}
build_delta=$(awk "BEGIN { printf \"%.2f\", ($current_build - $main_build) }")

main_size=$(jq -r '.main.binary_size_mb // 0' "$build_file")
current_size=${CURRENT_BINARY_SIZE_MB:-$main_size}
size_delta=$(awk "BEGIN { printf \"%.2f\", ($current_size - $main_size) }")

main_deps=$(jq -r '.main.dependency_count // 0' "$build_file")
current_deps=${CURRENT_DEPENDENCY_COUNT:-$main_deps}
deps_delta=$(awk "BEGIN { printf \"%.2f\", ($current_deps - $main_deps) }")

cat <<EOF
## CI Metrics Comparison

| Metric | Main Baseline | Current | Delta |
|---|---:|---:|---:|
| Coverage (%) | $main_coverage | $current_coverage | $coverage_delta |
| Build time (s) | $main_build | $current_build | $build_delta |
| Binary size (MB) | $main_size | $current_size | $size_delta |
| Dependency count | $main_deps | $current_deps | $deps_delta |

### Baseline Sources
- $perf_file
- $cov_file
- $build_file
EOF
