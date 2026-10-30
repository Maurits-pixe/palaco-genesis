#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINES_DIR="$BASE_DIR/baselines"
TODAY="${BASELINE_DATE:-$(date -u +%F)}"

current_coverage="${CURRENT_COVERAGE_PERCENT:-$(jq -r '.main.coverage_percent // 0' "$BASELINES_DIR/coverage.json")}"
current_build="${CURRENT_BUILD_TIME_SECS:-$(jq -r '.main.build_time_secs // 0' "$BASELINES_DIR/build-metrics.json")}"
current_size="${CURRENT_BINARY_SIZE_MB:-$(jq -r '.main.binary_size_mb // 0' "$BASELINES_DIR/build-metrics.json")}"
current_deps="${CURRENT_DEPENDENCY_COUNT:-$(jq -r '.main.dependency_count // 0' "$BASELINES_DIR/build-metrics.json")}"
current_benchmarks="${CURRENT_BENCHMARKS_JSON:-$(jq -c '.main.benchmarks // {}' "$BASELINES_DIR/performance.json")}"

jq \
  --arg ts "$TODAY" \
  --argjson benchmarks "$current_benchmarks" \
  '.main.timestamp = $ts | .main.benchmarks = $benchmarks' \
  "$BASELINES_DIR/performance.json" > "$BASELINES_DIR/performance.json.tmp"
mv "$BASELINES_DIR/performance.json.tmp" "$BASELINES_DIR/performance.json"

jq \
  --arg ts "$TODAY" \
  --argjson coverage "$current_coverage" \
  '.main.timestamp = $ts | .main.coverage_percent = $coverage' \
  "$BASELINES_DIR/coverage.json" > "$BASELINES_DIR/coverage.json.tmp"
mv "$BASELINES_DIR/coverage.json.tmp" "$BASELINES_DIR/coverage.json"

jq \
  --arg ts "$TODAY" \
  --argjson build "$current_build" \
  --argjson size "$current_size" \
  --argjson deps "$current_deps" \
  '.main.timestamp = $ts | .main.build_time_secs = $build | .main.binary_size_mb = $size | .main.dependency_count = $deps' \
  "$BASELINES_DIR/build-metrics.json" > "$BASELINES_DIR/build-metrics.json.tmp"
mv "$BASELINES_DIR/build-metrics.json.tmp" "$BASELINES_DIR/build-metrics.json"

echo "Baselines updated for $TODAY"
