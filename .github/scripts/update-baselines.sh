#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINES_DIR="$BASE_DIR/baselines"
TODAY="${BASELINE_DATE:-$(date -u +%F)}"

: "${CURRENT_COVERAGE_PERCENT:=0}"
: "${CURRENT_BUILD_TIME_SECS:=0}"
: "${CURRENT_BINARY_SIZE_MB:=0}"
: "${CURRENT_DEPENDENCY_COUNT:=0}"

jq \
  --arg ts "$TODAY" \
  '.main.timestamp = $ts' \
  "$BASELINES_DIR/performance.json" > "$BASELINES_DIR/performance.json.tmp"
mv "$BASELINES_DIR/performance.json.tmp" "$BASELINES_DIR/performance.json"

jq \
  --arg ts "$TODAY" \
  --argjson coverage "$CURRENT_COVERAGE_PERCENT" \
  '.main.timestamp = $ts | .main.coverage_percent = $coverage' \
  "$BASELINES_DIR/coverage.json" > "$BASELINES_DIR/coverage.json.tmp"
mv "$BASELINES_DIR/coverage.json.tmp" "$BASELINES_DIR/coverage.json"

jq \
  --arg ts "$TODAY" \
  --argjson build "$CURRENT_BUILD_TIME_SECS" \
  --argjson size "$CURRENT_BINARY_SIZE_MB" \
  --argjson deps "$CURRENT_DEPENDENCY_COUNT" \
  '.main.timestamp = $ts | .main.build_time_secs = $build | .main.binary_size_mb = $size | .main.dependency_count = $deps' \
  "$BASELINES_DIR/build-metrics.json" > "$BASELINES_DIR/build-metrics.json.tmp"
mv "$BASELINES_DIR/build-metrics.json.tmp" "$BASELINES_DIR/build-metrics.json"

echo "Baselines updated for $TODAY"
