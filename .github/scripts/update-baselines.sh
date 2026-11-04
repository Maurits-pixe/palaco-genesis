#!/usr/bin/env bash
set -euo pipefail

BASELINE_FILE="${1:-metrics/baseline.json}"
mkdir -p "$(dirname "$BASELINE_FILE")"

if [[ -f "$BASELINE_FILE" ]]; then
  CURRENT_BASELINE="$(cat "$BASELINE_FILE")"
else
  CURRENT_BASELINE='{}'
fi

DEPENDENCY_COUNT="$(cargo metadata --format-version=1 --no-deps | jq '.packages | length')"
BUILD_SECONDS="${CURRENT_BUILD_SECONDS:-}"
TEST_SECONDS="${CURRENT_TEST_SECONDS:-}"
SIZE_BYTES="${CURRENT_SIZE_BYTES:-}"
BENCHMARKS_JSON="${CURRENT_BENCHMARKS_JSON:-}"

python - <<'PY' "$BASELINE_FILE" "$CURRENT_BASELINE" "$DEPENDENCY_COUNT" "$BUILD_SECONDS" "$TEST_SECONDS" "$SIZE_BYTES" "$BENCHMARKS_JSON"
import json,sys
path,raw_baseline,dep_count,build_s,test_s,size_b,bench_json = sys.argv[1:]
baseline = json.loads(raw_baseline or "{}")

def keep_or_new(key, new_value, cast=None):
    if new_value not in ("", None):
        return cast(new_value) if cast else new_value
    return baseline.get(key)

updated = dict(baseline)
updated["dependency_count"] = int(dep_count)
updated["build_seconds"] = keep_or_new("build_seconds", build_s, float)
updated["test_seconds"] = keep_or_new("test_seconds", test_s, float)
updated["size_bytes"] = keep_or_new("size_bytes", size_b, int)
if bench_json:
    updated["benchmarks"] = json.loads(bench_json)
else:
    updated["benchmarks"] = baseline.get("benchmarks")

with open(path, "w", encoding="utf-8") as f:
    json.dump(updated, f, indent=2, sort_keys=True)
    f.write("\n")
PY

echo "Updated baseline: $BASELINE_FILE"
