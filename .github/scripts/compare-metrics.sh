#!/usr/bin/env bash
set -euo pipefail

BASELINE_FILE="${1:-metrics/baseline.json}"
OUTPUT_FILE="${2:-metrics/metrics-report.md}"

mkdir -p "$(dirname "$OUTPUT_FILE")"

if [[ -f "$BASELINE_FILE" ]]; then
  BASELINE_DEPENDENCY_COUNT="$(python - <<'PY' "$BASELINE_FILE"
import json,sys
path=sys.argv[1]
with open(path,"r",encoding="utf-8") as f:
    data=json.load(f)
print(data.get("dependency_count",0))
PY
)"
else
  BASELINE_DEPENDENCY_COUNT=0
fi

CURRENT_DEPENDENCY_COUNT="$(cargo metadata --format-version=1 --no-deps | jq '.packages | length')"
DELTA_DEPENDENCY_COUNT="$((CURRENT_DEPENDENCY_COUNT - BASELINE_DEPENDENCY_COUNT))"

cat > "$OUTPUT_FILE" <<EOF
| Metric | Baseline | Current | Delta |
| --- | ---: | ---: | ---: |
| dependency_count | ${BASELINE_DEPENDENCY_COUNT} | ${CURRENT_DEPENDENCY_COUNT} | ${DELTA_DEPENDENCY_COUNT} |
EOF

echo "Wrote metrics report to $OUTPUT_FILE"
