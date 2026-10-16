#!/usr/bin/env bash
set -euo pipefail

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
    printf 'Bash 4.3 of nieuwer is vereist.\n' >&2
    exit 1
fi

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
node_projects=(
    services/bastion-core
    apps/neo-launcher
    apps/aether-frontend
    apps/bastion-frontend
)

missing=0
for manifest in services/aether-engine/Cargo.toml "${node_projects[@]/%//package.json}"; do
    if [[ ! -f "$root/$manifest" ]]; then
        printf 'Ontbrekend project: %s (launch-placeholder).\n' "$root/$manifest" >&2
        missing=1
    fi
done
if (( missing )); then
    printf 'Voeg eerst de applicaties toe en installeer hun dependencies; niets gestart.\n' >&2
    exit 1
fi

for tool in cargo node npm; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Vereist programma ontbreekt: %s\n' "$tool" >&2
        exit 1
    fi
done
for project in "${node_projects[@]}"; do
    node -e '
        const fs = require("node:fs");
        const path = process.argv[1];
        const pkg = JSON.parse(fs.readFileSync(path, "utf8"));
        if (typeof pkg.scripts?.dev !== "string" || !pkg.scripts.dev.trim()) {
            console.error(`Ontbrekend dev-script: ${path}`);
            process.exit(1);
        }
    ' "$root/$project/package.json"
done

# Job control gives each service its own process group, including npm children.
set -m
pids=()
cleanup() {
    trap '' INT TERM
    for pid in "${pids[@]}"; do
        kill -TERM -- "-$pid" 2>/dev/null || true
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

(cd -- "$root/services/aether-engine" && exec cargo run) &
pids+=("$!")
for project in "${node_projects[@]}"; do
    (cd -- "$root/$project" && exec npm run dev) &
    pids+=("$!")
done

status=0
wait -n || status=$?
printf 'Een applicatie is gestopt; alle overige applicaties worden beëindigd.\n' >&2
if (( status == 0 )); then
    status=1
fi
exit "$status"
