#!/usr/bin/env bash
set -euo pipefail
umask 077

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
        printf 'Ontbrekend project: %s.\n' "$root/$manifest" >&2
        missing=1
    fi
done
if (( missing )); then
    printf 'Herstel de ontbrekende projecten; niets gestart.\n' >&2
    exit 1
fi

for tool in cargo node npm; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Vereist programma ontbreekt: %s\n' "$tool" >&2
        exit 1
    fi
done
node -e '
    const [major, minor] = process.versions.node.split(".").map(Number);
    if (major < 22 || (major === 22 && minor < 13)) {
        console.error("Node.js 22.13 of nieuwer is vereist.");
        process.exit(1);
    }
    for (const name of ["AETHER_TOKEN", "BASTION_TOKEN"]) {
        if (!/^[\x21-\x7e]{32,4096}$/.test(process.env[name] ?? "")) {
            console.error(`${name} vereist 32–4096 afdrukbare ASCII-tekens zonder spaties; niets gestart.`);
            process.exit(1);
        }
    }
'
if [[ ! ${AETHER_KEY_HEX-} =~ ^[[:xdigit:]]{64}$ ]]; then
    printf 'AETHER_KEY_HEX moet 64 hexadecimale tekens bevatten; niets gestart.\n' >&2
    exit 1
fi
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
    if ! npm ls --prefix "$root/$project" --depth=0 >/dev/null 2>&1; then
        printf 'Installeer eerst dependencies: npm ci --prefix "%s"; niets gestart.\n' "$root/$project" >&2
        exit 1
    fi
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

(cd -- "$root/services/aether-engine" && exec cargo run --locked) &
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
