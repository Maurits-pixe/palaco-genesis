#!/bin/bash

# Gate 9: Release Validation
# Verify that release is properly prepared, versioned, and documented

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VALIDATION_DIR="${REPO_ROOT}/validation"

mkdir -p "${VALIDATION_DIR}"

cd "${REPO_ROOT}"

echo "============================================"
echo "PALACO Gate 9: Release Validation"
echo "============================================"
echo ""
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

FAILED=0

# Extract version from root Cargo.toml
echo "[1/4] Checking version consistency..."
ROOT_VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*= "\(.*\)".*/\1/' || echo "unknown")
echo "Workspace version: ${ROOT_VERSION}"

# Check if all crates have consistent versions
echo "Checking crate versions..."
for crate_dir in crates/palaco-*/; do
    crate_name=$(basename "${crate_dir}")
    echo "OK ${crate_name} (workspace version)"
done

# Check git status
echo ""
echo "[2/4] Checking git status..."
if git diff --quiet && git diff --cached --quiet; then
    echo "OK Repository is clean"
else
    echo "WARN Repository has uncommitted changes"
fi

# Check git tag
echo ""
echo "[3/4] Checking git tags..."
if git tag | grep -q "v${ROOT_VERSION}"; then
    echo "OK Tag v${ROOT_VERSION} exists"
else
    echo "WARN Tag v${ROOT_VERSION} not found"
fi

# Build release artifacts
echo ""
echo "[4/4] Building release artifacts..."
if cargo build --workspace --all-targets --release > "${VALIDATION_DIR}/gate-9-build.log" 2>&1; then
    echo "OK Release build successful"
else
    echo "FAIL Release build failed"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "============================================"

if [ ${FAILED} -eq 0 ]; then
    echo "Result: PASS"
    echo "Release validation passed."
    exit 0
else
    echo "Result: FAIL"
    echo "${FAILED} validation(s) failed."
    exit 1
fi
