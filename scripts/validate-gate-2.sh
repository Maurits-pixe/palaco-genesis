#!/bin/bash

# Gate 2: Build Validation
# Verify that code compiles, passes linting, tests pass, and formatting is correct

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VALIDATION_DIR="${REPO_ROOT}/validation"

mkdir -p "${VALIDATION_DIR}"

cd "${REPO_ROOT}"

echo "============================================"
echo "PALACO Gate 2: Build Validation"
echo "============================================"
echo ""
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

FAILED=0

# Format check
echo "[1/7] Checking code formatting..."
if cargo fmt --all --check > "${VALIDATION_DIR}/gate-2-fmt.log" 2>&1; then
    echo "OK Format check passed"
else
    echo "FAIL Format check failed"
    FAILED=$((FAILED + 1))
fi

# Clippy check
echo "[2/7] Running Clippy lints..."
if cargo clippy --workspace -- -D warnings > "${VALIDATION_DIR}/gate-2-clippy.log" 2>&1; then
    echo "OK Clippy check passed"
else
    echo "FAIL Clippy check failed"
    FAILED=$((FAILED + 1))
fi

# Build check
echo "[3/7] Building workspace..."
if cargo build --workspace --all-targets > "${VALIDATION_DIR}/gate-2-build.log" 2>&1; then
    echo "OK Build passed"
else
    echo "FAIL Build failed"
    FAILED=$((FAILED + 1))
fi

# Test check
echo "[4/7] Running tests..."
if cargo test --workspace --lib > "${VALIDATION_DIR}/gate-2-test.log" 2>&1; then
    echo "OK Tests passed"
else
    echo "FAIL Tests failed"
    FAILED=$((FAILED + 1))
fi

# Doc check
echo "[5/7] Building documentation..."
if cargo doc --no-deps --all > "${VALIDATION_DIR}/gate-2-doc.log" 2>&1; then
    echo "OK Documentation built"
else
    echo "FAIL Documentation build failed"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "============================================"

if [ ${FAILED} -eq 0 ]; then
    echo "Result: PASS"
    echo "All build validations passed."
    exit 0
else
    echo "Result: FAIL"
    echo "${FAILED} validation(s) failed."
    exit 1
fi
