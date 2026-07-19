#!/bin/bash

# Comprehensive validation runner
# Runs all validation gates and generates a summary report

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VALIDATION_DIR="${REPO_ROOT}/validation"

mkdir -p "${VALIDATION_DIR}"

echo "============================================"
echo "PALACO Validation Suite"
echo "PVC-001: PALACO Validation Certification"
echo "============================================"
echo ""
echo "Repository: ${REPO_ROOT}"
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""
echo "Running gates..."
echo ""

PASSED=0
FAILED=0
SKIPPED=0

# Gate 0: Foundation
echo "[Gate 0] Foundation Validation..."
if bash "${REPO_ROOT}/scripts/validate-gate-0.sh" > /dev/null 2>&1; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi

# Gate 1: Repository
echo "[Gate 1] Repository Genesis..."
if bash "${REPO_ROOT}/scripts/validate-gate-1.sh" > /dev/null 2>&1; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi

# Gate 2: Build
echo "[Gate 2] Build Validation..."
if bash "${REPO_ROOT}/scripts/validate-gate-2.sh" > /dev/null 2>&1; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi

# Gate 7: Architecture
echo "[Gate 7] Architecture Compliance..."
if bash "${REPO_ROOT}/scripts/validate-gate-7.sh" > /dev/null 2>&1; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi

# Gate 8: Security
echo "[Gate 8] Security Validation..."
if bash "${REPO_ROOT}/scripts/validate-gate-8.sh" > /dev/null 2>&1; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi

# Gate 9: Release
echo "[Gate 9] Release Validation..."
if bash "${REPO_ROOT}/scripts/validate-gate-9.sh" > /dev/null 2>&1; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "SKIP (non-release build)"
    SKIPPED=$((SKIPPED + 1))
fi

echo ""
echo "============================================"
echo "Summary"
echo "============================================"
echo "Passed:  ${PASSED}"
echo "Failed:  ${FAILED}"
echo "Skipped: ${SKIPPED}"
echo ""

if [ ${FAILED} -eq 0 ]; then
    echo "Result: ALL GATES PASSED"
    exit 0
else
    echo "Result: SOME GATES FAILED"
    exit 1
fi
