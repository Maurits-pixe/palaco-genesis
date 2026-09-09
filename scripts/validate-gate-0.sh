#!/bin/bash

# Gate 0: Foundation Validation
# Verify that all foundational documents and architecture specifications exist

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VALIDATION_DIR="${REPO_ROOT}/validation"

mkdir -p "${VALIDATION_DIR}"

REPORT="${VALIDATION_DIR}/gate-0-foundation-report.txt"

{
    echo "============================================"
    echo "PALACO Gate 0: Foundation Validation"
    echo "============================================"
    echo ""
    echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Repository: ${REPO_ROOT}"
    echo ""

    FAILED=0

    # Check for required documents
    REQUIRED_DOCS=(
        "docs/PALACO-Constitution.md"
        "docs/PAS-001.md"
        "docs/PIS-001.md"
        "docs/POS-001.md"
        "docs/adr/INDEX.md"
        "docs/POC-Traceability.md"
        "docs/PVC-001-PALACO-Validation-Standard.md"
        "LICENSE"
        "README.md"
        "CONTRIBUTING.md"
    )

    echo "Checking required documents:"
    echo ""

    for doc in "${REQUIRED_DOCS[@]}"; do
        if [ -f "${REPO_ROOT}/${doc}" ]; then
            echo "OK ${doc}"
        else
            echo "FAIL ${doc} (MISSING)"
            FAILED=$((FAILED + 1))
        fi
    done

    echo ""
    echo "============================================"

    if [ ${FAILED} -eq 0 ]; then
        echo "Result: PASS"
        echo "All foundational documents present."
        exit 0
    else
        echo "Result: FAIL"
        echo "${FAILED} document(s) missing."
        exit 1
    fi
} | tee "${REPORT}"
