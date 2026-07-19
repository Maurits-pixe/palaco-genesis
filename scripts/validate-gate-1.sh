#!/bin/bash

# Gate 1: Repository Genesis
# Verify that the repository structure matches declared architecture

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VALIDATION_DIR="${REPO_ROOT}/validation"

mkdir -p "${VALIDATION_DIR}"

REPORT="${VALIDATION_DIR}/gate-1-repository-report.txt"

{
    echo "============================================"
    echo "PALACO Gate 1: Repository Genesis"
    echo "============================================"
    echo ""
    echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Repository: ${REPO_ROOT}"
    echo ""

    FAILED=0

    # Check root Cargo.toml
    echo "Checking workspace structure:"
    echo ""

    if [ -f "${REPO_ROOT}/Cargo.toml" ]; then
        echo "OK Root Cargo.toml exists"
    else
        echo "FAIL Root Cargo.toml missing"
        FAILED=$((FAILED + 1))
    fi

    # Check .gitignore
    if [ -f "${REPO_ROOT}/.gitignore" ]; then
        echo "OK .gitignore exists"
    else
        echo "FAIL .gitignore missing"
        FAILED=$((FAILED + 1))
    fi

    echo ""
    echo "Checking all 9 crates:"
    echo ""

    REQUIRED_CRATES=(
        "palaco-kernel"
        "palaco-eventbus"
        "palaco-runtime"
        "palaco-security"
        "palaco-storage"
        "palaco-operations"
        "palaco-knowledge"
        "palaco-gateway"
        "palaco-plugin"
    )

    for crate in "${REQUIRED_CRATES[@]}"; do
        crate_dir="${REPO_ROOT}/crates/${crate}"
        if [ -d "${crate_dir}" ]; then
            if [ -f "${crate_dir}/Cargo.toml" ] && [ -d "${crate_dir}/src" ]; then
                echo "OK ${crate}"
            else
                echo "FAIL ${crate} (incomplete structure)"
                FAILED=$((FAILED + 1))
            fi
        else
            echo "FAIL ${crate} (missing directory)"
            FAILED=$((FAILED + 1))
        fi
    done

    echo ""
    echo "Checking git status:"
    echo ""

    if git -C "${REPO_ROOT}" diff --quiet && git -C "${REPO_ROOT}" diff --cached --quiet; then
        echo "OK Repository is clean"
    else
        echo "FAIL Repository has uncommitted changes"
        FAILED=$((FAILED + 1))
    fi

    echo ""
    echo "============================================"

    if [ ${FAILED} -eq 0 ]; then
        echo "Result: PASS"
        echo "Repository genesis validated."
        exit 0
    else
        echo "Result: FAIL"
        echo "${FAILED} validation(s) failed."
        exit 1
    fi
} | tee "${REPORT}"
