#!/bin/bash

# Install PALACO validation tools

set -euo pipefail

echo "Installing PALACO validation tools..."
echo ""

echo "Making scripts executable..."
chmod +x "$(dirname "${BASH_SOURCE[0]}")/validate-*.sh"
echo "OK Scripts are now executable"

echo ""
echo "============================================"
echo "Installation complete!"
echo "============================================"
echo ""
echo "Run validation with:"
echo "  bash scripts/validate-all.sh"
echo ""
echo "Or run individual gates:"
echo "  bash scripts/validate-gate-0.sh"
echo "  bash scripts/validate-gate-1.sh"
echo "  bash scripts/validate-gate-2.sh"
echo "  bash scripts/validate-gate-7.sh"
echo "  bash scripts/validate-gate-8.sh"
echo "  bash scripts/validate-gate-9.sh"
echo ""
