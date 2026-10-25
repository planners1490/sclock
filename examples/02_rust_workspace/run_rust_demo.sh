#!/bin/zsh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCLOCK_BIN="$SCRIPT_DIR/../../bin/sclock"
C_SRC="$SCRIPT_DIR/../01_quickstart_c/secret_pricing.c"

echo "=== [1] Emitting Protected Rust Workspace Crate (my-sclock-guard) ==="
"$SCLOCK_BIN" compile "$C_SRC" \
  --emit-crate "$SCRIPT_DIR/my-sclock-guard" \
  --crate-name my-sclock-guard \
  --entry calc_license_tier \
  --seed 0x9988776655443322

echo ""
echo "Generated Crate Contents:"
ls -la "$SCRIPT_DIR/my-sclock-guard"
