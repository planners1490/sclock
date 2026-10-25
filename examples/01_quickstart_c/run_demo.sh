#!/bin/zsh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCLOCK_BIN="$SCRIPT_DIR/../../bin/sclock"

echo "=== [1] Compiling & Locking secret_pricing.c with scLock (by relay) ==="
"$SCLOCK_BIN" compile "$SCRIPT_DIR/secret_pricing.c" \
  -o "$SCRIPT_DIR/secret_pricing_locked" \
  --entry calc_license_tier \
  --seed 0x20261025AABBCCDD

echo ""
echo "=== [2] Applying Stealth Hardening & Apple Hardened Runtime Signature ==="
"$SCLOCK_BIN" protect-app "$SCRIPT_DIR/secret_pricing_locked"

echo ""
echo "=== [3] Executing Protected Binary (seats=20, unlock_pin=7777) ==="
RESULT=$("$SCRIPT_DIR/secret_pricing_locked" 20 7777)
echo " -> Protected Output Result: $RESULT"
