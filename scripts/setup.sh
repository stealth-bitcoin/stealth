#!/usr/bin/env bash
# =============================================================================
# setup.sh — Bootstrap Bitcoin Core regtest for stealth-cli development
# =============================================================================
# Creates a local regtest environment with a funded wallet, then prints the
# descriptor and a ready-to-use stealth-cli command.
#
# Prerequisites: bitcoind, bitcoin-cli, cargo (Rust toolchain).
#
# Usage:
#   ./scripts/setup.sh           # keep existing chain state
#   ./scripts/setup.sh --fresh   # wipe regtest, start from genesis
# =============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$REPO_DIR/bitcoin.conf"
DATADIR="$REPO_DIR/.bitcoin-regtest"
WALLET="scanwallet_cli"
INITIAL_BLOCKS=101

# ─── Parse args ───────────────────────────────────────────────────────────────
FRESH=0
for arg in "$@"; do
  [[ "$arg" == "--fresh" ]] && FRESH=1
done

# ─── Ensure bitcoin.conf exists ──────────────────────────────────────────────
if [[ ! -f "$CONF" ]]; then
  if [[ -f "$REPO_DIR/bitcoin.conf.example" ]]; then
    cp "$REPO_DIR/bitcoin.conf.example" "$CONF"
    echo "Copied bitcoin.conf.example → bitcoin.conf"
  else
    echo "error: bitcoin.conf not found (copy bitcoin.conf.example first)" >&2
    exit 1
  fi
fi

# ─── Helpers ──────────────────────────────────────────────────────────────────
bcli() { bitcoin-cli -datadir="$DATADIR" -conf="$CONF" -regtest -rpcport=18443 "$@"; }

# ─── Optionally wipe regtest chain ───────────────────────────────────────────
if [[ $FRESH -eq 1 ]]; then
  bcli stop 2>/dev/null || true
  sleep 2
  rm -rf "$DATADIR"
  echo "Wiped regtest data"
fi

# ─── Start bitcoind if not running ───────────────────────────────────────────
mkdir -p "$DATADIR"
if ! bcli getblockchaininfo >/dev/null 2>&1; then
  bitcoind -datadir="$DATADIR" -conf="$CONF" -daemon
  echo -n "Waiting for bitcoind"
  for _ in $(seq 1 60); do
    if bcli getblockchaininfo >/dev/null 2>&1; then
      echo " ready"
      break
    fi
    echo -n "."
    sleep 0.5
  done
fi

# ─── Create / load wallet ────────────────────────────────────────────────────
if ! bcli -rpcwallet="$WALLET" getwalletinfo >/dev/null 2>&1; then
  bcli loadwallet "$WALLET" >/dev/null 2>&1 || bcli createwallet "$WALLET" >/dev/null
fi

# ─── Mine initial blocks ─────────────────────────────────────────────────────
BLOCKS=$(bcli getblockcount)
if [[ $BLOCKS -lt $INITIAL_BLOCKS ]]; then
  NEED=$(( INITIAL_BLOCKS - BLOCKS ))
  ADDR=$(bcli -rpcwallet="$WALLET" getnewaddress "" bech32)
  bcli generatetoaddress "$NEED" "$ADDR" >/dev/null
  echo "Mined $NEED blocks (now at $(bcli getblockcount))"
fi

# ─── Print descriptor for stealth-cli ─────────────────────────────────────────
DESC=$(bcli -rpcwallet="$WALLET" listdescriptors \
  | grep -o '"desc":"[^"]*"' \
  | grep '/0/\*' \
  | grep -v 'internal' \
  | head -1 \
  | sed 's/"desc":"//;s/"$//')

COOKIE="$DATADIR/regtest/.cookie"

echo ""
echo "Regtest ready."
echo ""
echo "Descriptor:"
echo "  $DESC"
echo ""
echo "Run:"
echo "  cargo run --bin stealth-cli -- scan \\"
echo "    --descriptor '$DESC' \\"
echo "    --rpc-url http://127.0.0.1:18443 \\"
echo "    --rpc-cookie '$COOKIE' \\"
echo "    --format text"
