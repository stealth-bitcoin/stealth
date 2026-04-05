# Stealth API

`stealth-api` is the Rust HTTP transport layer for Stealth. It connects to a
running `bitcoind` via JSON-RPC, imports descriptors into temporary wallets,
builds a transaction graph, and runs privacy detectors from
`stealth-engine`.

## Running

```bash
# Stop any old API process, then start the current source build
pkill -f 'target/debug/stealth-api' 2>/dev/null || true

# Auto-detects local bitcoind RPC port (prefers 18443, then 8332/18332/38332)
# and uses credentials from bitcoin.conf or local cookie files.
cargo run --bin stealth-api
```

Set auth explicitly with username/password:

```bash
STEALTH_RPC_URL=http://127.0.0.1:8332 \
STEALTH_RPC_USER=user \
STEALTH_RPC_PASS=pass \
  cargo run --bin stealth-api
```

Or use a cookie file:

```bash
STEALTH_RPC_URL=http://127.0.0.1:8332 \
STEALTH_RPC_COOKIE=~/.bitcoin/.cookie \
  cargo run --bin stealth-api
```

Configure the listen address with `STEALTH_API_BIND` (default `127.0.0.1:20899`).

If you see `Connection refused (os error 111)`, either:
1. an old `stealth-api` process is still running, or
2. `bitcoind` RPC is not reachable on the detected/configured URL.

## API

### `POST /api/wallet/scan`

Accepts one mutually-exclusive source:

| Field | Type | Description |
|-------|------|-------------|
| `descriptor` | `string` | Single output descriptor |
| `descriptors` | `string[]` | Multiple descriptors |
| `utxos` | `UtxoInput[]` | Raw UTXO set |

**Descriptor scan flow:** creates a blank watch-only wallet, imports the
descriptor(s) with a full blockchain rescan, builds a `TxGraph`, runs all
17 detectors, then cleans up the temporary wallet.

**UTXO scan flow:** resolves each UTXO's address from the node, builds a
partial transaction graph, and runs applicable detectors.

#### Example (real descriptor from Bitcoin Core)

```bash
RPC="bitcoin-cli -regtest -rpcport=18443 -rpcuser=localuser -rpcpassword=localpass"
WALLET="scanwallet_$(date +%s)"

$RPC createwallet "$WALLET" >/dev/null
ADDR="$($RPC -rpcwallet="$WALLET" getnewaddress)"
DESC="$($RPC -rpcwallet="$WALLET" getaddressinfo "$ADDR" | jq -r '.desc')"

curl 'http://localhost:20899/api/wallet/scan' \
  -H 'content-type: application/json' \
  -d "{\"descriptor\":\"$DESC\"}" | jq
```

#### Responses

| Status | Meaning |
|--------|---------|
| `200` | Scan completed — body is a `Report` |
| `400` | Invalid input (bad descriptor shape, empty UTXOs, …) |
| `502` | bitcoind RPC unavailable/auth failed/connection failed |

## Environment variables

| Variable | Description |
|----------|-------------|
| `STEALTH_API_BIND` | Listen address (default `127.0.0.1:20899`) |
| `STEALTH_RPC_URL` | bitcoind RPC endpoint (overrides auto-detection) |
| `STEALTH_RPC_USER` | RPC username (otherwise read from `bitcoin.conf` when available) |
| `STEALTH_RPC_PASS` | RPC password (otherwise read from `bitcoin.conf` when available) |
| `STEALTH_RPC_COOKIE` | Path to `.cookie` file (otherwise API auto-detects common local cookie locations) |

## E2E test (regtest)

The API includes an end-to-end regtest integration test that:
1. creates wallets,
2. gets a real descriptor from `bitcoind`,
3. scans once with no history (`summary.clean = true`),
4. creates/mine transactions,
5. scans again and asserts findings (`summary.clean = false`).

Run it with:

```bash
cargo test -p stealth-api scan_descriptor_clean_then_findings_after_regtest_activity -- --nocapture
```
