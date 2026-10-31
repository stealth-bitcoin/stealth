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

Browsers may only call the API from loopback origins (`http://localhost`,
`http://127.0.0.1` and `http://[::1]`, on any port), which covers the
frontend's Vite dev server. To allow another web origin, pass it with
`--allow-origin` (repeatable) or list it in `STEALTH_API_ALLOW_ORIGINS`
(comma-separated). Each value is an exact origin, `scheme://host[:port]` with no
path; the API refuses to start on a malformed one. Hosts must be ASCII (use the
punycode form of an internationalised name), IPv4 addresses must be four
decimal numbers without leading zeros, and a default port such as `:443` is
dropped to match what browsers send. `stealth-api --help` lists the flag and
the environment variables; any other unknown argument stops startup.
Added origins also get `Access-Control-Allow-Private-Network`, which some
Chrome versions ask for before a public page may reach a loopback address.

CORS only decides which web pages may read the API's responses. It does not
stop DNS rebinding, where an attacker's domain resolves to `127.0.0.1` and the
page becomes same-origin with the API; that needs a `Host` header check, which
the API does not do yet.

```bash
cargo run --bin stealth-api -- --allow-origin https://wallet.example.org
```

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
| `cache_wallet` | `bool` | Optional, default `false`. Keep a watch-only wallet named after the descriptors on the node so repeat scans only pay Core's incremental catch-up. The viewing key stays in the node's wallet directory until removed by hand. |

**Descriptor scan flow:** creates a blank watch-only wallet, imports the
descriptor(s) with a full blockchain rescan, builds a `TxGraph`, runs all
17 detectors, then unloads the temporary wallet. With `cache_wallet` the
wallet is kept instead; a cached wallet whose build failed or was cancelled
is built again on the next scan rather than trusted.

**UTXO scan flow:** resolves each UTXO's address from the node, fetches the
chain history of those addresses the way a descriptor scan does (one `addr()`
import and rescan for all of them), builds the transaction graph from the
pasted outputs plus that history, and runs the detectors. When the node cannot
serve the history, the scan completes on the pasted outputs alone and
`stats.addresses_without_history` says how many addresses that affected.

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
| `STEALTH_API_ALLOW_ORIGINS` | Extra web origins allowed by CORS, comma-separated (loopback origins are always allowed; same as repeating `--allow-origin`) |
| `STEALTH_RPC_URL` | bitcoind RPC endpoint (overrides auto-detection) |
| `STEALTH_RPC_USER` | RPC username (otherwise read from `bitcoin.conf` when available) |
| `STEALTH_RPC_PASS` | RPC password (otherwise read from `bitcoin.conf` when available) |
| `STEALTH_RPC_COOKIE` | Path to `.cookie` file (otherwise API auto-detects common local cookie locations) |

## E2E test (regtest)

The API includes an end-to-end regtest integration test that:
1. creates wallets,
2. gets a real descriptor from `bitcoind`,
3. scans once with no history (`summary.analyzed_nothing = true`, `summary.clean = false`),
4. creates/mine transactions,
5. scans again and asserts findings (`summary.clean = false`).

Run it with:

```bash
cargo test -p stealth-api scan_descriptor_clean_then_findings_after_regtest_activity -- --nocapture
```
