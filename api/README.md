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
`http://127.0.0.1` and `http://[::1]`, on any port). The frontend is not
affected: it calls `/api` through the Vite proxy, which the browser treats as
the page's own origin, so CORS does not apply. To allow another web origin, pass it with
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

**Transactions left out:** some wallet transactions are left out of the
analysis in any scan and listed in `stats`, as hex txids:
`conflicted_txids` for those Core reports at negative confirmations (it, or a
transaction it depends on, conflicts with another one), `mempool_conflicted_txids`
for unconfirmed ones a transaction in the mempool conflicts with, such as the
original of a fee bump or a payment double-spent by a raw transaction (each an
object with `txid` and `conflicts_with`; the conflicting transaction is
analyzed only when the wallet lists it and the scan keeps it),
`abandoned_txids` for those abandoned in the scan's own wallet, and
`unavailable_txids` for unconfirmed ones the node no longer has (expired or
evicted from the mempool, never broadcast, or depending on a transaction that
was double-spent, in which case they can never confirm). The abandoned list fills only
when someone abandons a transaction in Stealth's cache wallet; one abandoned in
the user's own wallet lands in `unavailable_txids`. A wallet transaction the
node cannot serve still fails the scan when it is confirmed, or when the node
answers with any error other than not found. `mempoolconflicts`,
which `mempool_conflicted_txids` relies on, appeared in Bitcoin Core 28.0; on
an older node an unmined fee bump's original lands in `unavailable_txids`. A
scan that hits an unconfirmed transaction the node does not have while the
node is still loading its mempool fails, asking to scan again later. A fresh scan wallet
only sees the active chain and the mempool, so through this API the lists can
be non-empty only for a scan with `cache_wallet`, whose wallet was watching
when these transactions were in the mempool.

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
