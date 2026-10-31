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
dropped to match what browsers send. `stealth-api --help` lists the flags and
the environment variables; any other unknown argument stops startup.
Added origins also get `Access-Control-Allow-Private-Network`, which some
Chrome versions ask for before a public page may reach a loopback address.

```bash
cargo run --bin stealth-api -- --allow-origin https://wallet.example.org
```

### Host check

CORS only decides which web pages may read the API's responses. It does not
stop DNS rebinding, where an attacker's domain resolves to `127.0.0.1` and the
page becomes same-origin with the API. So every request, preflights included,
must name the API in its `Host` header; any other request gets
`403 Host not allowed` before it reaches a route. Accepted are:

- `localhost`, `127.0.0.1` and `[::1]` on the bound port (for example
  `localhost:20899`), and the port may be left out when it is 80;
- the bound address itself, such as `192.168.1.20:20899`, unless it is
  `0.0.0.0` or `[::]` (an IPv4-mapped bind such as `[::ffff:192.168.1.20]` is
  accepted in its IPv4 form, and `[::ffff:0.0.0.0]` counts as `0.0.0.0`);
- each host added with `--allow-host` (repeatable) or `STEALTH_API_ALLOW_HOSTS`
  (comma-separated).

A request without a `Host` header, with a malformed one such as two ports or a
port with leading zeros, or with a loopback name on another port, is refused. A request with more than one
`Host` header gets `400 More than one Host header`, as RFC 9112 asks. When the
request line carries a full URL (`GET http://localhost:20899/... HTTP/1.1`),
its host is checked instead of the `Host` header, since the RFC says it takes
precedence; an `https://` URL without a port means port 443.

Added hosts are written `host` or `host:port`, one per `--allow-host`, where
the host is a name of letters, digits, `-` and `.`, an IPv4 address or a
bracketed IPv6 address, and the port has no leading zeros; anything else
stops startup. They are matched exactly,
ignoring case, except that `:80` and no port count as the same, since clients
leave port 80 out. An explicit `:443` is refused at startup unless the API
itself listens on 443, since a client behind an HTTPS proxy leaves that port
out too: write `stealth.lan`, not `stealth.lan:443`. A host written without a
port also matches an `https://` URL without a port; one written with `:80`
does not. Write hosts the way clients send them: `stealth.lan:20899` when
clients connect to that port directly, or `stealth.lan` alone behind a reverse
proxy on port 80 or 443 that passes the original `Host` through. When the API
itself is not on port 80, a host written without a port gets a startup
warning, since clients reaching the API directly send the port too, unless the
bound port already accepts that name, as it does for `localhost`.

Binding to `0.0.0.0` or `[::]` does not open the API to other names: only the
loopback names and the added hosts pass, and the API logs a warning when none
are added. Bound to one address, that address passes too, so no warning is
logged. For a scoped link-local bind such as `[fe80::1%2]:20899`, the bound
address is accepted without its zone (`[fe80::1]:20899`), and a `Host` that
carries a zone (`[fe80::1%252]:20899`) is refused; the API logs a warning
saying so. To reach an API bound to every interface from another machine, add
the name or address that machine uses:

```bash
STEALTH_API_BIND=0.0.0.0:20899 cargo run --bin stealth-api -- --allow-host 192.168.1.20:20899
```

The frontend needs nothing: the Vite proxy rewrites `Host` to its target,
`localhost:20899`. A proxy that keeps the browser's `Host`, such as
`localhost:5173`, needs that value added.

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
| `max_txs` | `number` | Optional, default `5000`. The most transactions of the wallet's history the scan loads; see below. |
| `no_limits` | `bool` | Optional, default `false`. Lifts `max_txs`. Cannot be combined with it. |

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

**Transactions left out:** a scan leaves some wallet transactions out of the
analysis and lists them in `stats`, as hex txids:
`conflicted_txids` for those Core reports at negative confirmations (it, or a
transaction it depends on, conflicts with another one; they can only come
back if a reorg removes the conflicting block), `mempool_conflicted_txids`
for unconfirmed ones a transaction in the mempool conflicts with, such as the
original of a fee bump or a payment double-spent by a raw transaction (each an
object with `txid` and `conflicts_with`; the conflicting transaction is
analyzed only when the wallet lists it and the scan keeps it),
`abandoned_txids` for those abandoned in the scan's own wallet,
`orphaned_txids` for coinbases from a block no longer in the chain (they can
only come back if a reorg restores that block; Core also marks them abandoned,
but they are listed here instead), and `unavailable_txids` for unconfirmed ones the node does not have (replaced or
double-spent, expired or evicted from the mempool, never broadcast, or
depending on a transaction that was; such a one may still confirm, unless it or a
transaction it depends on has a conflicting transaction mined). The abandoned list fills
when someone abandons a transaction in Stealth's cache wallet, or when Core
abandons the spend of a coinbase a reorg removed; one abandoned in the user's
own wallet lands in `unavailable_txids`. A wallet transaction the
node cannot serve still fails the scan when it is confirmed, or when the node
answers with any error other than not found. `mempoolconflicts`,
which `mempool_conflicted_txids` relies on, appeared in Bitcoin Core 28.0; on
an older node an unmined fee bump's original lands in `unavailable_txids`. A
scan that hits an unconfirmed transaction the node does not have while the
node is still loading its mempool fails, asking to scan again later; otherwise
those transactions are fetched once more and only what is still missing is
listed. This adds a `getmempoolinfo` call, made only when an unconfirmed
transaction is missing; a node that refuses it is treated as having loaded. A fresh scan wallet
only sees the active chain and the mempool, so through this API the lists can
be non-empty only for a scan with `cache_wallet`, whose wallet was watching
when these transactions were in the mempool.

**History limit:** after the rescan, the scan reads the scan wallet's
transaction count (`getwalletinfo`) before it loads any of the history, since
loading a large one makes `bitcoind` grow its memory and keep it. Above
`max_txs` the scan stops, unloads the scan wallet (a cache wallet stays on
disk, complete, for the next scan) and fails with the count and the limit. A
UTXO scan counts the history of the pasted outputs' addresses, which it loads
in one wallet, the same way. To go on, send the same scan again with
`max_txs` set to at least the count, or with `no_limits: true`; the rescan
runs again.

`POST /api/wallet/scan` answers `422`:

```json
{
  "error": {
    "code": "history_too_large",
    "message": "analysis failed: the wallet history holds 12345 transactions, more than the limit of 5000; loading it can take long and put a heavy load on the node",
    "tx_count": 12345,
    "limit": 5000
  }
}
```

A job from `POST /api/wallet/scans` (same body) ends as `failed`, with
`limit_exceeded` set (it is `null` on every other status):

```json
{
  "state": "failed",
  "progress": null,
  "report": null,
  "error": "analysis failed: the wallet history holds 12345 transactions, more than the limit of 5000; loading it can take long and put a heavy load on the node",
  "limit_exceeded": { "tx_count": 12345, "limit": 5000 }
}
```

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
| `422` | The wallet history is above `max_txs` (`history_too_large`) |
| `502` | bitcoind RPC unavailable/auth failed/connection failed |

## Environment variables

| Variable | Description |
|----------|-------------|
| `STEALTH_API_BIND` | Listen address (default `127.0.0.1:20899`) |
| `STEALTH_API_ALLOW_ORIGINS` | Extra web origins allowed by CORS, comma-separated (loopback origins are always allowed; same as repeating `--allow-origin`) |
| `STEALTH_API_ALLOW_HOSTS` | Extra `Host` header values the API answers to, comma-separated (loopback names on the bound port are always accepted; same as repeating `--allow-host`) |
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
