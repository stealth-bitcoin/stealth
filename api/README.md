# Stealth API

`stealth-api` is the Rust HTTP transport layer for Stealth. It connects to a
running `bitcoind` via JSON-RPC, imports descriptors into temporary wallets,
builds a transaction graph, and runs the 12 privacy detectors from
`stealth-core`.

## Running

```bash
# Start with RPC connection (required for scanning)
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

If `STEALTH_RPC_URL` is not set the server still starts, but scan requests
return `503 Service Unavailable` until configured.

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
12 detectors, then cleans up the temporary wallet.

**UTXO scan flow:** resolves each UTXO's address from the node, builds a
partial transaction graph, and runs applicable detectors.

#### Example

```bash
curl 'http://localhost:20899/api/wallet/scan' \
  -H 'content-type: application/json' \
  -d '{"descriptor":"wpkh(xpub.../0/*)"}' | jq
```

#### Responses

| Status | Meaning |
|--------|---------|
| `200` | Scan completed — body is a `Report` |
| `400` | Invalid input (bad descriptor shape, empty UTXOs, …) |
| `502` | bitcoind RPC connection failed |
| `503` | Scanner not configured (`STEALTH_RPC_URL` not set) |

## Environment variables

| Variable | Description |
|----------|-------------|
| `STEALTH_API_BIND` | Listen address (default `127.0.0.1:20899`) |
| `STEALTH_RPC_URL` | bitcoind RPC endpoint |
| `STEALTH_RPC_USER` | RPC username |
| `STEALTH_RPC_PASS` | RPC password |
| `STEALTH_RPC_COOKIE` | Path to `.cookie` file |
