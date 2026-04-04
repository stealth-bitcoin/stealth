# stealth-bitcoincore

`stealth-bitcoincore` is the Bitcoin Core JSON-RPC gateway implementation for
[`stealth-engine`](../core/README.md).

It implements `stealth_engine::gateway::BlockchainGateway` and is used by both:

- `stealth-cli` (terminal scans)
- `stealth-api` (HTTP scans)

## What it does

This crate wraps the Bitcoin Core RPC surface needed by the analysis engine:

- descriptor normalization and derivation
- descriptor import into temporary watch-only wallets
- wallet history + UTXO retrieval
- raw transaction expansion (including ancestry walk)

The output is converted into `stealth-engine` gateway types (`WalletHistory`,
`DecodedTransaction`, `Utxo`, etc), so the engine can run detectors without
knowing anything about RPC transport details.

## Authentication and configuration

The gateway supports:

- RPC user/password
- Bitcoin Core cookie auth

`BitcoinCoreRpc::from_url(...)` does not auto-discover cookie files. If you
want internal cookie lookup, construct with `BitcoinCoreConfig` and set
`datadir`.

### 1) Build from URL (used by API/CLI)

```rust
use stealth_bitcoincore::BitcoinCoreRpc;

let gateway = BitcoinCoreRpc::from_url(
    "http://127.0.0.1:18443",
    Some("rpcuser".to_owned()),
    Some("rpcpassword".to_owned()),
)?;
# let _ = gateway;
# Ok::<(), stealth_model::error::AnalysisError>(())
```

Pass explicit credentials (or parse a cookie file yourself and pass those
values here).

### 2) Build from INI file

```ini
[bitcoin]
network=regtest
datadir=/home/user/.bitcoin
rpchost=127.0.0.1
rpcport=18443
rpcuser=rpcuser
rpcpassword=rpcpassword
```

```rust
use stealth_bitcoincore::{BitcoinCoreConfig, BitcoinCoreRpc};

let config = BitcoinCoreConfig::from_ini_file("stealth.ini")?;
let gateway = BitcoinCoreRpc::new(config)?;
# let _ = gateway;
# Ok::<(), stealth_model::error::AnalysisError>(())
```

Config defaults:

- `network`: `regtest`
- `rpchost`: `127.0.0.1`
- `rpcport`: inferred from network (`8332` mainnet, `18332` testnet, `38332` signet, `18443` regtest)
- `datadir`: optional (required for cookie fallback)

Cookie lookup:

- mainnet: `<datadir>/.cookie`
- other networks: `<datadir>/<network>/.cookie`, then `<datadir>/.cookie`

## Using with the analysis engine

```rust,ignore
use stealth_bitcoincore::BitcoinCoreRpc;
use stealth_engine::{AnalysisEngine, EngineSettings, ScanTarget};

let gateway = BitcoinCoreRpc::from_url(
    "http://127.0.0.1:18443",
    Some("rpcuser".to_owned()),
    Some("rpcpassword".to_owned()),
)?;

let engine = AnalysisEngine::new(&gateway, EngineSettings::default());
let report = engine.analyze(ScanTarget::Descriptor(
    "wpkh([f23f9fd2/84h/1h/0h]tpub.../0/*)".to_owned(),
))?;

println!("clean: {}", report.summary.clean);
# Ok::<(), stealth_model::error::AnalysisError>(())
```

## RPC methods used

| Gateway behavior | Bitcoin Core RPC |
| --- | --- |
| Descriptor normalization | `getdescriptorinfo` |
| Address derivation | `deriveaddresses` |
| Temporary wallet creation | `createwallet` |
| Descriptor import | `importdescriptors` |
| Wallet tx list | `listtransactions` |
| UTXO list | `listunspent` |
| Raw tx decode/history expansion | `getrawtransaction` (verbose) |
| Wallet descriptor listing | `listdescriptors` |
| Wallet cleanup | `unloadwallet` |

## Notes

- Descriptor scans create a temporary wallet named `_stealth_scan_<timestamp_ms>`
  and unload it after collection.
- Most gateway failures are surfaced as
  `AnalysisError::EnvironmentUnavailable(...)` with the underlying RPC/context
  message.
- For robust transaction lookups beyond wallet-only data, running `bitcoind`
  with `txindex=1` is recommended.

## Development

```bash
cargo test -p stealth-bitcoincore
```

## License

[MIT](../LICENSE)
