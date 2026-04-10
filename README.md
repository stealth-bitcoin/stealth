# Stealth

A privacy auditing tool for Bitcoin wallets.

Stealth analyzes wallet behavior using real-world blockchain heuristics and surfaces privacy risks that are often invisible to users.

## Why this matters

Bitcoin users often unknowingly leak sensitive information through common transaction patterns such as address reuse, input clustering, and change detection.

These leaks can:

- Expose wallet balances
- Link identities across transactions
- Reveal behavioral patterns over time
- Compromise the privacy of activists, journalists, and everyday users

While these heuristics are widely used in blockchain analysis, they are rarely accessible to the users themselves.

**Stealth makes these risks visible.**

Stealth aims to become a foundational privacy auditing layer for Bitcoin wallets and tools. By making privacy risks understandable and actionable, it helps users take control of their on-chain footprint before those leaks become irreversible.

## Status

Stealth is currently transitioning from a controlled regtest environment to real-world mainnet support.

The immediate focus is enabling analysis of real wallet data using a local Bitcoin node.

Stealth ships a Rust workspace with:

- `stealth-engine` (analysis engine)
- `stealth-model` (domain model types and interfaces)
- `stealth-cli`
- `stealth-bitcoincore` (Bitcoin Core RPC gateway adapter)

## Project Direction

Stealth is evolving into a modular privacy heuristics engine for Bitcoin.

The long-term goal is to:

- Provide a reusable analysis engine for wallet developers
- Integrate with tools like Bitcoin wallets and node-based clients
- Enable privacy-preserving analysis using a local Bitcoin node

The project is also moving towards a Rust-based core for performance and portability.

## What it does

Stealth takes a Bitcoin wallet descriptor as input and analyzes its transaction history (initially in controlled environments, moving towards full mainnet support).

The report includes:

- `findings`: confirmed privacy leaks
- `warnings`: potential risks or patterns
- Severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- Structured evidence for each issue

Stealth is designed to work with real wallet data and highlight privacy risks based on observed on-chain behavior.

## Example risks detected

Stealth identifies real-world privacy issues such as:

- **Address reuse** → links transactions and balances
- **Common Input Ownership (CIOH)** → links multiple addresses to the same entity
- **Change detection** → reveals wallet structure
- **Dust attacks and spending patterns** → cluster linking
- **Script type mixing** → strong wallet fingerprinting
- **UTXO consolidation** → merges previously separate histories
- **Behavioral fingerprinting** → consistent transaction patterns over time

## Detection taxonomy

Stealth's source-of-truth detector is:

```
engine/src/detect.rs
```

The report model and type names are defined in:

```
model/src/types.rs
```

### Severity levels

| Level      | Meaning                                                           |
| ---------- | ----------------------------------------------------------------- |
| `LOW`      | Weak or contextual signal; monitor behavior                       |
| `MEDIUM`   | Meaningful privacy leakage under common heuristics                |
| `HIGH`     | Strong linkage/fingerprinting risk                                |
| `CRITICAL` | Very strong deanonymization signal requiring immediate mitigation |

## Vulnerabilities detected

Stealth currently runs **12 detectors** in `stealth-engine`.

| #   | Type                     | Default severity | What it indicates                                      |
| --- | ------------------------ | ---------------- | ------------------------------------------------------ |
| 1   | `ADDRESS_REUSE`          | HIGH             | Same receive address used across multiple transactions |
| 2   | `CIOH`                   | HIGH - CRITICAL  | Multi-input ownership linkage                          |
| 3   | `DUST`                   | MEDIUM - HIGH    | Dust outputs received/spent                            |
| 4   | `DUST_SPENDING`          | HIGH             | Dust merged with normal inputs                         |
| 5   | `CHANGE_DETECTION`       | MEDIUM           | Identifiable change output patterns                    |
| 6   | `CONSOLIDATION`          | MEDIUM           | Consolidation transactions linking clusters            |
| 7   | `SCRIPT_TYPE_MIXING`     | HIGH             | Mixed script types that fingerprint wallet behavior    |
| 8   | `CLUSTER_MERGE`          | HIGH             | Previously separate clusters merged on-chain           |
| 9   | `UTXO_AGE_SPREAD`        | LOW              | Broad age spread revealing timing behavior             |
| 10  | `EXCHANGE_ORIGIN`        | MEDIUM           | Signals typical of exchange batch withdrawals          |
| 11  | `TAINTED_UTXO_MERGE`     | HIGH             | Tainted and clean inputs merged                        |
| 12  | `BEHAVIORAL_FINGERPRINT` | MEDIUM           | Repeating transaction patterns                         |

### Warning types

| Type            | Typical severity | Meaning                                         |
| --------------- | ---------------- | ----------------------------------------------- |
| `DORMANT_UTXOS` | LOW              | Dormant/hoarded UTXO behavior                   |
| `DIRECT_TAINT`  | HIGH             | Funds directly received from known risky source |

## How to use the frontend

1. Run and open the application
2. Paste a wallet descriptor (`wpkh(...)`, `tr(...)`, etc.)
3. Click **Analyze**
4. Review:
   - Findings and warnings
   - Severity levels
   - Structured explanations

## Roadmap

### Short term

- [ ] Rewrite the analysis engine in Rust, replacing the current multi-language implementation
- [ ] Add support for analyzing real wallet data using a local Bitcoin node (mainnet)

### Medium term

- [ ] Enable integration with wallet ecosystems (e.g. BDK-based wallets)
- [ ] Expose the analysis engine as a reusable library

### Long term

- [ ] Enable external clients (e.g. wallets, tools like am-i-exposed)
- [ ] Integrate with Floresta

## Installation

### Prerequisites

| Dependency     | Version | Purpose           |
| -------------- | ------- | ----------------- |
| Bitcoin Core   | ≥ 26    | Local node        |
| Rust toolchain | ≥ 1.56  | CLI + engine      |
| Node.js + yarn | ≥ 18    | Frontend          |

### 1. Clone the repository

```bash
git clone https://github.com/stealth-bitcoin/stealth.git
cd stealth
cargo build
```

### 2. Configure Bitcoin Core RPC (regtest)

Copy the example config:

```bash
cp bitcoin.conf.example bitcoin.conf
```

### 3. Start regtest and fund a wallet

```bash
./scripts/setup.sh
```

This starts `bitcoind` in regtest mode, creates a wallet, mines initial blocks,
and prints the descriptor and a ready-to-use `stealth-cli` command.

Use `./scripts/setup.sh --fresh` to wipe the chain and start from genesis.

### 4. Run a CLI scan

```bash
cargo run --bin stealth-cli -- scan \
  --descriptor '<descriptor from setup.sh output>' \
  --rpc-url http://127.0.0.1:18443 \
  --rpc-cookie .bitcoin-regtest/regtest/.cookie \
  --format text
```

### 5. Start frontend

```bash
cd frontend
yarn install
yarn dev
```

## Project structure

```
stealth/
├── Cargo.toml              # Rust workspace definition
├── engine/                 # stealth-engine (detectors + graph + report model)
│   ├── src/
│   │   ├── detect.rs       # privacy detectors
│   │   ├── engine.rs       # AnalysisEngine entry point
│   │   ├── graph.rs        # Transaction graph builder
│   │   └── lib.rs          # Crate root and re-exports
│   └── tests/
│       └── integration.rs  # Regtest integration tests
├── model/                  # stealth-model (domain model types and interfaces)
├── bitcoincore/            # Bitcoin Core gateway implementation crate
├── frontend/              # React + Vite UI
│   └── src/
│       ├── components/    # FindingCard, VulnerabilityBadge
│       ├── screens/       # InputScreen, LoadingScreen, ReportScreen
│       └── services/      # walletService.js (API client)
├── backend/
│   ├── script/            # Python scripts + regtest data
│   │   ├── setup.sh       # Bootstrap bitcoind regtest
│   │   ├── reproduce.py   # Create 12 vulnerability scenarios
│   │   ├── detect.py      # Privacy vulnerability detector
│   │   ├── bitcoin_rpc.py # bitcoin-cli wrapper
│   │   ├── config.ini     # Connection config (datadir, network)
│   │   └── bitcoin-data/  # Regtest chain data (gitignored)
│   └── src/StealthBackend/ # Quarkus Java REST API (single /api/wallet/scan endpoint)
├── cli/                   # stealth-cli
├── scripts/               # Development helper scripts (setup.sh)
└── target/                # Cargo build outputs
```

### Test Coverage

Stealth test coverage includes end-to-end api tests, integration tests using bitcoind regtest in core/ and additional unit tests.

You may run tests with:

```bash
cargo test
```

## Privacy notice

Stealth follows a local-first approach.

It is designed to run on top of a user's own Bitcoin node, avoiding the need to share sensitive wallet data with third-party services or external APIs.

This ensures that wallet analysis can be performed without leaking addresses, descriptors, or behavioral patterns.
