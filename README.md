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
backend/script/detect.py
```

### Finding types

| Type                     | Meaning                                         |
| ------------------------ | ----------------------------------------------- |
| `ADDRESS_REUSE`          | Address received funds in multiple transactions |
| `CIOH`                   | Multi-input linkage across co-spent inputs      |
| `DUST`                   | Dust output detection                           |
| `DUST_SPENDING`          | Dust inputs linking clusters                    |
| `CHANGE_DETECTION`       | Identifiable change output                      |
| `CONSOLIDATION`          | Many-input transaction merging UTXOs            |
| `SCRIPT_TYPE_MIXING`     | Mixed script types in one spend                 |
| `CLUSTER_MERGE`          | Previously separate funding chains merged       |
| `UTXO_AGE_SPREAD`        | Reveals dormancy and timing patterns            |
| `EXCHANGE_ORIGIN`        | Likely exchange withdrawal origin               |
| `TAINTED_UTXO_MERGE`     | Tainted inputs propagating risk                 |
| `BEHAVIORAL_FINGERPRINT` | Consistent identifiable patterns                |

### Warning types

| Type            | Meaning                          |
| --------------- | -------------------------------- |
| `DORMANT_UTXOS` | Dormant funds pattern            |
| `DIRECT_TAINT`  | Direct exposure to risky sources |

## How to use

1. Open the application
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

| Dependency     | Version | Purpose         |
| -------------- | ------- | --------------- |
| Bitcoin Core   | ≥ 26    | Local node      |
| Python         | ≥ 3.10  | Analysis engine |
| Java           | 21      | Backend         |
| Node.js + yarn | ≥ 18    | Frontend        |

### 1. Clone the repository

```bash
git clone https://github.com/stealth-bitcoin/stealth.git
cd stealth
```

### 2. Configure blockchain connection

Edit:

```
backend/script/config.ini
```

### 3. Development setup (regtest)

A regtest environment is provided for development and reproducible testing of heuristics.

```bash
cd backend/script
./setup.sh
```

### 4. Generate sample transactions

```bash
python3 reproduce.py
```

### 5. Start backend

```bash
cd backend/src/StealthBackend
./mvnw quarkus:dev
```

### 6. Start frontend

```bash
cd frontend
yarn install
yarn dev
```

## Project structure

```
stealth/
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
└── slides/                # Slidev pitch presentation
```

## Privacy notice

Stealth follows a local-first approach.

It is designed to run on top of a user's own Bitcoin node, avoiding the need to share sensitive wallet data with third-party services or external APIs.

This ensures that wallet analysis can be performed without leaking addresses, descriptors, or behavioral patterns.
