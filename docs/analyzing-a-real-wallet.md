# Analyzing a real (mainnet) wallet

Stealth runs entirely against your own Bitcoin Core node. Your wallet's
public key never leaves your machine, which is the whole point: unlike
index-backed tools, Stealth does not hand your addresses to a third party.

## 1. Node requirements

Your Bitcoin Core node needs:

- `server=1` — RPC enabled
- `txindex=1` — Stealth resolves ancestors by transaction id
- unpruned — a pruned node cannot serve historical transactions
- **`blockfilterindex=1` (required in practice)** — Stealth always rescans a
  descriptor from the start of the chain, so on a real wallet the rescan speed
  is decided entirely by this index. Core 25+ uses BIP-158 compact block
  filters to skip blocks that contain nothing of yours. With the index a full
  scan finishes in minutes; without it the same scan reads the whole chain and
  can take hours, so treat it as a requirement, not a nicety. Building the
  index is a one-time cost (a few gigabytes, one pass); the node stays usable
  while it builds.

Example `bitcoin.conf` additions:

```
server=1
txindex=1
blockfilterindex=1
```

## 2. Get your wallet's public key

Most wallets export an **extended public key** (xpub, or the SLIP-132 variants
zpub/ypub). That is all Stealth needs — paste it directly.

- **Single-sig wallets:** export the account xpub/zpub from your wallet's
  settings. Stealth figures out the script type and derives both the receive
  and change chains automatically.
- **Multisig or advanced setups:** use the full output descriptor instead.
- **LND / Lightning nodes:** the on-chain account key comes from the node, not
  the wallet UI:

  ```
  lncli wallet accounts list
  ```

  Take the `extended_public_key` of the account with
  `address_type: WITNESS_PUBKEY_HASH` (derivation `m/84'/0'/0'`) and paste that.
  Everything else in that list is Lightning channel-key machinery with no
  on-chain history of its own.

Never paste a **private** key (xprv/zprv and the like). Stealth rejects them
before anything reaches the node, and never echoes the key back — but you
should never be handing a private key to an analysis tool in the first place.

## 3. Run the scan

Any of the three interfaces works. The scan is always a full analysis; there
is no wallet birth date to guess.

- **Frontend:** paste the xpub (or an address, or a list of `txid:vout` lines)
  into the input field and run it. A progress bar shows the real rescan
  progress; you can cancel a long scan.
- **API:**

  ```bash
  curl -s 'http://localhost:20899/api/wallet/scan' \
      -H 'content-type: application/json' \
      -d '{"descriptor":"<your xpub or descriptor>"}' | jq
  ```

- **CLI:**

  ```bash
  stealth-cli scan --descriptor '<your xpub or descriptor>' \
    --rpc-url http://127.0.0.1:8332 --format text
  ```

## 4. Fast, specific checks: UTXO mode

To audit only certain coins (or to get an instant answer with no rescan at
all), pass the UTXOs directly instead of a wallet key:

```bash
# utxos.json — one entry per coin
[
  {"txid": "<txid>", "vout": 0},
  {"txid": "<txid>", "vout": 1}
]
```

```bash
stealth-cli scan --utxos utxos.json --rpc-url http://127.0.0.1:8332
```

This path reads only the referenced transactions, so it returns in seconds
regardless of chain size. You can combine `--utxos` with `--descriptors` so
the scan recognizes which inputs are your own.

## 5. What it covers, and what it can't

Stealth analyzes the **on-chain** footprint of a wallet: address reuse, input
merging, change patterns, consolidation, exchange-origin deposits, and so on —
the same signals a chain-analysis firm sees about you.

For a Lightning wallet, that means it audits the on-chain part: channel
funding and closing transactions, deposits, and withdrawals. The Lightning
payments themselves are off-chain and invisible by design — which is privacy
working in your favor, not a gap in the tool.

If a scan reports that nothing was found, that is not the same as a clean
result. It usually means the input has no on-chain history yet (an unused
address, a fresh wallet), the activity is off-chain, or your node is behind
the chain tip.
