use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Txid};

use crate::gateway::{DecodedTransaction, WalletHistory, WalletTxCategory};
use crate::types::{AddressInfo, InputInfo, OutputInfo, WalletTx};

/// Indexed view of all transactions touching a wallet's address set.
///
/// All caches are populated up-front from a [`WalletHistory`] so no live
/// RPC connection is needed at detection time.
#[derive(Debug)]
pub struct TxGraph {
    /// Map of our addresses → metadata.
    pub addr_map: HashMap<Address<NetworkUnchecked>, AddressInfo>,
    /// All our addresses (quick lookup).
    pub our_addrs: HashSet<Address<NetworkUnchecked>>,
    /// Current UTXOs from `listunspent`.
    pub utxos: Vec<UtxoEntry>,
    /// Transaction IDs that touch our wallet.
    pub our_txids: HashSet<Txid>,
    /// Per-address transaction entries.
    pub addr_txs: HashMap<Address<NetworkUnchecked>, Vec<WalletTx>>,
    /// Per-txid set of our addresses involved.
    pub tx_addrs: HashMap<Txid, HashSet<Address<NetworkUnchecked>>>,

    /// Decoded transactions keyed by txid.
    pub tx_cache: HashMap<Txid, DecodedTransaction>,
    /// Cached input addresses per txid.
    pub input_cache: HashMap<Txid, Vec<InputInfo>>,
    /// Cached output addresses per txid.
    pub output_cache: HashMap<Txid, Vec<OutputInfo>>,
}

/// A UTXO entry from `listunspent`.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub txid: Txid,
    pub vout: u32,
    pub address: Address<NetworkUnchecked>,
    pub amount: Amount,
    pub confirmations: u32,
}

impl TxGraph {
    /// Check whether an address belongs to our wallet.
    pub fn is_ours(&self, address: &Address<NetworkUnchecked>) -> bool {
        self.our_addrs.contains(address)
    }

    /// Get the script type for an address.
    pub fn script_type(&self, address: &Address<NetworkUnchecked>) -> String {
        self.addr_map
            .get(address)
            .map(|info| info.script_type.clone())
            .unwrap_or_else(|| script_type_from_address(address))
    }

    /// Look up a decoded transaction by txid.
    pub fn fetch_tx(&self, txid: &Txid) -> Option<&DecodedTransaction> {
        self.tx_cache.get(txid)
    }

    /// Get all input addresses for a transaction.
    pub fn get_input_addresses(&self, txid: &Txid) -> Vec<InputInfo> {
        self.input_cache.get(txid).cloned().unwrap_or_default()
    }

    /// Get all output addresses for a transaction.
    pub fn get_output_addresses(&self, txid: &Txid) -> Vec<OutputInfo> {
        self.output_cache.get(txid).cloned().unwrap_or_default()
    }

    /// Build a [`TxGraph`] from a pre-fetched [`WalletHistory`] produced
    /// by a [`BlockchainGateway`](crate::gateway::BlockchainGateway).
    ///
    /// All transaction caches are populated up-front so no live RPC
    /// connection is needed.
    pub fn from_wallet_history(history: WalletHistory) -> Self {
        let mut our_addrs = HashSet::new();
        let mut addr_map = HashMap::new();
        let mut our_txids = HashSet::new();
        let mut addr_txs: HashMap<Address<NetworkUnchecked>, Vec<WalletTx>> = HashMap::new();
        let mut tx_addrs: HashMap<Txid, HashSet<Address<NetworkUnchecked>>> = HashMap::new();

        for entry in &history.wallet_txs {
            our_txids.insert(entry.txid);
            let address = match &entry.address {
                Some(addr) => addr,
                None => continue,
            };

            let wtx = WalletTx {
                txid: entry.txid,
                address: address.clone(),
                category: entry.category,
                amount: entry.amount,
                confirmations: entry.confirmations,
            };

            if entry.category != WalletTxCategory::Send {
                our_addrs.insert(address.clone());
                addr_map
                    .entry(address.clone())
                    .or_insert_with(|| AddressInfo {
                        script_type: script_type_from_address(address),
                        internal: history.internal_addresses.contains(address),
                        index: 0,
                    });
            }

            addr_txs.entry(address.clone()).or_default().push(wtx);
            tx_addrs
                .entry(entry.txid)
                .or_default()
                .insert(address.clone());
        }

        let utxos: Vec<UtxoEntry> = history
            .utxos
            .iter()
            .filter_map(|u| {
                let address = u.address.clone()?;
                our_addrs.insert(address.clone());
                addr_map
                    .entry(address.clone())
                    .or_insert_with(|| AddressInfo {
                        script_type: script_type_from_address(&address),
                        internal: history.internal_addresses.contains(&address),
                        index: 0,
                    });
                Some(UtxoEntry {
                    txid: u.txid,
                    vout: u.vout,
                    address,
                    amount: u.amount,
                    confirmations: u.confirmations,
                })
            })
            .collect();

        // Add ALL derived addresses to `our_addrs` and `addr_map`, matching
        // the Python reference (`our_addrs = set(addr_map.keys())` where
        // `addr_map` contains every address derived from the descriptors).
        for addr in &history.derived_addresses {
            our_addrs.insert(addr.clone());
            addr_map.entry(addr.clone()).or_insert_with(|| AddressInfo {
                script_type: script_type_from_address(addr),
                internal: history.internal_addresses.contains(addr),
                index: 0,
            });
        }

        // Pre-populate caches from decoded transactions.
        let mut tx_cache = HashMap::new();
        let mut input_cache: HashMap<Txid, Vec<InputInfo>> = HashMap::new();
        let mut output_cache: HashMap<Txid, Vec<OutputInfo>> = HashMap::new();

        for (txid, tx) in &history.transactions {
            tx_cache.insert(*txid, tx.clone());

            let inputs: Vec<InputInfo> = tx
                .vin
                .iter()
                .filter_map(|input| {
                    if input.coinbase {
                        return None;
                    }
                    let parent = history.transactions.get(&input.previous_txid)?;
                    let out = parent.vout.iter().find(|o| o.n == input.previous_vout)?;
                    let address = out.address.clone()?;
                    Some(InputInfo {
                        address,
                        value: out.value,
                        funding_txid: input.previous_txid,
                        funding_vout: input.previous_vout,
                    })
                })
                .collect();
            input_cache.insert(*txid, inputs);

            let outputs: Vec<OutputInfo> = tx
                .vout
                .iter()
                .filter_map(|out| {
                    let address = out.address.clone()?;
                    Some(OutputInfo {
                        address: address.clone(),
                        value: out.value,
                        index: out.n,
                        script_type: script_type_from_address(&address),
                    })
                })
                .collect();
            output_cache.insert(*txid, outputs);
        }

        TxGraph {
            addr_map,
            our_addrs,
            utxos,
            our_txids,
            addr_txs,
            tx_addrs,
            tx_cache,
            input_cache,
            output_cache,
        }
    }
}

/// Determine script type by decoding the address and inspecting the
/// resulting script.
///
/// * `bc1q` / `tb1q` / `bcrt1q` with a 20-byte program → **p2wpkh**
/// * `bc1q` / `tb1q` / `bcrt1q` with a 32-byte program → **p2wsh**
/// * `bc1p` / `tb1p` / `bcrt1p` → **p2tr**
/// * Base58 `1`/`m`/`n` (version 0x00/0x6f) → **p2pkh**
/// * Base58 `3`/`2` (version 0x05/0xc4) → **p2sh** (we *cannot* know if it
///   wraps p2wpkh, p2wsh, or bare multisig without the redeem script)
pub fn script_type_from_address(address: &Address<NetworkUnchecked>) -> String {
    let addr = address.clone().assume_checked();
    let script = addr.script_pubkey();
    if script.is_p2pkh() {
        "p2pkh".into()
    } else if script.is_p2sh() {
        "p2sh".into()
    } else if script.is_p2wpkh() {
        "p2wpkh".into()
    } else if script.is_p2wsh() {
        "p2wsh".into()
    } else if script.is_p2tr() {
        "p2tr".into()
    } else {
        "unknown".into()
    }
}
