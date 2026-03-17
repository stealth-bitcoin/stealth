use std::collections::{HashMap, HashSet};

use crate::model::{
    DecodedTransaction, DerivedAddress, DescriptorChainRole, DescriptorType,
    TransactionParticipant, TxOutput, Utxo, WalletHistory, WalletTxEntry,
};

#[derive(Debug, Clone)]
pub struct TxGraph {
    addresses: HashMap<String, DerivedAddress>,
    our_addrs: HashSet<String>,
    history: WalletHistory,
    addr_txs: HashMap<String, Vec<WalletTxEntry>>,
    tx_addrs: HashMap<String, HashSet<String>>,
    our_txids: HashSet<String>,
}

impl TxGraph {
    pub fn new(addresses: Vec<DerivedAddress>, history: WalletHistory) -> Self {
        let mut address_map = HashMap::new();
        let mut our_addrs = HashSet::new();
        let mut addr_txs: HashMap<String, Vec<WalletTxEntry>> = HashMap::new();
        let mut tx_addrs: HashMap<String, HashSet<String>> = HashMap::new();
        let mut our_txids = HashSet::new();

        for address in addresses {
            our_addrs.insert(address.address.clone());
            address_map.insert(address.address.clone(), address);
        }

        for entry in &history.wallet_txs {
            our_txids.insert(entry.txid.clone());
            if !entry.address.is_empty() {
                addr_txs
                    .entry(entry.address.clone())
                    .or_default()
                    .push(entry.clone());
                tx_addrs
                    .entry(entry.txid.clone())
                    .or_default()
                    .insert(entry.address.clone());
            }
        }

        Self {
            addresses: address_map,
            our_addrs,
            history,
            addr_txs,
            tx_addrs,
            our_txids,
        }
    }

    pub fn addresses(&self) -> impl Iterator<Item = &DerivedAddress> {
        self.addresses.values()
    }

    pub fn derived_address(&self, address: &str) -> Option<&DerivedAddress> {
        self.addresses.get(address)
    }

    pub fn wallet_entries(&self, address: &str) -> &[WalletTxEntry] {
        self.addr_txs.get(address).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn tx_addrs(&self, txid: &str) -> Option<&HashSet<String>> {
        self.tx_addrs.get(txid)
    }

    pub fn tx(&self, txid: &str) -> Option<&DecodedTransaction> {
        self.history.transactions.get(txid)
    }

    pub fn our_txids(&self) -> impl Iterator<Item = &String> {
        self.our_txids.iter()
    }

    pub fn utxos(&self) -> &[Utxo] {
        &self.history.utxos
    }

    pub fn is_ours(&self, address: &str) -> bool {
        self.our_addrs.contains(address)
    }

    pub fn get_script_type(&self, address: &str) -> DescriptorType {
        self.derived_address(address)
            .map(|item| item.descriptor_type)
            .unwrap_or_else(|| DescriptorType::infer_from_address(address))
    }

    pub fn output_by_outpoint(&self, txid: &str, vout: u32) -> Option<&TxOutput> {
        self.tx(txid)?.vout.iter().find(|output| output.n == vout)
    }

    pub fn input_participants(&self, txid: &str) -> Vec<TransactionParticipant> {
        let Some(tx) = self.tx(txid) else {
            return Vec::new();
        };

        tx.vin
            .iter()
            .filter(|input| !input.coinbase)
            .filter_map(|input| {
                let previous_output =
                    self.output_by_outpoint(&input.previous_txid, input.previous_vout)?;
                let script_type = self.get_script_type(&previous_output.address);
                Some(TransactionParticipant {
                    address: previous_output.address.clone(),
                    value_btc: previous_output.value_btc,
                    value_sats: btc_to_sats(previous_output.value_btc),
                    script_type,
                    is_ours: self.is_ours(&previous_output.address),
                    funding_txid: Some(input.previous_txid.clone()),
                    funding_vout: Some(input.previous_vout),
                })
            })
            .collect()
    }

    pub fn output_participants(&self, txid: &str) -> Vec<TransactionParticipant> {
        let Some(tx) = self.tx(txid) else {
            return Vec::new();
        };

        tx.vout
            .iter()
            .map(|output| TransactionParticipant {
                address: output.address.clone(),
                value_btc: output.value_btc,
                value_sats: btc_to_sats(output.value_btc),
                script_type: self.get_script_type(&output.address),
                is_ours: self.is_ours(&output.address),
                funding_txid: Some(txid.to_string()),
                funding_vout: Some(output.n),
            })
            .collect()
    }

    pub fn address_role(&self, address: &str) -> &'static str {
        match self.derived_address(address).map(|item| item.chain_role) {
            Some(DescriptorChainRole::Internal) => "change",
            _ => "receive",
        }
    }
}

pub fn btc_to_sats(value_btc: f64) -> u64 {
    (value_btc * 100_000_000.0).round() as u64
}
