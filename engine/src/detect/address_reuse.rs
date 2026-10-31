//! Address reuse detection.

use std::collections::HashSet;

use bitcoin::Txid;
use serde_json::json;

use crate::gateway::WalletTxCategory;
use crate::graph::TxGraph;
use crate::types::*;

impl TxGraph {
    // ── 1. Address Reuse ───────────────────────────────────────────────────

    pub(super) fn detect_address_reuse(&self, findings: &mut Vec<Finding>) {
        let mut addrs: Vec<_> = self.our_addrs.iter().collect();
        addrs.sort_unstable();
        for addr in addrs {
            let entries = match self.addr_txs.get(addr) {
                Some(e) => e,
                None => continue,
            };
            let receive_txids: HashSet<Txid> = entries
                .iter()
                .filter(|e| e.category == WalletTxCategory::Receive)
                .map(|e| e.txid)
                .collect();

            if receive_txids.len() >= 2 {
                let mut reuse_txids: Vec<Txid> = receive_txids.iter().copied().collect();
                reuse_txids.sort_unstable();
                let meta = self.addr_map.get(addr);
                let role = if meta.is_some_and(|m: &AddressInfo| m.internal) {
                    "change"
                } else {
                    "receive"
                };
                // More confirmations means an earlier block; equal counts leave the order unknown.
                let confirmations = |t: &Txid| {
                    entries
                        .iter()
                        .find(|e| e.txid == *t)
                        .map_or(0, |e| e.confirmations)
                };
                // A payment the user made sent its change back to the coin's own address,
                // or onto this address after it had received in an earlier block.
                let change_back = reuse_txids.iter().any(|t| {
                    let inputs = self.get_input_addresses(t);
                    let pays_out = self
                        .get_output_addresses(t)
                        .iter()
                        .any(|o| !self.is_ours(&o.address));
                    let back_to_input = inputs.iter().any(|ia| ia.address == *addr);
                    let after_a_receive = inputs.iter().any(|ia| self.is_ours(&ia.address))
                        && reuse_txids
                            .iter()
                            .any(|r| confirmations(r) > confirmations(t));
                    pays_out && (back_to_input || after_a_receive)
                });
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::AddressReuse,
                    severity: Severity::High,
                    description: format!(
                        "Address {} ({}) reused across {} transactions",
                        addr.assume_checked_ref(),
                        role,
                        receive_txids.len()
                    ),
                    details: Some(json!({
                        "address": addr.assume_checked_ref().to_string(),
                        "role": role,
                        "tx_count": reuse_txids.len(),
                        "txids": reuse_txids,
                    })),
                    correction: Some(format!(
                        "{}Generate a fresh address for every payment received. \
                         Enable HD wallet derivation (BIP-32/44/84) so your wallet \
                         produces a new address automatically. \
                         For a recurring or published receiving address, use a Silent \
                         Payments address (sp1...): the sp1 string never appears on-chain \
                         and every payment to it lands on a fresh, unrelated address, so \
                         publishing it does not link the payments you receive.",
                        if change_back {
                            "Change came back to this address from your own spends: send \
                             change to a fresh change address instead, as wallets do by default. "
                        } else {
                            ""
                        }
                    )),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests;
