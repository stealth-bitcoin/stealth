use std::collections::HashSet;

use serde_json::json;

use crate::config::{AnalysisConfig, DetectorId};
use crate::graph::{TxGraph, btc_to_sats};
use crate::model::{
    Finding, FindingDetails, FindingKind, Severity, TransactionParticipant, Warning,
    WarningDetails, WarningKind,
};

#[derive(Debug, Default, Clone, PartialEq)]
pub struct DetectorResult {
    pub findings: Vec<Finding>,
    pub warnings: Vec<Warning>,
}

impl DetectorResult {
    pub fn extend(&mut self, other: Self) {
        self.findings.extend(other.findings);
        self.warnings.extend(other.warnings);
    }
}

pub struct DetectorContext<'a> {
    pub graph: &'a TxGraph,
    pub config: &'a AnalysisConfig,
    pub known_exchange_txids: &'a HashSet<String>,
    pub known_risky_txids: &'a HashSet<String>,
}

pub fn run_all(ctx: &DetectorContext<'_>) -> DetectorResult {
    let mut result = DetectorResult::default();
    let enabled = &ctx.config.enabled_detectors;

    for (detector, run) in [
        (
            DetectorId::AddressReuse,
            detect_address_reuse as fn(&DetectorContext<'_>) -> DetectorResult,
        ),
        (DetectorId::Cioh, detect_cioh),
        (DetectorId::Dust, detect_dust),
        (DetectorId::DustSpending, detect_dust_spending),
        (DetectorId::ChangeDetection, detect_change_detection),
        (DetectorId::Consolidation, detect_consolidation),
        (DetectorId::ScriptTypeMixing, detect_script_type_mixing),
        (DetectorId::ClusterMerge, detect_cluster_merge),
        (DetectorId::UtxoAgeSpread, detect_utxo_age_spread),
        (DetectorId::ExchangeOrigin, detect_exchange_origin),
        (DetectorId::TaintedUtxoMerge, detect_tainted_utxo_merge),
        (
            DetectorId::BehavioralFingerprint,
            detect_behavioral_fingerprint,
        ),
    ] {
        if enabled.contains(&detector) {
            result.extend(run(ctx));
        }
    }

    result
}

pub fn detect_address_reuse(ctx: &DetectorContext<'_>) -> DetectorResult {
    let mut findings = Vec::new();

    for address in ctx.graph.addresses() {
        let receive_txids: Vec<_> = ctx
            .graph
            .wallet_entries(&address.address)
            .iter()
            .filter(|entry| matches!(entry.category, crate::model::WalletTxCategory::Receive))
            .map(|entry| entry.txid.clone())
            .collect();
        let distinct: HashSet<_> = receive_txids.into_iter().collect();
        if distinct.len() < 2 {
            continue;
        }

        let mut txids = distinct
            .iter()
            .map(|txid| {
                let confirmations = ctx
                    .graph
                    .tx(txid)
                    .map(|tx| tx.confirmations)
                    .unwrap_or_default();
                json!({
                    "txid": txid,
                    "confirmations": confirmations,
                })
            })
            .collect::<Vec<_>>();
        txids.sort_by(|left, right| left["txid"].as_str().cmp(&right["txid"].as_str()));

        findings.push(finding(
            FindingKind::AddressReuse,
            Severity::High,
            format!(
                "Address {} ({}) reused across {} transactions",
                address.address,
                ctx.graph.address_role(&address.address),
                distinct.len()
            ),
            json!({
                "address": address.address,
                "role": ctx.graph.address_role(&address.address),
                "tx_count": distinct.len(),
                "txids": txids,
            }),
            Some("Generate a fresh address for each receipt and avoid static reuse.".into()),
        ));
    }

    DetectorResult {
        findings,
        warnings: Vec::new(),
    }
}

pub fn detect_cioh(ctx: &DetectorContext<'_>) -> DetectorResult {
    let mut findings = Vec::new();

    for txid in ctx.graph.our_txids() {
        let Some(tx) = ctx.graph.tx(txid) else {
            continue;
        };
        if tx.vin.len() < 2 {
            continue;
        }

        let inputs = ctx.graph.input_participants(txid);
        if inputs.len() < 2 {
            continue;
        }

        let our_inputs: Vec<_> = inputs.iter().filter(|input| input.is_ours).collect();
        if our_inputs.len() < 2 {
            continue;
        }
        let external_inputs = inputs.len() - our_inputs.len();
        let ownership_pct = (our_inputs.len() as f64 / inputs.len() as f64 * 100.0).round() as u64;
        let severity = if our_inputs.len() == inputs.len() {
            Severity::Critical
        } else {
            Severity::High
        };

        findings.push(finding(
            FindingKind::Cioh,
            severity,
            format!(
                "TX {txid} merges {}/{} of your inputs ({}% ownership)",
                our_inputs.len(),
                inputs.len(),
                ownership_pct
            ),
            json!({
                "txid": txid,
                "total_inputs": inputs.len(),
                "our_inputs": our_inputs.len(),
                "external_inputs": external_inputs,
                "ownership_pct": ownership_pct,
                "our_addresses": our_inputs.iter().map(|input| json!({
                    "address": input.address,
                    "role": ctx.graph.address_role(&input.address),
                    "amount_btc": round_btc(input.value_btc),
                })).collect::<Vec<_>>(),
            }),
            Some(
                "Use coin control or collaborative spending tools to avoid linking inputs.".into(),
            ),
        ));
    }

    DetectorResult {
        findings,
        warnings: Vec::new(),
    }
}

pub fn detect_dust(ctx: &DetectorContext<'_>) -> DetectorResult {
    let dust_sats = ctx.config.thresholds.dust_sats;
    let strict_dust_sats = ctx.config.thresholds.strict_dust_sats;
    let mut findings = Vec::new();

    let current = ctx
        .graph
        .utxos()
        .iter()
        .filter(|utxo| {
            ctx.graph.is_ours(&utxo.address) && btc_to_sats(utxo.amount_btc) <= dust_sats
        })
        .collect::<Vec<_>>();

    for utxo in &current {
        let sats = btc_to_sats(utxo.amount_btc);
        let label = if sats <= strict_dust_sats {
            "STRICT_DUST"
        } else {
            "dust-class"
        };
        findings.push(finding(
            FindingKind::Dust,
            if sats <= strict_dust_sats {
                Severity::High
            } else {
                Severity::Medium
            },
            format!(
                "Dust UTXO at {} ({} sats, {}, unspent)",
                utxo.address, sats, label
            ),
            json!({
                "status": "unspent",
                "address": utxo.address,
                "sats": sats,
                "label": label,
                "txid": utxo.txid,
                "vout": utxo.vout,
            }),
            Some("Freeze dust UTXOs instead of spending them alongside normal funds.".into()),
        ));
    }

    let current_keys = current
        .iter()
        .map(|utxo| (utxo.txid.clone(), utxo.address.clone()))
        .collect::<HashSet<_>>();
    let mut historical_seen = HashSet::new();

    for txid in ctx.graph.our_txids() {
        for output in ctx.graph.output_participants(txid) {
            if !output.is_ours || output.value_sats > dust_sats {
                continue;
            }
            let key = (txid.clone(), output.address.clone());
            if current_keys.contains(&key) || !historical_seen.insert(key.clone()) {
                continue;
            }
            findings.push(finding(
                FindingKind::Dust,
                Severity::Low,
                format!(
                    "Historical dust output at {} ({} sats, already spent)",
                    output.address, output.value_sats
                ),
                json!({
                    "status": "spent",
                    "address": output.address,
                    "sats": output.value_sats,
                    "txid": txid,
                }),
                Some("Reject unsolicited dust or isolate it before spending.".into()),
            ));
        }
    }

    DetectorResult {
        findings,
        warnings: Vec::new(),
    }
}

pub fn detect_dust_spending(ctx: &DetectorContext<'_>) -> DetectorResult {
    let dust_sats = ctx.config.thresholds.dust_sats;
    let normal_min = ctx.config.thresholds.normal_input_min_sats;
    let mut findings = Vec::new();

    for txid in ctx.graph.our_txids() {
        let inputs = ctx.graph.input_participants(txid);
        if inputs.len() < 2 {
            continue;
        }

        let mut dust_inputs = Vec::new();
        let mut normal_inputs = Vec::new();

        for input in inputs.iter().filter(|input| input.is_ours) {
            if input.value_sats <= dust_sats {
                dust_inputs.push(input);
            } else if input.value_sats > normal_min {
                normal_inputs.push(input);
            }
        }

        if dust_inputs.is_empty() || normal_inputs.is_empty() {
            continue;
        }

        findings.push(finding(
            FindingKind::DustSpending,
            Severity::High,
            format!(
                "TX {txid} spends {} dust input(s) alongside {} normal input(s)",
                dust_inputs.len(),
                normal_inputs.len()
            ),
            json!({
                "txid": txid,
                "dust_inputs": dust_inputs.iter().map(|input| json!({
                    "address": input.address,
                    "sats": input.value_sats,
                })).collect::<Vec<_>>(),
                "normal_inputs": normal_inputs.iter().map(|input| json!({
                    "address": input.address,
                    "amount_btc": round_btc(input.value_btc),
                })).collect::<Vec<_>>(),
            }),
            Some("Do not combine dust with normal inputs in the same spend.".into()),
        ));
    }

    DetectorResult {
        findings,
        warnings: Vec::new(),
    }
}

pub fn detect_change_detection(ctx: &DetectorContext<'_>) -> DetectorResult {
    let mut findings = Vec::new();

    for txid in ctx.graph.our_txids() {
        let outputs = ctx.graph.output_participants(txid);
        if outputs.len() < 2 {
            continue;
        }
        let inputs = ctx.graph.input_participants(txid);
        let our_inputs: Vec<_> = inputs.iter().filter(|input| input.is_ours).collect();
        if our_inputs.is_empty() {
            continue;
        }

        let our_outputs: Vec<_> = outputs.iter().filter(|output| output.is_ours).collect();
        let external_outputs: Vec<_> = outputs.iter().filter(|output| !output.is_ours).collect();
        if our_outputs.is_empty() || external_outputs.is_empty() {
            continue;
        }

        let input_types = our_inputs
            .iter()
            .map(|input| input.script_type)
            .collect::<HashSet<_>>();
        let mut reasons = Vec::new();

        for change in &our_outputs {
            let change_round = is_round_amount(change.value_sats);
            let change_internal =
                ctx.graph
                    .derived_address(&change.address)
                    .is_some_and(|address| {
                        address.chain_role == crate::model::DescriptorChainRole::Internal
                    });

            for payment in &external_outputs {
                if is_round_amount(payment.value_sats) && !change_round {
                    reasons.push(format!(
                        "Round payment ({} sats) vs non-round change ({} sats)",
                        payment.value_sats, change.value_sats
                    ));
                }

                if input_types.contains(&change.script_type)
                    && change.script_type != payment.script_type
                {
                    reasons.push(format!(
                        "Change script type ({}) matches inputs and differs from payment ({})",
                        change.script_type.as_script_name(),
                        payment.script_type.as_script_name()
                    ));
                }

                if change_internal {
                    reasons
                        .push("Change uses an internal (BIP-44 /1/*) derivation path".to_string());
                }
            }
        }

        if reasons.is_empty() {
            continue;
        }

        reasons.sort();
        reasons.dedup();

        findings.push(finding(
            FindingKind::ChangeDetection,
            Severity::Medium,
            format!(
                "TX {txid} has identifiable change output(s) ({} heuristic(s) matched)",
                reasons.len()
            ),
            json!({
                "txid": txid,
                "reasons": reasons,
                "change_outputs": our_outputs.iter().map(|output| json!({
                    "address": output.address,
                    "amount_btc": round_btc(output.value_btc),
                })).collect::<Vec<_>>(),
            }),
            Some("Prefer payment construction that avoids trivially identifiable change.".into()),
        ));
    }

    DetectorResult {
        findings,
        warnings: Vec::new(),
    }
}

pub fn detect_consolidation(ctx: &DetectorContext<'_>) -> DetectorResult {
    let mut findings = Vec::new();
    let min_inputs = ctx.config.thresholds.consolidation_min_inputs;
    let max_outputs = ctx.config.thresholds.consolidation_max_outputs;

    for utxo in ctx
        .graph
        .utxos()
        .iter()
        .filter(|utxo| ctx.graph.is_ours(&utxo.address))
    {
        let Some(parent) = ctx.graph.tx(&utxo.txid) else {
            continue;
        };
        if parent.vin.len() < min_inputs || parent.vout.len() > max_outputs {
            continue;
        }
        let parent_inputs = ctx.graph.input_participants(&utxo.txid);
        let our_parent_inputs = parent_inputs.iter().filter(|input| input.is_ours).count();
        findings.push(finding(
            FindingKind::Consolidation,
            Severity::Medium,
            format!(
                "UTXO {}:{} ({:.8} BTC) born from a {}-input consolidation",
                utxo.txid,
                utxo.vout,
                utxo.amount_btc,
                parent.vin.len()
            ),
            json!({
                "txid": utxo.txid,
                "vout": utxo.vout,
                "amount_btc": round_btc(utxo.amount_btc),
                "consolidation_inputs": parent.vin.len(),
                "consolidation_outputs": parent.vout.len(),
                "our_inputs_in_consolidation": our_parent_inputs,
            }),
            Some("Avoid large one-shot consolidations unless you can hide the linkage.".into()),
        ));
    }

    DetectorResult {
        findings,
        warnings: Vec::new(),
    }
}

pub fn detect_script_type_mixing(ctx: &DetectorContext<'_>) -> DetectorResult {
    let mut findings = Vec::new();

    for txid in ctx.graph.our_txids() {
        let inputs = ctx.graph.input_participants(txid);
        if inputs.len() < 2 {
            continue;
        }
        let our_inputs = inputs.iter().filter(|input| input.is_ours).count();
        if our_inputs < 2 {
            continue;
        }

        let mut types = inputs
            .iter()
            .map(|input| input.script_type)
            .filter(|script_type| *script_type != crate::model::DescriptorType::Unknown)
            .collect::<Vec<_>>();
        types.sort();
        types.dedup();

        if types.len() < 2 {
            continue;
        }

        findings.push(finding(
            FindingKind::ScriptTypeMixing,
            Severity::High,
            format!("TX {txid} mixes input script types: {:?}", types),
            json!({
                "txid": txid,
                "script_types": types.iter().map(|script_type| script_type.as_script_name()).collect::<Vec<_>>(),
                "inputs": inputs.iter().map(|input| json!({
                    "address": input.address,
                    "script_type": input.script_type.as_script_name(),
                    "ours": input.is_ours,
                })).collect::<Vec<_>>(),
            }),
            Some("Standardize on a single script family per spend.".into()),
        ));
    }

    DetectorResult {
        findings,
        warnings: Vec::new(),
    }
}

pub fn detect_cluster_merge(ctx: &DetectorContext<'_>) -> DetectorResult {
    let mut findings = Vec::new();

    for txid in ctx.graph.our_txids() {
        let inputs = ctx.graph.input_participants(txid);
        if inputs.len() < 2 {
            continue;
        }
        let our_inputs = inputs
            .iter()
            .filter(|input| input.is_ours)
            .collect::<Vec<_>>();
        if our_inputs.len() < 2 {
            continue;
        }

        let mut funding_sources = serde_json::Map::new();
        let mut source_sets = Vec::new();

        for input in our_inputs {
            let Some(parent_txid) = input.funding_txid.as_deref() else {
                continue;
            };
            let Some(parent_tx) = ctx.graph.tx(parent_txid) else {
                continue;
            };
            let mut sources = parent_tx
                .vin
                .iter()
                .map(|vin| {
                    if vin.coinbase {
                        "coinbase".to_string()
                    } else {
                        vin.previous_txid.chars().take(16).collect::<String>()
                    }
                })
                .collect::<Vec<_>>();
            sources.sort();
            sources.dedup();
            let source_set = sources.iter().cloned().collect::<HashSet<_>>();
            source_sets.push(source_set);
            funding_sources.insert(
                format!(
                    "{}:{}",
                    parent_txid.chars().take(16).collect::<String>(),
                    input.funding_vout.unwrap_or_default()
                ),
                json!(sources),
            );
        }

        let mut merged = false;
        for i in 0..source_sets.len() {
            for j in (i + 1)..source_sets.len() {
                if source_sets[i].is_disjoint(&source_sets[j]) {
                    merged = true;
                }
            }
        }

        if !merged {
            continue;
        }

        findings.push(finding(
            FindingKind::ClusterMerge,
            Severity::High,
            format!(
                "TX {txid} merges UTXOs from {} different funding chains",
                funding_sources.len()
            ),
            json!({
                "txid": txid,
                "funding_sources": funding_sources,
            }),
            Some("Avoid co-spending UTXOs from unrelated provenance clusters.".into()),
        ));
    }

    DetectorResult {
        findings,
        warnings: Vec::new(),
    }
}

pub fn detect_utxo_age_spread(ctx: &DetectorContext<'_>) -> DetectorResult {
    let our_utxos = ctx
        .graph
        .utxos()
        .iter()
        .filter(|utxo| ctx.graph.is_ours(&utxo.address))
        .collect::<Vec<_>>();
    if our_utxos.len() < 2 {
        return DetectorResult::default();
    }

    let mut ordered = our_utxos;
    ordered.sort_by_key(|utxo| std::cmp::Reverse(utxo.confirmations));
    let oldest = ordered.first().expect("ordered has at least two");
    let newest = ordered.last().expect("ordered has at least two");
    let spread = oldest.confirmations.saturating_sub(newest.confirmations);

    let mut findings = Vec::new();
    let mut warnings = Vec::new();

    if spread >= ctx.config.thresholds.utxo_age_spread_blocks {
        findings.push(finding(
            FindingKind::UtxoAgeSpread,
            Severity::Low,
            format!("UTXO age spread of {spread} blocks between oldest and newest"),
            json!({
                "spread_blocks": spread,
                "oldest": {
                    "txid": oldest.txid,
                    "confirmations": oldest.confirmations,
                    "amount_btc": round_btc(oldest.amount_btc),
                },
                "newest": {
                    "txid": newest.txid,
                    "confirmations": newest.confirmations,
                    "amount_btc": round_btc(newest.amount_btc),
                },
            }),
            Some("Normalize UTXO ages or isolate long-dormant coins before spending.".into()),
        ));
    }

    let dormant = ordered
        .iter()
        .filter(|utxo| utxo.confirmations >= ctx.config.thresholds.dormant_utxo_blocks)
        .count();
    if dormant > 0 {
        warnings.push(warning(
            WarningKind::DormantUtxos,
            Severity::Low,
            format!(
                "{} UTXO(s) have ≥{} confirmations (dormant/hoarded coins pattern)",
                dormant, ctx.config.thresholds.dormant_utxo_blocks
            ),
            json!({
                "count": dormant,
                "threshold_blocks": ctx.config.thresholds.dormant_utxo_blocks,
            }),
        ));
    }

    DetectorResult { findings, warnings }
}

pub fn detect_exchange_origin(ctx: &DetectorContext<'_>) -> DetectorResult {
    let mut findings = Vec::new();
    let threshold = ctx.config.thresholds.exchange_batch_outputs;

    for txid in ctx.graph.our_txids() {
        let Some(tx) = ctx.graph.tx(txid) else {
            continue;
        };
        if tx.vout.len() < threshold {
            continue;
        }

        let our_inputs = ctx
            .graph
            .input_participants(txid)
            .into_iter()
            .filter(|input| input.is_ours)
            .collect::<Vec<_>>();
        if !our_inputs.is_empty() {
            continue;
        }
        let our_outputs = ctx
            .graph
            .output_participants(txid)
            .into_iter()
            .filter(|output| output.is_ours)
            .collect::<Vec<_>>();
        if our_outputs.is_empty() {
            continue;
        }

        let mut signals = vec![format!("High output count: {}", tx.vout.len())];
        let unique_recipients = tx
            .vout
            .iter()
            .filter(|output| !output.address.is_empty())
            .map(|output| output.address.clone())
            .collect::<HashSet<_>>();
        if unique_recipients.len() >= threshold {
            signals.push(format!(
                "{} unique recipient addresses",
                unique_recipients.len()
            ));
        }
        if ctx.known_exchange_txids.contains(txid) {
            signals.push("TX matches known exchange wallet history".into());
        }

        let inputs = ctx.graph.input_participants(txid);
        let input_total = inputs.iter().map(|input| input.value_btc).sum::<f64>();
        let mut output_values = tx
            .vout
            .iter()
            .map(|output| output.value_btc)
            .collect::<Vec<_>>();
        output_values.sort_by(|left, right| left.total_cmp(right));
        if let Some(median) = output_values.get(output_values.len() / 2).copied() {
            if median > 0.0 {
                let ratio = input_total / median;
                if ratio > 10.0 {
                    signals.push(format!("Input/median-output ratio: {:.0}x", ratio));
                }
            }
        }

        if signals.len() < 2 {
            continue;
        }

        findings.push(finding(
            FindingKind::ExchangeOrigin,
            Severity::Medium,
            format!(
                "TX {txid} looks like an exchange batch withdrawal ({} signal(s))",
                signals.len()
            ),
            json!({
                "txid": txid,
                "signals": signals,
                "received_outputs": our_outputs.iter().map(|output| json!({
                    "address": output.address,
                    "amount_btc": round_btc(output.value_btc),
                })).collect::<Vec<_>>(),
            }),
            Some(
                "Treat exchange withdrawals as linkable entry points and remix before reuse."
                    .into(),
            ),
        ));
    }

    DetectorResult {
        findings,
        warnings: Vec::new(),
    }
}

pub fn detect_tainted_utxo_merge(ctx: &DetectorContext<'_>) -> DetectorResult {
    if ctx.known_risky_txids.is_empty() {
        return DetectorResult::default();
    }

    let mut findings = Vec::new();
    let mut warnings = Vec::new();

    for txid in ctx.graph.our_txids() {
        let inputs = ctx.graph.input_participants(txid);
        if inputs.len() < 2 || !inputs.iter().any(|input| input.is_ours) {
            continue;
        }

        let mut tainted = Vec::new();
        let mut clean = Vec::new();
        for input in &inputs {
            let is_tainted = input
                .funding_txid
                .as_ref()
                .is_some_and(|funding_txid| ctx.known_risky_txids.contains(funding_txid));
            if is_tainted {
                tainted.push(input);
            } else {
                clean.push(input);
            }
        }

        if !tainted.is_empty() && !clean.is_empty() {
            let taint_pct = (tainted.len() as f64 / inputs.len() as f64 * 100.0).round() as u64;
            findings.push(finding(
                FindingKind::TaintedUtxoMerge,
                Severity::High,
                format!(
                    "TX {txid} merges {} tainted + {} clean inputs ({}% taint)",
                    tainted.len(),
                    clean.len(),
                    taint_pct
                ),
                json!({
                    "txid": txid,
                    "tainted_inputs": tainted.iter().map(|input| participant_json(input)).collect::<Vec<_>>(),
                    "clean_inputs": clean.iter().map(|input| participant_json(input)).collect::<Vec<_>>(),
                    "taint_pct": taint_pct,
                }),
                Some("Keep tainted and clean flows isolated to avoid propagating risk.".into()),
            ));
        }
    }

    for txid in ctx.graph.our_txids() {
        if !ctx.known_risky_txids.contains(txid) {
            continue;
        }
        let our_outputs = ctx
            .graph
            .output_participants(txid)
            .into_iter()
            .filter(|output| output.is_ours)
            .collect::<Vec<_>>();
        if our_outputs.is_empty() {
            continue;
        }
        warnings.push(warning(
            WarningKind::DirectTaint,
            Severity::High,
            format!("TX {txid} is directly from a known risky source"),
            json!({
                "txid": txid,
                "received_outputs": our_outputs.iter().map(|output| json!({
                    "address": output.address,
                    "amount_btc": round_btc(output.value_btc),
                })).collect::<Vec<_>>(),
            }),
        ));
    }

    DetectorResult { findings, warnings }
}

pub fn detect_behavioral_fingerprint(ctx: &DetectorContext<'_>) -> DetectorResult {
    let send_txids = ctx
        .graph
        .our_txids()
        .filter(|txid| {
            ctx.graph
                .input_participants(txid)
                .iter()
                .any(|input| input.is_ours)
        })
        .cloned()
        .collect::<Vec<_>>();
    if send_txids.len() < 3 {
        return DetectorResult::default();
    }

    let mut output_counts = Vec::new();
    let mut input_script_types = Vec::new();
    let mut rbf_signals = Vec::new();
    let mut locktime_values = Vec::new();
    let mut fee_rates = Vec::new();
    let mut n_inputs = Vec::new();
    let mut total_payments = 0usize;
    let mut round_payments = 0usize;
    let mut change_types = HashSet::new();
    let mut payment_types = HashSet::new();

    for txid in &send_txids {
        let Some(tx) = ctx.graph.tx(txid) else {
            continue;
        };
        output_counts.push(tx.vout.len());
        n_inputs.push(tx.vin.len());
        locktime_values.push(tx.locktime);
        rbf_signals.extend(tx.vin.iter().map(|vin| vin.sequence < 0xffff_fffe));

        let inputs = ctx.graph.input_participants(txid);
        input_script_types.extend(
            inputs
                .iter()
                .filter(|input| input.is_ours)
                .map(|input| input.script_type),
        );

        for output in ctx.graph.output_participants(txid) {
            if output.is_ours {
                change_types.insert(output.script_type);
            } else {
                payment_types.insert(output.script_type);
                total_payments += 1;
                if is_round_amount(output.value_sats) {
                    round_payments += 1;
                }
            }
        }

        if tx.vsize > 0 {
            let in_total = inputs.iter().map(|input| input.value_btc).sum::<f64>();
            let out_total = tx.vout.iter().map(|output| output.value_btc).sum::<f64>();
            let fee_sats = ((in_total - out_total) * 100_000_000.0).round();
            if fee_sats > 0.0 {
                fee_rates.push(fee_sats / tx.vsize as f64);
            }
        }
    }

    let mut patterns = Vec::new();

    if total_payments > 0 {
        let round_pct = round_payments as f64 / total_payments as f64 * 100.0;
        if round_pct > 60.0 {
            patterns.push(format!(
                "Round payment amounts: {:.0}% of payments are round numbers",
                round_pct
            ));
        }
    }

    if output_counts.len() >= 3 && output_counts.iter().all(|count| *count == output_counts[0]) {
        patterns.push(format!(
            "Uniform output count: all {} send TXs have exactly {} outputs",
            output_counts.len(),
            output_counts[0]
        ));
    }

    let input_types = input_script_types.iter().copied().collect::<HashSet<_>>();
    if input_types.len() > 1 {
        patterns.push("Mixed input script types used across send transactions".into());
    } else if input_types.len() == 1 && input_types.contains(&crate::model::DescriptorType::P2pkh) {
        patterns.push("All inputs use legacy P2PKH".into());
    }

    if !rbf_signals.is_empty() {
        let rbf_enabled = rbf_signals.iter().filter(|signal| **signal).count();
        if rbf_enabled == rbf_signals.len() {
            patterns.push("RBF always enabled".into());
        } else if rbf_enabled == 0 {
            patterns.push("RBF never enabled".into());
        }
    }

    if locktime_values.len() >= 3 {
        let non_zero = locktime_values.iter().filter(|value| **value > 0).count();
        if non_zero == locktime_values.len() {
            patterns.push("Anti-fee-sniping locktime always set".into());
        } else if non_zero == 0 {
            patterns.push("Locktime always 0".into());
        }
    }

    if fee_rates.len() >= 3 {
        let avg = fee_rates.iter().sum::<f64>() / fee_rates.len() as f64;
        if avg > 0.0 {
            let variance = fee_rates
                .iter()
                .map(|rate| (*rate - avg).powi(2))
                .sum::<f64>()
                / fee_rates.len() as f64;
            let stddev = variance.sqrt();
            let cv = stddev / avg;
            if cv < 0.15 {
                patterns.push(format!("Very consistent fee rate: avg {:.1} sat/vB", avg));
            }
        }
    }

    if !change_types.is_empty() && !payment_types.is_empty() && change_types != payment_types {
        patterns.push("Change uses different script type than payments".into());
    }

    if n_inputs.len() >= 3
        && n_inputs
            .iter()
            .all(|count| *count == n_inputs[0] && *count > 1)
    {
        patterns.push(format!("Always uses exactly {} inputs per TX", n_inputs[0]));
    }

    if patterns.is_empty() {
        return DetectorResult::default();
    }

    DetectorResult {
        findings: vec![finding(
            FindingKind::BehavioralFingerprint,
            Severity::Medium,
            format!(
                "Behavioral fingerprint detected across {} send transactions ({} pattern(s))",
                send_txids.len(),
                patterns.len()
            ),
            json!({
                "send_tx_count": send_txids.len(),
                "patterns": patterns,
            }),
            Some(
                "Vary spend structure and standardize wallet defaults to reduce fingerprinting."
                    .into(),
            ),
        )],
        warnings: Vec::new(),
    }
}

fn finding(
    kind: FindingKind,
    severity: Severity,
    description: String,
    details: serde_json::Value,
    correction: Option<String>,
) -> Finding {
    Finding {
        kind,
        severity,
        description,
        details: FindingDetails::Generic(details),
        correction,
    }
}

fn warning(
    kind: WarningKind,
    severity: Severity,
    description: String,
    details: serde_json::Value,
) -> Warning {
    Warning {
        kind,
        severity,
        description,
        details: WarningDetails::Generic(details),
    }
}

fn participant_json(participant: &TransactionParticipant) -> serde_json::Value {
    json!({
        "address": participant.address,
        "amount_btc": round_btc(participant.value_btc),
        "source_txid": participant.funding_txid,
    })
}

fn round_btc(value: f64) -> f64 {
    (value * 100_000_000.0).round() / 100_000_000.0
}

fn is_round_amount(sats: u64) -> bool {
    sats > 0 && (sats % 100_000 == 0 || sats % 1_000_000 == 0)
}
