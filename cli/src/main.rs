use std::path::PathBuf;
use std::process::ExitCode;
use std::{env, fs};

use stealth_bitcoincore::{read_cookie_file, BitcoinCoreRpc};
use stealth_engine::engine::{AnalysisEngine, EngineSettings, ScanTarget, UtxoInput};
use stealth_engine::types::{Finding, Summary};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_usage();
        return ExitCode::SUCCESS;
    }

    if args[0] != "scan" {
        eprintln!(
            "error: unknown command '{}' (try 'stealth-cli --help')",
            args[0]
        );
        return ExitCode::from(2);
    }

    match run_scan(&args[1..]) {
        Ok(clean) => {
            if clean {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}

fn run_scan(args: &[String]) -> Result<bool, String> {
    let opts = parse_scan_args(args)?;
    let gateway = opts.build_gateway()?;
    let target = opts.scan_target()?;

    let engine = AnalysisEngine::new(&gateway, opts.engine_settings()?);
    let report = engine.analyze(target).map_err(|e| e.to_string())?;

    match opts.format.as_deref() {
        Some("text") | None => print_text_report(&report),
        Some("json") => {
            let json = serde_json::to_string_pretty(&report)
                .map_err(|e| format!("serialization failed: {e}"))?;
            println!("{json}");
        }
        Some(other) => return Err(format!("unsupported format '{other}' (use json or text)")),
    }

    Ok(scan_succeeded(&report.summary))
}

/// Nothing was analyzed and nothing was reported. Findings alongside zero
/// analyzed transactions would make the empty-scan notice a contradiction, so
/// the findings take precedence.
fn is_empty_report(summary: &Summary) -> bool {
    summary.analyzed_nothing && summary.findings == 0 && summary.warnings == 0
}

/// Exit 0 only when there is nothing to report: a clean history, or a scan
/// that analyzed nothing and found nothing.
fn scan_succeeded(summary: &Summary) -> bool {
    if summary.findings > 0 || summary.warnings > 0 {
        return false;
    }
    summary.clean || summary.analyzed_nothing
}

/// Worst first; the engine's order within one severity.
fn by_severity(list: &[Finding]) -> Vec<&Finding> {
    let mut sorted: Vec<&Finding> = list.iter().collect();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.severity));
    sorted
}

#[derive(Debug, Default)]
struct ScanOpts {
    descriptor: Option<String>,
    descriptors_file: Option<PathBuf>,
    utxos_file: Option<PathBuf>,
    rescan_since: Option<u64>,
    rpc_url: Option<String>,
    rpc_user: Option<String>,
    rpc_cookie: Option<PathBuf>,
    format: Option<String>,
    cache_wallet: bool,
}

impl ScanOpts {
    fn build_gateway(&self) -> Result<BitcoinCoreRpc, String> {
        let url = self
            .rpc_url
            .clone()
            .or_else(|| env::var("STEALTH_RPC_URL").ok())
            .ok_or("--rpc-url or STEALTH_RPC_URL is required")?;

        let (user, pass) = match (
            self.rpc_user
                .clone()
                .or_else(|| env::var("STEALTH_RPC_USER").ok()),
            env::var("STEALTH_RPC_PASS").ok(),
            self.rpc_cookie
                .clone()
                .or_else(|| env::var("STEALTH_RPC_COOKIE").ok().map(PathBuf::from)),
        ) {
            (Some(user), Some(pass), _) => (Some(user), Some(pass)),
            (_, _, Some(cookie_path)) => {
                let (u, p) = read_cookie_file(&cookie_path).map_err(|e| e.to_string())?;
                (Some(u), Some(p))
            }
            _ => (None, None),
        };

        BitcoinCoreRpc::from_url(&url, user, pass).map_err(|e| e.to_string())
    }

    fn scan_target(&self) -> Result<ScanTarget, String> {
        if self.descriptor.is_some()
            && (self.descriptors_file.is_some() || self.utxos_file.is_some())
        {
            return Err("--descriptor cannot be combined with other inputs".to_owned());
        }

        // --utxos may be combined with --descriptors: the descriptors act
        // as ownership context so the scan recognises the user's inputs.
        if let Some(path) = &self.utxos_file {
            let utxos: Vec<UtxoInput> = read_json(path)?;
            return Ok(ScanTarget::Utxos(utxos));
        }
        if let Some(path) = &self.descriptors_file {
            let descriptors: Vec<String> = read_json(path)?;
            return Ok(ScanTarget::Descriptors(descriptors));
        }
        if let Some(d) = &self.descriptor {
            return Ok(ScanTarget::Descriptor(d.clone()));
        }

        Err("one input is required: --descriptor, --descriptors, or --utxos".to_owned())
    }

    fn engine_settings(&self) -> Result<EngineSettings, String> {
        Ok(EngineSettings {
            rescan_since: self.rescan_since,
            ownership_descriptors: self.ownership_descriptors()?,
            persist_scan_wallet: self.cache_wallet,
            ..EngineSettings::default()
        })
    }

    fn ownership_descriptors(&self) -> Result<Vec<String>, String> {
        match (&self.utxos_file, &self.descriptors_file) {
            (Some(_), Some(path)) => read_json(path),
            _ => Ok(Vec::new()),
        }
    }
}

fn parse_scan_args(args: &[String]) -> Result<ScanOpts, String> {
    let mut opts = ScanOpts::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--descriptor" => {
                opts.descriptor = Some(take_value(args, &mut i, "--descriptor")?);
            }
            "--descriptors" => {
                opts.descriptors_file =
                    Some(PathBuf::from(take_value(args, &mut i, "--descriptors")?));
            }
            "--utxos" => {
                opts.utxos_file = Some(PathBuf::from(take_value(args, &mut i, "--utxos")?));
            }
            "--rescan-since" => {
                let raw = take_value(args, &mut i, "--rescan-since")?;
                let ts = raw.parse::<u64>().map_err(|_| {
                    format!("--rescan-since expects a unix timestamp in seconds, got '{raw}'")
                })?;
                opts.rescan_since = Some(ts);
            }
            "--rpc-url" => {
                opts.rpc_url = Some(take_value(args, &mut i, "--rpc-url")?);
            }
            "--rpc-user" => {
                opts.rpc_user = Some(take_value(args, &mut i, "--rpc-user")?);
            }
            "--rpc-cookie" => {
                opts.rpc_cookie = Some(PathBuf::from(take_value(args, &mut i, "--rpc-cookie")?));
            }
            "--format" => {
                opts.format = Some(take_value(args, &mut i, "--format")?);
            }
            "--cache-wallet" => {
                opts.cache_wallet = true;
            }
            other => return Err(format!("unknown flag '{other}'")),
        }
        i += 1;
    }

    Ok(opts)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&content).map_err(|e| format!("invalid JSON in {}: {e}", path.display()))
}

fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    let value = args
        .get(*i)
        .ok_or_else(|| format!("{flag} requires a value"))?;

    if value.starts_with('-') {
        return Err(format!("{flag} requires a value"));
    }

    Ok(value.clone())
}

fn print_text_report(report: &stealth_engine::Report) {
    print!("{}", text_report(report));
}

fn text_report(report: &stealth_engine::Report) -> String {
    let mut lines = vec![format!(
        "Scanned {} transactions, {} addresses, {} current UTXOs\n",
        report.stats.transactions_analyzed, report.stats.addresses_seen, report.stats.utxos_current,
    )];

    let unserved = report.stats.addresses_without_history;
    if unserved > 0 {
        lines.push(format!(
            "The node could not serve the chain history of {unserved} address{}; \
             the counts for {} cover only the outputs you pasted.\n",
            if unserved == 1 { "" } else { "es" },
            if unserved == 1 { "it" } else { "them" },
        ));
    }

    if is_empty_report(&report.summary) {
        lines.push("No transactions found for this input.".to_owned());
        lines.push(
            "Nothing was analyzed — this can mean an unused address, a wallet whose \
             activity predates the rescan window, purely off-chain (e.g. Lightning) \
             history, or a node still catching up to the chain tip."
                .to_owned(),
        );
        return lines.join("\n") + "\n";
    }

    if report.summary.clean {
        lines.push("No privacy issues found.".to_owned());
        return lines.join("\n") + "\n";
    }

    if !report.findings.is_empty() {
        lines.push(format!("Findings ({}):", report.findings.len()));
        lines.extend(by_severity(&report.findings).into_iter().map(finding_line));
        lines.push(String::new());
    }
    if !report.warnings.is_empty() {
        lines.push(format!("Warnings ({}):", report.warnings.len()));
        lines.extend(by_severity(&report.warnings).into_iter().map(finding_line));
    }
    lines.join("\n") + "\n"
}

fn finding_line(f: &Finding) -> String {
    format!(
        "  [{severity}] {vtype}: {desc}",
        severity = f.severity,
        vtype = f.vulnerability_type,
        desc = f.description,
    )
}

fn print_usage() {
    eprintln!("stealth-cli – Bitcoin UTXO privacy vulnerability scanner\n");
    eprintln!("USAGE:");
    eprintln!("  stealth-cli scan [OPTIONS]\n");
    eprintln!("SCAN INPUT (one required, mutually exclusive):");
    eprintln!("  --descriptor <DESC>      Output descriptor OR bare extended public key");
    eprintln!("  --descriptors <FILE>     JSON array of descriptors");
    eprintln!("  --utxos <FILE>           JSON array of {{txid,vout,...}}");
    eprintln!("                           May be combined with --descriptors, which then");
    eprintln!("                           act as ownership context for the analysis\n");
    eprintln!("DESCRIPTOR OPTIONS:");
    eprintln!("  --rescan-since <UNIX_TS> Rescan from this time when importing");
    eprintln!("                           descriptors (default: genesis; set this");
    eprintln!("                           to the wallet's birth time on mainnet)");
    eprintln!("  --cache-wallet           Keep a persistent watch-only wallet keyed to");
    eprintln!("                           the descriptors so repeat scans skip the full");
    eprintln!("                           rescan (default: off, wallet is discarded).");
    eprintln!("                           Trade-off: this writes the viewing key (xpub)");
    eprintln!("                           into Core's wallet DB in plaintext and leaves a");
    eprintln!("                           durable _stealth_cache_<hash> wallet revealing");
    eprintln!("                           the descriptors were scanned. Use only on a");
    eprintln!("                           node you trust.\n");
    eprintln!("RPC CONNECTION:");
    eprintln!("  --rpc-url <URL>          bitcoind RPC endpoint");
    eprintln!("  --rpc-user <USER>        RPC username");
    eprintln!("  --rpc-cookie <PATH>      Path to .cookie file (recommended)\n");
    eprintln!("  Env vars: STEALTH_RPC_URL, STEALTH_RPC_USER,");
    eprintln!("            STEALTH_RPC_PASS, STEALTH_RPC_COOKIE\n");
    eprintln!("OUTPUT:");
    eprintln!("  --format <text|json>     Output format (default: text)\n");
    eprintln!("EXIT CODES:");
    eprintln!("  0  scan completed, no findings");
    eprintln!("  1  scan completed, findings present");
    eprintln!("  2  error");
}

#[cfg(test)]
mod tests;
