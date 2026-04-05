use std::path::PathBuf;
use std::process::ExitCode;
use std::{env, fs};

use stealth_bitcoincore::{read_cookie_file, BitcoinCoreRpc};
use stealth_engine::engine::{AnalysisEngine, EngineSettings, ScanTarget, UtxoInput};

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

    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());
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

    Ok(report.summary.clean)
}

#[derive(Debug, Default)]
struct ScanOpts {
    descriptor: Option<String>,
    descriptors_file: Option<PathBuf>,
    utxos_file: Option<PathBuf>,
    rpc_url: Option<String>,
    rpc_user: Option<String>,
    rpc_pass: Option<String>,
    rpc_cookie: Option<PathBuf>,
    format: Option<String>,
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
            self.rpc_pass
                .clone()
                .or_else(|| env::var("STEALTH_RPC_PASS").ok()),
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
        let mut sources = 0usize;
        if self.descriptor.is_some() {
            sources += 1;
        }
        if self.descriptors_file.is_some() {
            sources += 1;
        }
        if self.utxos_file.is_some() {
            sources += 1;
        }

        if sources == 0 {
            return Err(
                "one input is required: --descriptor, --descriptors, or --utxos".to_owned(),
            );
        }
        if sources > 1 {
            return Err(
                "--descriptor, --descriptors, and --utxos are mutually exclusive".to_owned(),
            );
        }

        if let Some(d) = &self.descriptor {
            return Ok(ScanTarget::Descriptor(d.clone()));
        }
        if let Some(path) = &self.descriptors_file {
            let content = fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let descriptors: Vec<String> = serde_json::from_str(&content)
                .map_err(|e| format!("invalid JSON in {}: {e}", path.display()))?;
            return Ok(ScanTarget::Descriptors(descriptors));
        }
        if let Some(path) = &self.utxos_file {
            let content = fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let utxos: Vec<UtxoInput> = serde_json::from_str(&content)
                .map_err(|e| format!("invalid JSON in {}: {e}", path.display()))?;
            return Ok(ScanTarget::Utxos(utxos));
        }

        Err("no scan target specified".to_owned())
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
            "--rpc-url" => {
                opts.rpc_url = Some(take_value(args, &mut i, "--rpc-url")?);
            }
            "--rpc-user" => {
                opts.rpc_user = Some(take_value(args, &mut i, "--rpc-user")?);
            }
            "--rpc-pass" => {
                opts.rpc_pass = Some(take_value(args, &mut i, "--rpc-pass")?);
            }
            "--rpc-cookie" => {
                opts.rpc_cookie = Some(PathBuf::from(take_value(args, &mut i, "--rpc-cookie")?));
            }
            "--format" => {
                opts.format = Some(take_value(args, &mut i, "--format")?);
            }
            other => return Err(format!("unknown flag '{other}'")),
        }
        i += 1;
    }

    Ok(opts)
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
    println!(
        "Scanned {} transactions, {} addresses, {} current UTXOs\n",
        report.stats.transactions_analyzed, report.stats.addresses_seen, report.stats.utxos_current,
    );

    if report.summary.clean {
        println!("No privacy issues found.");
        return;
    }

    if !report.findings.is_empty() {
        println!("Findings ({}):", report.findings.len());
        for f in &report.findings {
            println!(
                "  [{severity}] {vtype}: {desc}",
                severity = f.severity,
                vtype = f.vulnerability_type,
                desc = f.description,
            );
        }
        println!();
    }

    if !report.warnings.is_empty() {
        println!("Warnings ({}):", report.warnings.len());
        for w in &report.warnings {
            println!(
                "  [{severity}] {vtype}: {desc}",
                severity = w.severity,
                vtype = w.vulnerability_type,
                desc = w.description,
            );
        }
    }
}

fn print_usage() {
    eprintln!("stealth-cli – Bitcoin UTXO privacy vulnerability scanner\n");
    eprintln!("USAGE:");
    eprintln!("  stealth-cli scan [OPTIONS]\n");
    eprintln!("SCAN INPUT (one required, mutually exclusive):");
    eprintln!("  --descriptor <DESC>      Single output descriptor");
    eprintln!("  --descriptors <FILE>     JSON array of descriptors");
    eprintln!("  --utxos <FILE>           JSON array of {{txid,vout,...}}\n");
    eprintln!("RPC CONNECTION:");
    eprintln!("  --rpc-url <URL>          bitcoind RPC endpoint");
    eprintln!("  --rpc-user <USER>        RPC username");
    eprintln!("  --rpc-pass <PASS>        RPC password");
    eprintln!("  --rpc-cookie <PATH>      Path to .cookie file\n");
    eprintln!("  Env vars: STEALTH_RPC_URL, STEALTH_RPC_USER,");
    eprintln!("            STEALTH_RPC_PASS, STEALTH_RPC_COOKIE\n");
    eprintln!("OUTPUT:");
    eprintln!("  --format <text|json>     Output format (default: text)\n");
    eprintln!("EXIT CODES:");
    eprintln!("  0  scan completed, no findings");
    eprintln!("  1  scan completed, findings present");
    eprintln!("  2  error");
}
