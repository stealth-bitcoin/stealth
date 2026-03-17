use std::path::PathBuf;

use clap::Parser;
use stealth_app::default_bitcoin_config_path;
use stealth_bitcoincore::{BitcoinCoreConfig, BitcoinCoreRpc};
use stealth_core::engine::{AnalysisEngine, EngineSettings, ScanTarget};

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long = "descriptor", short = 'd')]
    descriptors: Vec<String>,
    #[arg(long)]
    wallet: Option<String>,
    #[arg(long, default_value_os_t = default_bitcoin_config_path())]
    config: PathBuf,
    #[arg(long = "known-risky-wallet")]
    known_risky_wallets: Vec<String>,
    #[arg(long = "known-exchange-wallet")]
    known_exchange_wallets: Vec<String>,
    #[arg(long)]
    pretty: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let settings = EngineSettings {
        known_exchange_wallets: cli.known_exchange_wallets,
        known_risky_wallets: cli.known_risky_wallets,
        ..EngineSettings::default()
    };
    let config = BitcoinCoreConfig::from_ini_file(&cli.config)?;
    let gateway = BitcoinCoreRpc::new(config)?;
    let engine = AnalysisEngine::new(&gateway, settings);

    let report = if let Some(wallet_name) = cli.wallet {
        engine.analyze(ScanTarget::WalletName(wallet_name))?
    } else {
        engine.analyze(ScanTarget::Descriptors(cli.descriptors))?
    };

    if cli.pretty {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", serde_json::to_string(&report)?);
    }

    Ok(())
}
