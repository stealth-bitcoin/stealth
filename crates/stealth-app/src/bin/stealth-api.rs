use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use stealth_app::{build_router, build_runtime_service, default_bitcoin_config_path};
use stealth_core::engine::EngineSettings;

#[derive(Debug, Parser)]
struct ApiCli {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(long, default_value_t = 8080)]
    port: u16,
    #[arg(long, default_value = "http://localhost:5173")]
    cors_origin: String,
    #[arg(long, default_value_os_t = default_bitcoin_config_path())]
    config: PathBuf,
    #[arg(long = "known-risky-wallet")]
    known_risky_wallets: Vec<String>,
    #[arg(long = "known-exchange-wallet")]
    known_exchange_wallets: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = ApiCli::parse();
    let settings = EngineSettings {
        known_exchange_wallets: cli.known_exchange_wallets,
        known_risky_wallets: cli.known_risky_wallets,
        ..EngineSettings::default()
    };
    let service = build_runtime_service(&cli.config, settings)?;
    let router = build_router(Arc::new(service), Some(&cli.cors_origin));
    let addr: SocketAddr = format!("{}:{}", cli.host, cli.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
