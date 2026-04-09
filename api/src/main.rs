use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use stealth_api::app_with_gateway;
use stealth_bitcoincore::{read_cookie_file, BitcoinCoreRpc};
use stealth_engine::gateway::BlockchainGateway;
use tracing_subscriber::EnvFilter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    // `BitcoinCoreRpc` uses `reqwest::blocking::Client`, which must be
    // constructed outside a Tokio runtime.
    let gateway: Arc<dyn BlockchainGateway + Send + Sync> = Arc::new(build_gateway()?);
    let bind_addr = read_bind_addr()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_server(bind_addr, gateway.clone()))?;
    // Keep one strong reference until after async serving ends so the blocking
    // client drops outside async context.
    drop(gateway);
    Ok(())
}

async fn run_server(
    bind_addr: SocketAddr,
    gateway: Arc<dyn BlockchainGateway + Send + Sync>,
) -> std::io::Result<()> {
    let app = app_with_gateway(Some(gateway));
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    tracing::info!(%bind_addr, "stealth-api listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn read_bind_addr() -> Result<SocketAddr, String> {
    let raw = std::env::var("STEALTH_API_BIND").unwrap_or_else(|_| "127.0.0.1:20899".to_owned());
    raw.parse::<SocketAddr>()
        .map_err(|_| format!("invalid STEALTH_API_BIND value: {raw}"))
}

fn build_gateway() -> Result<BitcoinCoreRpc, Box<dyn std::error::Error>> {
    let url = std::env::var("STEALTH_RPC_URL").unwrap_or_else(|_| auto_detect_rpc_url());
    let env_user = std::env::var("STEALTH_RPC_USER").ok();
    let env_pass = std::env::var("STEALTH_RPC_PASS").ok();
    let env_cookie = std::env::var("STEALTH_RPC_COOKIE").ok();

    let (user, pass) = if let (Some(user), Some(pass)) = (env_user, env_pass) {
        tracing::info!(rpc_url = %url, rpc_auth = "userpass", "stealth-api RPC configured");
        (Some(user), Some(pass))
    } else if let Some(cookie_path) = env_cookie {
        let (u, p) = read_cookie_file(Path::new(&cookie_path))?;
        tracing::info!(rpc_url = %url, rpc_auth = "cookie", "stealth-api RPC configured");
        (Some(u), Some(p))
    } else if let Some((user, pass)) = read_bitcoin_conf_credentials() {
        tracing::info!(rpc_url = %url, rpc_auth = "bitcoin.conf", "stealth-api RPC configured");
        (Some(user), Some(pass))
    } else if let Some(cookie) = detect_cookie_file(&url) {
        let (u, p) = read_cookie_file(&cookie)?;
        tracing::info!(rpc_url = %url, rpc_auth = "cookie", "stealth-api RPC configured");
        (Some(u), Some(p))
    } else {
        tracing::info!(rpc_url = %url, rpc_auth = "none", "stealth-api RPC configured");
        (None, None)
    };

    Ok(BitcoinCoreRpc::from_url(&url, user, pass)?)
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .without_time()
        .try_init();
}

fn auto_detect_rpc_url() -> String {
    // Prefer regtest first for local development workflows.
    const CANDIDATES: [(&str, &str); 4] = [
        ("http://127.0.0.1:18443", "regtest"),
        ("http://127.0.0.1:8332", "mainnet"),
        ("http://127.0.0.1:18332", "testnet"),
        ("http://127.0.0.1:38332", "signet"),
    ];

    for (url, network) in CANDIDATES {
        if rpc_port_reachable(url) {
            tracing::info!(rpc_url = %url, %network, "auto-detected local bitcoind RPC");
            return url.to_owned();
        }
    }

    let fallback = "http://127.0.0.1:8332".to_owned();
    tracing::warn!(
        rpc_url = %fallback,
        "could not auto-detect a local bitcoind RPC port; using fallback"
    );
    fallback
}

fn rpc_port_reachable(url: &str) -> bool {
    let Some((host, port)) = host_port_from_url(url) else {
        return false;
    };

    let Ok(addrs) = (host.as_str(), port).to_socket_addrs() else {
        return false;
    };

    for addr in addrs {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok() {
            return true;
        }
    }
    false
}

fn host_port_from_url(url: &str) -> Option<(String, u16)> {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = without_scheme.split('/').next()?;
    let (host, port_str) = authority.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    Some((host.to_owned(), port))
}

fn detect_cookie_file(url: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let bitcoin_dir = PathBuf::from(home).join(".bitcoin");
    let port = host_port_from_url(url)
        .map(|(_, port)| port)
        .unwrap_or(8332);

    for candidate in cookie_candidates(&bitcoin_dir, port) {
        if candidate.exists() {
            return Some(candidate);
        }
    }
    cookie_candidates(&bitcoin_dir, port)
        .into_iter()
        .find(|candidate| candidate.exists())
}

fn cookie_candidates(bitcoin_dir: &Path, port: u16) -> Vec<PathBuf> {
    match port {
        18443 => vec![
            bitcoin_dir.join("regtest/.cookie"),
            bitcoin_dir.join(".cookie"),
        ],
        18332 => vec![
            bitcoin_dir.join("testnet4/.cookie"),
            bitcoin_dir.join("testnet3/.cookie"),
            bitcoin_dir.join("testnet/.cookie"),
            bitcoin_dir.join(".cookie"),
        ],
        38332 => vec![
            bitcoin_dir.join("signet/.cookie"),
            bitcoin_dir.join(".cookie"),
        ],
        _ => vec![bitcoin_dir.join(".cookie")],
    }
}

fn read_bitcoin_conf_credentials() -> Option<(String, String)> {
    let conf_path = PathBuf::from("bitcoin.conf");
    let conf = std::fs::read_to_string(conf_path).ok()?;

    let mut user: Option<String> = None;
    let mut pass: Option<String> = None;

    for raw_line in conf.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with('[')
        {
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.trim();
        if value.is_empty() {
            continue;
        }

        match key {
            "rpcuser" => user = Some(value.to_owned()),
            "rpcpassword" => pass = Some(value.to_owned()),
            _ => {}
        }
    }

    match (user, pass) {
        (Some(user), Some(pass)) => Some((user, pass)),
        _ => None,
    }
}
