use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ini::Ini;
use stealth_api::app_with_gateway;
use stealth_api::rpc::{self, RpcSettings};
use stealth_bitcoincore::{default_cookie_candidates, network_for_rpc_port, BitcoinCoreRpc};
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
    let settings = RpcSettings {
        user: std::env::var("STEALTH_RPC_USER").ok(),
        pass: std::env::var("STEALTH_RPC_PASS").ok(),
        cookie: std::env::var_os("STEALTH_RPC_COOKIE").map(PathBuf::from),
        url,
    };
    Ok(rpc::build_gateway(
        &settings,
        read_bitcoin_conf_credentials,
        || detect_cookie_file(&settings.url),
    )?)
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

    let network = network_for_rpc_port(port).unwrap_or("mainnet");
    default_cookie_candidates(&bitcoin_dir, network)
        .into_iter()
        .find(|candidate| candidate.exists())
}

fn read_bitcoin_conf_credentials() -> Option<(String, String)> {
    let conf = Ini::load_from_file("bitcoin.conf").ok()?;
    let try_section = |props: &ini::Properties| -> Option<(String, String)> {
        let user = props.get("rpcuser")?;
        let pass = props.get("rpcpassword")?;
        Some((user.to_owned(), pass.to_owned()))
    };
    try_section(conf.general_section())
        .or_else(|| conf.section(Some("regtest")).and_then(try_section))
        .or_else(|| conf.section(Some("test")).and_then(try_section))
        .or_else(|| conf.section(Some("signet")).and_then(try_section))
        .or_else(|| conf.section(Some("main")).and_then(try_section))
}
