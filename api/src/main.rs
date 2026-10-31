use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ini::Ini;
use stealth_api::rpc::{self, RpcSettings};
use stealth_api::{app_with_cors, AllowedOrigins};
use stealth_bitcoincore::BitcoinCoreRpc;
use stealth_engine::gateway::BlockchainGateway;
use tracing_subscriber::EnvFilter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let origins = read_allowed_origins()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;

    // `BitcoinCoreRpc` uses `reqwest::blocking::Client`, which must be
    // constructed outside a Tokio runtime.
    let gateway: Arc<dyn BlockchainGateway + Send + Sync> = Arc::new(build_gateway()?);
    let bind_addr = read_bind_addr()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_server(bind_addr, gateway.clone(), origins))?;
    // Keep one strong reference until after async serving ends so the blocking
    // client drops outside async context.
    drop(gateway);
    Ok(())
}

async fn run_server(
    bind_addr: SocketAddr,
    gateway: Arc<dyn BlockchainGateway + Send + Sync>,
    origins: AllowedOrigins,
) -> std::io::Result<()> {
    if !origins.extra().is_empty() {
        tracing::info!(extra = ?origins.extra(), "CORS allows loopback origins plus extra origins");
    }
    let app = app_with_cors(Some(gateway), origins);
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

fn read_allowed_origins() -> Result<AllowedOrigins, String> {
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|arg| format!("argument is not valid UTF-8: {}", arg.to_string_lossy()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let env = std::env::var_os("STEALTH_API_ALLOW_ORIGINS")
        .map(|raw| {
            raw.into_string().map_err(|raw| {
                format!(
                    "STEALTH_API_ALLOW_ORIGINS is not valid UTF-8: {}",
                    raw.to_string_lossy()
                )
            })
        })
        .transpose()?;
    allowed_origins_from(args.into_iter(), env)
}

fn allowed_origins_from(
    mut args: impl Iterator<Item = String>,
    env: Option<String>,
) -> Result<AllowedOrigins, String> {
    let mut origins = AllowedOrigins::localhost();
    if let Some(raw) = env {
        let values = raw
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty());
        origins = origins
            .with_extra(values)
            .map_err(|error| format!("invalid STEALTH_API_ALLOW_ORIGINS value: {error}"))?;
    }

    let mut flagged = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--allow-origin" {
            let value = args.next().ok_or(
                "--allow-origin needs a value, e.g. --allow-origin https://wallet.example.org",
            )?;
            flagged.push(value);
        } else if let Some(value) = arg.strip_prefix("--allow-origin=") {
            flagged.push(value.to_owned());
        } else {
            return Err(format!(
                "unknown argument: {arg} (supported: --allow-origin <origin>)"
            ));
        }
    }
    origins
        .with_extra(flagged)
        .map_err(|error| format!("invalid --allow-origin value: {error}"))
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

    rpc::cookie_candidates_for_port(&bitcoin_dir, port)
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
