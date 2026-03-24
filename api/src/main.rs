use std::net::SocketAddr;

use stealth_api::app_with_rpc;
use stealth_core::scanner::{RpcAuth, RpcConfig};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let rpc_config = read_rpc_config();
    if rpc_config.is_none() {
        tracing::warn!("STEALTH_RPC_URL not set – scan endpoint will return 503 until configured");
    }

    let bind_addr = read_bind_addr()?;
    let app = app_with_rpc(rpc_config);
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

fn read_rpc_config() -> Option<RpcConfig> {
    let url = std::env::var("STEALTH_RPC_URL").ok()?;
    let auth = match (
        std::env::var("STEALTH_RPC_USER").ok(),
        std::env::var("STEALTH_RPC_PASS").ok(),
        std::env::var("STEALTH_RPC_COOKIE").ok(),
    ) {
        (Some(user), Some(pass), _) => RpcAuth::UserPass { user, pass },
        (_, _, Some(cookie)) => RpcAuth::CookieFile(cookie.into()),
        _ => RpcAuth::None,
    };
    Some(RpcConfig { url, auth })
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .without_time()
        .try_init();
}
