mod error;
mod preflight;
mod routes;

use std::sync::Arc;

use axum::Router;
use stealth_core::scanner::RpcConfig;

pub fn app() -> Router {
    app_with_rpc(None)
}

pub fn app_with_rpc(rpc_config: Option<RpcConfig>) -> Router {
    let state: Option<Arc<RpcConfig>> = rpc_config.map(Arc::new);
    Router::new()
        .nest("/api/wallet", routes::wallet::router())
        .with_state(state)
}
