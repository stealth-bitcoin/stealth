mod cors;
mod error;
mod host;
mod jobs;
mod routes;
pub mod rpc;

use std::sync::Arc;

use axum::Router;
use stealth_engine::gateway::BlockchainGateway;

pub use cors::{AllowedOrigins, InvalidOrigin};
pub use host::{AllowedHosts, InvalidHost};
use jobs::JobStore;

/// Shared application state: an optional blockchain gateway.
pub type GatewayState = Option<Arc<dyn BlockchainGateway + Send + Sync>>;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) gateway: GatewayState,
    pub(crate) jobs: Arc<JobStore>,
}

/// Build the router without a gateway (503 on every scan request).
pub fn app() -> Router {
    app_with_gateway(None)
}

/// Build the router with a concrete [`BlockchainGateway`], allowing only
/// loopback web origins.
pub fn app_with_gateway(gateway: GatewayState) -> Router {
    app_with_cors(gateway, AllowedOrigins::localhost())
}

/// Build the router with a gateway and the web origins allowed by CORS.
/// It does not check the `Host` header; `stealth-api` serves [`app_with_hosts`].
pub fn app_with_cors(gateway: GatewayState, origins: AllowedOrigins) -> Router {
    let state = AppState {
        gateway,
        jobs: Arc::new(JobStore::default()),
    };
    Router::new()
        .nest("/api/wallet", routes::wallet::router())
        .layer(origins.layer())
        .with_state(state)
}

/// Build the router served by `stealth-api`: CORS plus a `Host` header check
/// that refuses, with 403, any request not addressed to one of `hosts`.
pub fn app_with_hosts(
    gateway: GatewayState,
    origins: AllowedOrigins,
    hosts: AllowedHosts,
) -> Router {
    // Router::layer wraps each route's MethodRouter, which adds `Allow` outside the layer;
    // wrapping the whole router as a fallback service keeps the check outermost.
    Router::new()
        .fallback_service(app_with_cors(gateway, origins))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(hosts),
            host::check_host,
        ))
}
