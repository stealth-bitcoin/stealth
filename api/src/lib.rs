mod cors;
mod error;
mod jobs;
mod routes;
pub mod rpc;

use std::sync::Arc;

use axum::Router;
use stealth_engine::gateway::BlockchainGateway;

pub use cors::{AllowedOrigins, InvalidOrigin};
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
