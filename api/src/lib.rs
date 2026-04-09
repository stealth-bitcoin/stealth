mod error;
mod preflight;
mod routes;

use std::sync::Arc;

use axum::Router;
use stealth_engine::gateway::BlockchainGateway;

/// Shared application state: an optional blockchain gateway.
pub type GatewayState = Option<Arc<dyn BlockchainGateway + Send + Sync>>;

/// Build the router without a gateway (503 on every scan request).
pub fn app() -> Router {
    app_with_gateway(None)
}

/// Build the router with a concrete [`BlockchainGateway`].
pub fn app_with_gateway(gateway: GatewayState) -> Router {
    Router::new()
        .nest("/api/wallet", routes::wallet::router())
        .with_state(gateway)
}
