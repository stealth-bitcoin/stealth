use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing::get};
use serde::{Deserialize, Serialize};
use stealth_bitcoincore::{BitcoinCoreConfig, BitcoinCoreRpc};
use stealth_core::engine::{AnalysisEngine, EngineSettings, ScanTarget};
use stealth_core::error::AnalysisError;
use stealth_core::gateway::BlockchainGateway;
use stealth_core::model::AnalysisReport;
use tower_http::cors::CorsLayer;

pub trait ScanService: Send + Sync + 'static {
    fn analyze_descriptor(&self, descriptor: String) -> Result<AnalysisReport, AnalysisError>;
}

pub struct CoreScanService<G> {
    gateway: G,
    settings: EngineSettings,
}

impl<G> CoreScanService<G> {
    pub fn new(gateway: G, settings: EngineSettings) -> Self {
        Self { gateway, settings }
    }
}

impl<G> ScanService for CoreScanService<G>
where
    G: BlockchainGateway + Send + Sync + 'static,
{
    fn analyze_descriptor(&self, descriptor: String) -> Result<AnalysisReport, AnalysisError> {
        AnalysisEngine::new(&self.gateway, self.settings.clone())
            .analyze(ScanTarget::Descriptors(vec![descriptor]))
    }
}

pub fn default_bitcoin_config_path() -> PathBuf {
    PathBuf::from("backend/script/config.ini")
}

pub fn build_runtime_service(
    config_path: &Path,
    settings: EngineSettings,
) -> Result<CoreScanService<BitcoinCoreRpc>, AnalysisError> {
    let config = BitcoinCoreConfig::from_ini_file(config_path)?;
    let gateway = BitcoinCoreRpc::new(config)?;
    Ok(CoreScanService::new(gateway, settings))
}

pub fn build_router<S>(service: Arc<S>, cors_origin: Option<&str>) -> Router
where
    S: ScanService,
{
    let mut router = Router::new()
        .route("/api/wallet/scan", get(scan_handler::<S>))
        .with_state(service);

    if let Some(origin) = cors_origin {
        if let Ok(header_value) = HeaderValue::from_str(origin) {
            router = router.layer(
                CorsLayer::new()
                    .allow_origin(header_value)
                    .allow_methods([Method::GET])
                    .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::ACCEPT]),
            );
        }
    }

    router
}

#[derive(Debug, Deserialize)]
struct ScanQuery {
    descriptor: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

async fn scan_handler<S>(State(service): State<Arc<S>>, Query(query): Query<ScanQuery>) -> Response
where
    S: ScanService,
{
    let Some(descriptor) = query.descriptor.map(|value| value.trim().to_string()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "descriptor query parameter is required".into(),
        );
    };
    if descriptor.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "descriptor query parameter is required".into(),
        );
    }

    match service.analyze_descriptor(descriptor) {
        Ok(report) => Json(report).into_response(),
        Err(error) => map_error(error),
    }
}

fn map_error(error: AnalysisError) -> Response {
    match error {
        AnalysisError::EmptyDescriptor | AnalysisError::DescriptorNormalization { .. } => {
            json_error(StatusCode::BAD_REQUEST, error.to_string())
        }
        AnalysisError::AnalysisEmpty => json_error(StatusCode::NOT_FOUND, error.to_string()),
        AnalysisError::EnvironmentUnavailable(_) => {
            json_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
        }
    }
}

fn json_error(status: StatusCode, message: String) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::json;
    use tower::util::ServiceExt;

    use super::*;

    struct MockService(Result<AnalysisReport, AnalysisError>);

    impl ScanService for MockService {
        fn analyze_descriptor(&self, _descriptor: String) -> Result<AnalysisReport, AnalysisError> {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn returns_400_for_missing_descriptor() {
        let app = build_router(
            Arc::new(MockService(Ok(AnalysisReport::new(
                0,
                0,
                Vec::new(),
                Vec::new(),
            )))),
            None,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_json_report_for_successful_scan() {
        let report = AnalysisReport::new(1, 2, Vec::new(), Vec::new());
        let app = build_router(Arc::new(MockService(Ok(report))), None);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan?descriptor=wpkh(test)")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
        assert_eq!(json["summary"]["clean"], json!(true));
    }
}
