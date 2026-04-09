use axum::{extract::State, routing::post, Json, Router};
use serde::Deserialize;
use stealth_engine::engine::{AnalysisEngine, EngineSettings, ScanTarget, UtxoInput};
use stealth_engine::Report;

use crate::error::ApiError;
use crate::preflight::validate;
use crate::GatewayState;

pub fn router() -> Router<GatewayState> {
    Router::new().route("/scan", post(scan_post))
}

#[derive(Debug, Deserialize)]
struct ScanRequestBody {
    #[serde(default)]
    descriptor: Option<String>,
    #[serde(default)]
    descriptors: Option<Vec<String>>,
    #[serde(default)]
    utxos: Option<Vec<UtxoInput>>,
}

async fn scan_post(
    State(gateway): State<GatewayState>,
    Json(body): Json<ScanRequestBody>,
) -> Result<Json<Report>, ApiError> {
    let target = body.into_scan_target()?;
    let target = validate(target)?;

    let gw = gateway.ok_or(ApiError::ScannerNotConfigured)?;
    let report = tokio::task::spawn_blocking(move || {
        let engine = AnalysisEngine::new(gw.as_ref(), EngineSettings::default());
        engine.analyze(target)
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))??;

    Ok(Json(report))
}

impl ScanRequestBody {
    fn into_scan_target(self) -> Result<ScanTarget, ApiError> {
        let mut selected_sources = 0usize;
        if self.descriptor.is_some() {
            selected_sources += 1;
        }
        if self.descriptors.is_some() {
            selected_sources += 1;
        }
        if self.utxos.is_some() {
            selected_sources += 1;
        }

        if selected_sources == 0 {
            return Err(ApiError::bad_request(
                "one input source is required: descriptor, descriptors, or utxos",
            ));
        }
        if selected_sources > 1 {
            return Err(ApiError::bad_request(
                "descriptor, descriptors, and utxos are mutually exclusive",
            ));
        }

        if let Some(descriptor) = self.descriptor {
            return Ok(ScanTarget::Descriptor(descriptor));
        }
        if let Some(descriptors) = self.descriptors {
            return Ok(ScanTarget::Descriptors(descriptors));
        }
        if let Some(utxos) = self.utxos {
            return Ok(ScanTarget::Utxos(utxos));
        }

        Err(ApiError::bad_request("invalid scan request body"))
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use crate::app;

    #[tokio::test]
    async fn get_scan_is_not_allowed() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn post_scan_requires_one_input_source() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn post_scan_rejects_multiple_sources() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "descriptor": "wpkh(xpub.../0/*)",
                            "utxos": [
                                {
                                    "txid": "0000000000000000000000000000000000000000000000000000000000000001",
                                    "vout": 0
                                }
                            ]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn post_scan_returns_503_without_rpc_config() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "descriptor": "wpkh(xpub.../0/*)" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "scanner_not_configured");
    }

    #[tokio::test]
    async fn post_scan_rejects_invalid_descriptor() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "descriptor": "" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_scan_input");
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}
