use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use stealth_engine::engine::{AnalysisEngine, EngineSettings, ScanTarget, UtxoInput};
use stealth_engine::progress::{ScanPhase, ScanProgress};
use stealth_engine::Report;

use crate::error::ApiError;
use crate::jobs::JobOutcome;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/scan", post(scan_post))
        .route("/scans", post(scans_create))
        .route("/scans/{id}", get(scans_get).delete(scans_delete))
}

#[derive(Debug, Deserialize)]
struct ScanRequestBody {
    #[serde(default)]
    descriptor: Option<String>,
    #[serde(default)]
    descriptors: Option<Vec<String>>,
    #[serde(default)]
    utxos: Option<Vec<UtxoInput>>,
    #[serde(default)]
    rescan_since: Option<u64>,
}

async fn scan_post(
    State(state): State<AppState>,
    Json(body): Json<ScanRequestBody>,
) -> Result<Json<Report>, ApiError> {
    let rescan_since = body.rescan_since;
    let (target, ownership_descriptors) = body.into_scan_request()?;

    let gw = state.gateway.ok_or(ApiError::ScannerNotConfigured)?;
    let report = tokio::task::spawn_blocking(move || {
        let settings = EngineSettings {
            rescan_since,
            ownership_descriptors,
            ..EngineSettings::default()
        };
        let engine = AnalysisEngine::new(gw.as_ref(), settings);
        engine.analyze(target)
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))??;

    Ok(Json(report))
}

// ── Asynchronous scan jobs ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ScanJobCreated {
    scan_id: String,
}

// All keys are always present; absent values serialize as null.
#[derive(Debug, Serialize)]
struct ScanJobStatus {
    state: &'static str,
    progress: Option<f32>,
    report: Option<Report>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanJobStateOnly {
    state: &'static str,
}

async fn scans_create(
    State(state): State<AppState>,
    Json(body): Json<ScanRequestBody>,
) -> Result<(StatusCode, Json<ScanJobCreated>), ApiError> {
    let rescan_since = body.rescan_since;
    let (target, ownership_descriptors) = body.into_scan_request()?;

    let sink = ScanProgress::new();
    let scan_id = state.jobs.create(sink.clone());

    match state.gateway {
        None => {
            // No gateway will ever serve this job; fail it before the
            // caller can even poll.
            state.jobs.finish(
                &scan_id,
                JobOutcome::Failed(ApiError::ScannerNotConfigured.to_string()),
            );
        }
        Some(gw) => {
            let jobs = state.jobs.clone();
            let job_id = scan_id.clone();
            // Fire-and-forget: dropping the handle does not stop the task.
            drop(tokio::task::spawn_blocking(move || {
                let settings = EngineSettings {
                    rescan_since,
                    ownership_descriptors,
                    progress: Some(sink.clone()),
                    ..EngineSettings::default()
                };
                let result = AnalysisEngine::new(gw.as_ref(), settings).analyze(target);
                let outcome = if sink.cancel_requested() {
                    JobOutcome::Cancelled
                } else {
                    match result {
                        Ok(report) => JobOutcome::Done(report),
                        Err(error) => JobOutcome::Failed(ApiError::Analysis(error).to_string()),
                    }
                };
                jobs.finish(&job_id, outcome);
            }));
        }
    }

    Ok((StatusCode::ACCEPTED, Json(ScanJobCreated { scan_id })))
}

async fn scans_get(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ScanJobStatus>, ApiError> {
    let view = state
        .jobs
        .view(&id)
        .ok_or_else(|| ApiError::not_found(format!("unknown scan job: {id}")))?;

    let status = match view.outcome {
        Some(JobOutcome::Done(report)) => ScanJobStatus {
            state: "done",
            progress: None,
            report: Some(report),
            error: None,
        },
        Some(JobOutcome::Failed(message)) => ScanJobStatus {
            state: "failed",
            progress: None,
            report: None,
            error: Some(message),
        },
        Some(JobOutcome::Cancelled) => ScanJobStatus {
            state: "cancelled",
            progress: None,
            report: None,
            error: None,
        },
        None => {
            let snapshot = view.progress.snapshot();
            let state_name = phase_state_name(snapshot.phase);
            ScanJobStatus {
                state: state_name,
                // Only the rescan phase has a meaningful percentage.
                progress: (snapshot.phase == ScanPhase::Rescanning)
                    .then_some(snapshot.rescan_progress)
                    .flatten(),
                report: None,
                error: None,
            }
        }
    };
    Ok(Json(status))
}

async fn scans_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<ScanJobStateOnly>), ApiError> {
    let view = state
        .jobs
        .view(&id)
        .ok_or_else(|| ApiError::not_found(format!("unknown scan job: {id}")))?;

    if let Some(outcome) = view.outcome {
        let state_name = match outcome {
            JobOutcome::Done(_) => "done",
            JobOutcome::Failed(_) => "failed",
            JobOutcome::Cancelled => "cancelled",
        };
        return Ok((StatusCode::OK, Json(ScanJobStateOnly { state: state_name })));
    }

    // The worker observes the flag when the (aborted) scan returns and
    // finishes the job as cancelled; the rescan poller also honours it
    // in case the wallet was not created yet when this request arrived.
    view.progress.request_cancel();
    let wallet_name = view.progress.snapshot().wallet_name;
    if let (Some(gw), Some(wallet_name)) = (state.gateway, wallet_name) {
        // The gateway client is blocking; keep it off the async runtime.
        drop(tokio::task::spawn_blocking(move || {
            gw.cancel_rescan(&wallet_name);
        }));
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(ScanJobStateOnly {
            state: "cancelling",
        }),
    ))
}

fn phase_state_name(phase: ScanPhase) -> &'static str {
    match phase {
        ScanPhase::Pending => "pending",
        ScanPhase::Rescanning => "rescanning",
        ScanPhase::LoadingHistory => "loading_history",
        ScanPhase::Analyzing => "analyzing",
    }
}

impl ScanRequestBody {
    fn into_scan_request(self) -> Result<(ScanTarget, Vec<String>), ApiError> {
        match (self.descriptor, self.descriptors, self.utxos) {
            (Some(d), None, None) => Ok((ScanTarget::Descriptor(d), Vec::new())),
            (None, Some(ds), None) if !ds.is_empty() => {
                Ok((ScanTarget::Descriptors(ds), Vec::new()))
            }
            (None, Some(_), None) => Err(ApiError::bad_request("`descriptors` must not be empty")),
            (None, None, Some(utxos)) if !utxos.is_empty() => {
                Ok((ScanTarget::Utxos(utxos), Vec::new()))
            }
            (None, None, Some(_)) => Err(ApiError::bad_request("`utxos` must not be empty")),
            // utxos + descriptors: the descriptors are ownership context,
            // letting is_ours() recognise the user's own inputs.
            (None, Some(ds), Some(utxos)) if !utxos.is_empty() && !ds.is_empty() => {
                Ok((ScanTarget::Utxos(utxos), ds))
            }
            (None, Some(_), Some(_)) => Err(ApiError::bad_request(
                "`utxos` and `descriptors` must not be empty when combined",
            )),
            (None, None, None) => Err(ApiError::bad_request(
                "one input source is required: descriptor, descriptors, or utxos",
            )),
            _ => Err(ApiError::bad_request("provide exactly one input source")),
        }
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
    async fn post_scan_rejects_empty_descriptors_list() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "descriptors": [] }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn post_scan_rejects_empty_utxos_list() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "utxos": [] }).to_string()))
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

    async fn read_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}
