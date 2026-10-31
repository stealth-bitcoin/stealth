use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use stealth_engine::engine::{
    AnalysisEngine, EngineSettings, HistoryLimit, ScanTarget, UtxoInput, DEFAULT_MAX_WALLET_TXS,
};
use stealth_engine::error::AnalysisError;
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
    /// Reuse a persistent watch-only wallet across scans of the same
    /// descriptors so repeat scans skip the full rescan. Default: false.
    /// Trade-off: this persists the viewing key (xpub) in Core's wallet DB
    /// in plaintext and leaves a durable `_stealth_cache_<hash>` wallet on
    /// the node that reveals the descriptors were scanned. Enable only
    /// against a trusted node.
    #[serde(default)]
    cache_wallet: bool,
    /// The most transactions of the user's own history the scan loads
    /// (default 5,000); above it the scan stops before loading any.
    #[serde(default)]
    max_txs: Option<u64>,
    /// Lifts the limit.
    #[serde(default)]
    no_limits: bool,
}

async fn scan_post(
    State(state): State<AppState>,
    Json(body): Json<ScanRequestBody>,
) -> Result<Json<Report>, ApiError> {
    let persist_scan_wallet = body.cache_wallet;
    let history_limit = body.history_limit()?;
    let (target, ownership_descriptors) = body.into_scan_request()?;

    let gw = state.gateway.ok_or(ApiError::ScannerNotConfigured)?;
    let report = tokio::task::spawn_blocking(move || {
        let settings = EngineSettings {
            ownership_descriptors,
            persist_scan_wallet,
            history_limit,
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
    /// Set when the scan stopped at the history limit.
    limit_exceeded: Option<LimitExceeded>,
}

#[derive(Debug, Serialize)]
struct LimitExceeded {
    tx_count: u64,
    limit: u64,
}

#[derive(Debug, Serialize)]
struct ScanJobStateOnly {
    state: &'static str,
}

async fn scans_create(
    State(state): State<AppState>,
    Json(body): Json<ScanRequestBody>,
) -> Result<(StatusCode, Json<ScanJobCreated>), ApiError> {
    let persist_scan_wallet = body.cache_wallet;
    let history_limit = body.history_limit()?;
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
                    ownership_descriptors,
                    persist_scan_wallet,
                    history_limit,
                    progress: Some(sink.clone()),
                    ..EngineSettings::default()
                };
                let result = AnalysisEngine::new(gw.as_ref(), settings).analyze(target);
                let outcome = if sink.cancel_requested() {
                    JobOutcome::Cancelled
                } else {
                    match result {
                        Ok(report) => JobOutcome::Done(report),
                        Err(
                            error @ AnalysisError::HistoryTooLarge {
                                tx_count, limit, ..
                            },
                        ) => JobOutcome::HistoryTooLarge {
                            message: ApiError::Analysis(error).to_string(),
                            tx_count,
                            limit,
                        },
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
            limit_exceeded: None,
        },
        Some(JobOutcome::Failed(message)) => ScanJobStatus {
            state: "failed",
            progress: None,
            report: None,
            error: Some(message),
            limit_exceeded: None,
        },
        Some(JobOutcome::HistoryTooLarge {
            message,
            tx_count,
            limit,
        }) => ScanJobStatus {
            state: "failed",
            progress: None,
            report: None,
            error: Some(message),
            limit_exceeded: Some(LimitExceeded { tx_count, limit }),
        },
        Some(JobOutcome::Cancelled) => ScanJobStatus {
            state: "cancelled",
            progress: None,
            report: None,
            error: None,
            limit_exceeded: None,
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
                limit_exceeded: None,
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
            JobOutcome::Failed(_) | JobOutcome::HistoryTooLarge { .. } => "failed",
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
    fn history_limit(&self) -> Result<HistoryLimit, ApiError> {
        match (self.max_txs, self.no_limits) {
            (Some(_), true) => Err(ApiError::bad_request(
                "`max_txs` and `no_limits` cannot be combined",
            )),
            (_, true) => Ok(HistoryLimit::unlimited()),
            (max_txs, false) => Ok(HistoryLimit::at_most(
                max_txs.unwrap_or(DEFAULT_MAX_WALLET_TXS),
            )),
        }
    }

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

    mod history_limit {
        use std::collections::{HashMap, HashSet};
        use std::sync::{Arc, Mutex};

        use axum::{
            body::Body,
            http::{Request, StatusCode},
            Router,
        };
        use bitcoin::address::NetworkUnchecked;
        use bitcoin::{Address, OutPoint, Txid};
        use serde_json::{json, Value};
        use stealth_engine::engine::HistoryLimit;
        use stealth_engine::error::AnalysisError;
        use stealth_engine::gateway::{
            BlockchainGateway, DecodedTransaction, LeftOut, ResolvedDescriptor, UtxoSetResults,
            WalletHistory,
        };
        use tower::ServiceExt;

        use super::read_json;
        use crate::app_with_gateway;

        const TX_COUNT: u64 = 6_000;

        /// A node whose scan wallet holds [`TX_COUNT`] transactions.
        #[derive(Default)]
        struct LargeHistory {
            limits: Mutex<Vec<Option<u64>>>,
        }

        impl BlockchainGateway for LargeHistory {
            fn normalize_descriptor(&self, descriptor: &str) -> Result<String, AnalysisError> {
                Ok(descriptor.to_owned())
            }

            fn derive_addresses(
                &self,
                _: &ResolvedDescriptor,
            ) -> Result<Vec<Address<NetworkUnchecked>>, AnalysisError> {
                Ok(Vec::new())
            }

            fn scan_descriptors(
                &self,
                _: &[ResolvedDescriptor],
                _: bool,
                limit: &HistoryLimit,
            ) -> Result<WalletHistory, AnalysisError> {
                self.limits.lock().unwrap().push(limit.max_txs);
                limit.check(TX_COUNT)?;
                Ok(WalletHistory {
                    wallet_txs: Vec::new(),
                    utxos: Vec::new(),
                    transactions: HashMap::new(),
                    internal_addresses: HashSet::new(),
                    derived_addresses: HashSet::new(),
                    ranged_addresses: HashSet::new(),
                    left_out: LeftOut::default(),
                })
            }

            fn list_wallet_descriptors(
                &self,
                _: &str,
            ) -> Result<Vec<ResolvedDescriptor>, AnalysisError> {
                Ok(Vec::new())
            }

            fn scan_wallet(&self, _: &str) -> Result<WalletHistory, AnalysisError> {
                Err(AnalysisError::EnvironmentUnavailable("not used".into()))
            }

            fn known_wallet_txids(&self, _: &[String]) -> Result<HashSet<Txid>, AnalysisError> {
                Ok(HashSet::new())
            }

            fn get_transaction(&self, txid: Txid) -> Result<DecodedTransaction, AnalysisError> {
                Err(AnalysisError::TransactionNotFound(txid.to_string()))
            }

            fn outputs_in_utxo_set(&self, _: &[OutPoint]) -> Result<UtxoSetResults, AnalysisError> {
                Ok(Vec::new())
            }
        }

        fn app() -> (Router, Arc<LargeHistory>) {
            let gateway = Arc::new(LargeHistory::default());
            (app_with_gateway(Some(gateway.clone())), gateway)
        }

        async fn post(app: &Router, path: &str, body: Value) -> axum::response::Response {
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .method("POST")
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap()
        }

        /// Starts a scan job and polls it until it ends.
        async fn finished_job(app: &Router, body: Value) -> Value {
            let created = post(app, "/api/wallet/scans", body).await;
            assert_eq!(created.status(), StatusCode::ACCEPTED);
            let id = read_json(created).await["scan_id"]
                .as_str()
                .unwrap()
                .to_owned();
            for _ in 0..200 {
                let polled = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(format!("/api/wallet/scans/{id}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let job = read_json(polled).await;
                if ["done", "failed", "cancelled"].contains(&job["state"].as_str().unwrap()) {
                    return job;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            panic!("the scan job never finished");
        }

        fn scan(extra: Value) -> Value {
            let mut body =
                json!({ "descriptor": "addr(bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080)" });
            body.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            body
        }

        #[tokio::test]
        async fn a_job_above_the_limit_fails_with_the_count_and_the_limit() {
            let (app, _) = app();
            let job = finished_job(&app, scan(json!({}))).await;
            assert_eq!(job["state"], "failed");
            assert_eq!(
                job["limit_exceeded"],
                json!({ "tx_count": TX_COUNT, "limit": 5_000 })
            );
            let error = job["error"].as_str().unwrap();
            assert!(error.contains("6000 transactions"), "{error}");
        }

        #[tokio::test]
        async fn a_job_sent_again_with_max_txs_or_no_limits_goes_on() {
            let (app, gateway) = app();
            for extra in [json!({ "max_txs": TX_COUNT }), json!({ "no_limits": true })] {
                let job = finished_job(&app, scan(extra.clone())).await;
                assert_eq!(job["state"], "done", "{extra}: {job}");
                assert_eq!(job["limit_exceeded"], Value::Null);
            }
            assert_eq!(*gateway.limits.lock().unwrap(), vec![Some(TX_COUNT), None]);
        }

        #[tokio::test]
        async fn a_lower_max_txs_is_the_limit_the_job_names() {
            let (app, _) = app();
            let job = finished_job(&app, scan(json!({ "max_txs": 10 }))).await;
            assert_eq!(job["limit_exceeded"]["limit"], 10);
        }

        #[tokio::test]
        async fn any_other_failure_carries_no_limit() {
            let (app, _) = app();
            let job = finished_job(&app, json!({ "descriptor": "" })).await;
            assert_eq!(job["state"], "failed", "{job}");
            let status = job.as_object().unwrap();
            assert_eq!(status.get("limit_exceeded"), Some(&Value::Null), "{job}");
        }

        #[tokio::test]
        async fn max_txs_and_no_limits_do_not_go_together() {
            let (app, _) = app();
            for path in ["/api/wallet/scan", "/api/wallet/scans"] {
                let body = scan(json!({ "max_txs": 10, "no_limits": true }));
                let response = post(&app, path, body).await;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
            }
        }

        #[tokio::test]
        async fn a_direct_scan_above_the_limit_answers_422_with_the_count_and_the_limit() {
            let (app, _) = app();
            let response = post(&app, "/api/wallet/scan", scan(json!({}))).await;
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            let body = read_json(response).await;
            assert_eq!(body["error"]["code"], "history_too_large");
            assert_eq!(body["error"]["tx_count"], TX_COUNT);
            assert_eq!(body["error"]["limit"], 5_000);

            let response = post(&app, "/api/wallet/scan", scan(json!({ "no_limits": true }))).await;
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}
