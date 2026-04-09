use std::net::SocketAddr;

use reqwest::StatusCode;
use serde_json::json;
use tokio::sync::oneshot;

#[tokio::test]
async fn root_path_with_descriptor_is_not_found() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    let response = client
        .get(server.url("/?descriptor=123"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    server.stop().await;
}

#[tokio::test]
async fn scan_get_is_not_allowed() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    let response = client
        .get(server.url("/api/wallet/scan?descriptor=wpkh(xpub.../0/*)"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    server.stop().await;
}

#[tokio::test]
async fn scan_post_with_valid_descriptor_returns_503_without_rpc() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    let response = client
        .post(server.url("/api/wallet/scan"))
        .json(&json!({
            "descriptor": "wpkh(xpub.../0/*)"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "scanner_not_configured");
    server.stop().await;
}

#[tokio::test]
async fn scan_post_with_invalid_descriptor_returns_bad_request() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    let response = client
        .post(server.url("/api/wallet/scan"))
        .json(&json!({
            "descriptor": "123"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_scan_input");
    server.stop().await;
}

#[tokio::test]
async fn scan_post_with_descriptors_returns_503_without_rpc() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    let response = client
        .post(server.url("/api/wallet/scan"))
        .json(&json!({
            "descriptors": ["wpkh(xpub.../0/*)", "wpkh(xpub.../1/*)"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "scanner_not_configured");
    server.stop().await;
}

#[tokio::test]
async fn scan_post_rejects_multiple_input_sources() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    let response = client
        .post(server.url("/api/wallet/scan"))
        .json(&json!({
            "descriptor": "abc",
            "utxos": [{
                "txid": "0000000000000000000000000000000000000000000000000000000000000001",
                "vout": 0
            }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "bad_request");
    server.stop().await;
}

struct TestServer {
    address: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn spawn() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server = axum::serve(listener, stealth_api::app()).with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });

        let handle = tokio::spawn(async move {
            let _ = server.await;
        });

        Self {
            address,
            shutdown_tx: Some(shutdown_tx),
            handle,
        }
    }

    fn url(&self, path_and_query: &str) -> String {
        format!("http://{}{}", self.address, path_and_query)
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.handle.await;
    }
}
