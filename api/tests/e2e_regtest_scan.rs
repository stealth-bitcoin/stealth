use std::net::SocketAddr;
use std::sync::Arc;

use corepc_node::client::bitcoin::Amount;
use corepc_node::Node;
use reqwest::StatusCode;
use serde_json::{json, Value};
use stealth_bitcoincore::BitcoinCoreRpc;
use tokio::sync::oneshot;

#[tokio::test]
async fn scan_descriptor_clean_then_findings_after_regtest_activity() {
    let node = start_node();
    let mining_addr = node.client.new_address().unwrap();
    mine(&node, 110, &mining_addr);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Fund bob so it can create payments to alice.
    let bob_fund_addr = bob.new_address().unwrap();
    node.client
        .send_to_address(&bob_fund_addr, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &mining_addr);

    let reused_addr = alice.new_address().unwrap();
    let descriptor = alice
        .get_address_info(&reused_addr)
        .unwrap()
        .descriptor
        .expect("wallet address has no descriptor");

    let rpc_url = node.rpc_url();
    let cookie =
        std::fs::read_to_string(&node.params.cookie_file).expect("failed to read cookie file");
    let gateway = tokio::task::spawn_blocking(move || {
        let mut parts = cookie.trim().splitn(2, ':');
        let user = parts.next().unwrap().to_string();
        let pass = parts.next().unwrap().to_string();
        BitcoinCoreRpc::from_url(&rpc_url, Some(user), Some(pass)).expect("failed to build gateway")
    })
    .await
    .unwrap();
    let server = ApiServer::spawn(gateway).await;
    let client = reqwest::Client::new();

    let first = scan_descriptor(&client, &server, &descriptor).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["summary"]["clean"], Value::Bool(true));
    assert_eq!(first.body["stats"]["transactions_analyzed"], Value::from(0));

    // Reuse one receive address twice to trigger address-reuse finding.
    bob.send_to_address(&reused_addr, Amount::from_sat(1_000_000))
        .unwrap();
    bob.send_to_address(&reused_addr, Amount::from_sat(2_000_000))
        .unwrap();
    mine(&node, 1, &mining_addr);

    let second = scan_descriptor(&client, &server, &descriptor).await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(second.body["summary"]["clean"], Value::Bool(false));
    assert!(
        second.body["summary"]["findings"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(
        second.body["stats"]["transactions_analyzed"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );

    server.stop().await;
}

fn start_node() -> Node {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    Node::with_conf(exe, &conf).expect("failed to start regtest node")
}

fn mine(node: &Node, blocks: usize, addr: &corepc_node::client::bitcoin::Address) {
    node.client.generate_to_address(blocks, addr).unwrap();
}

async fn scan_descriptor(
    client: &reqwest::Client,
    server: &ApiServer,
    descriptor: &str,
) -> ScanResponse {
    let response = client
        .post(server.url("/api/wallet/scan"))
        .json(&json!({ "descriptor": descriptor }))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body: Value = response.json().await.unwrap();
    ScanResponse { status, body }
}

struct ScanResponse {
    status: StatusCode,
    body: Value,
}

struct ApiServer {
    address: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
    /// Held so the gateway outlives the server task; dropped explicitly
    /// on a blocking thread to avoid reqwest::blocking runtime panics.
    gateway: Option<Arc<dyn stealth_engine::gateway::BlockchainGateway + Send + Sync>>,
}

impl ApiServer {
    async fn spawn(gateway: BitcoinCoreRpc) -> Self {
        let gateway: Arc<dyn stealth_engine::gateway::BlockchainGateway + Send + Sync> =
            Arc::new(gateway);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server = axum::serve(
            listener,
            stealth_api::app_with_gateway(Some(gateway.clone())),
        )
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });

        let handle = tokio::spawn(async move {
            let _ = server.await;
        });

        Self {
            address,
            shutdown_tx: Some(shutdown_tx),
            handle,
            gateway: Some(gateway),
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
        // Drop the gateway (reqwest::blocking::Client) on a blocking
        // thread so its internal Tokio runtime can shut down safely.
        if let Some(gw) = self.gateway.take() {
            tokio::task::spawn_blocking(move || drop(gw)).await.ok();
        }
    }
}
