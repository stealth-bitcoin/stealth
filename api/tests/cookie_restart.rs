use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use corepc_node::client::client_sync::Auth;
use corepc_node::{Client, Conf, Node};
use stealth_api::rpc::{build_gateway, RpcSettings};
use stealth_engine::gateway::BlockchainGateway;

// Kills the restarted bitcoind even when an assertion fails.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn api_gateway_on_a_cookie_survives_node_restart() {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let datadir = std::env::temp_dir().join(format!("stealth-api-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);
    let mut conf = Conf::default();
    conf.staticdir = Some(datadir.clone());
    let mut first = Node::with_conf(&exe, &conf).expect("start bitcoind");
    let port = first.params.rpc_socket.port();
    let cookie_file: PathBuf = first.params.cookie_file.clone();
    let old_cookie = std::fs::read_to_string(&cookie_file).expect("read cookie");

    let settings = RpcSettings {
        url: first.rpc_url(),
        cookie: Some(cookie_file.clone()),
        ..RpcSettings::default()
    };
    let gateway = build_gateway(&settings, || None, || None).expect("build gateway");
    gateway
        .normalize_descriptor("raw(51)")
        .expect("call before restart");

    // Restart on the same port (corepc_node would pick a new one); Core writes a new cookie.
    first.stop().expect("stop bitcoind");
    drop(first);
    let second = KillOnDrop(
        Command::new(&exe)
            .arg(format!("-datadir={}", datadir.display()))
            .args(["-regtest", "-listen=0"])
            .arg(format!("-rpcport={port}"))
            .stdout(Stdio::null())
            .spawn()
            .expect("restart bitcoind"),
    );

    // Wait for warmup with an independent client, so the gateway gets a single shot.
    let url = format!("http://127.0.0.1:{port}");
    let ready = (0..150).any(|_| {
        let probe = Client::new_with_auth(&url, Auth::CookieFile(cookie_file.clone()));
        let up = probe.is_ok_and(|client| client.get_blockchain_info().is_ok());
        if !up {
            std::thread::sleep(Duration::from_millis(200));
        }
        up
    });
    let after = gateway.normalize_descriptor("raw(51)");
    let new_cookie = std::fs::read_to_string(&cookie_file).unwrap_or_default();
    drop(second);
    let _ = std::fs::remove_dir_all(&datadir);
    assert!(ready, "restarted bitcoind never answered");
    assert_ne!(old_cookie, new_cookie, "restart must regenerate the cookie");
    after.expect("the API's gateway must re-read the regenerated cookie");
}
