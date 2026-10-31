//! The CLI against a regtest node, at the history limit.

use std::process::{Command, Output, Stdio};

use corepc_node::client::bitcoin::{Address, Amount};
use corepc_node::Node;

fn node_with_an_address_paid_five_times() -> (Node, Address) {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    let node = Node::with_conf(exe, &conf).expect("failed to start bitcoind");
    let da = node.client.new_address().expect("default address");
    node.client.generate_to_address(110, &da).expect("mine");
    let alice = node.create_wallet("alice").expect("create alice");
    let aa = alice.new_address().expect("alice address");
    for _ in 0..5 {
        node.client
            .send_to_address(&aa, Amount::from_sat(100_000))
            .expect("pay alice");
        node.client.generate_to_address(1, &da).expect("mine");
    }
    (node, aa)
}

// stdin is not a terminal here, so nobody is asked.
fn scan(node: &Node, address: &Address, flags: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stealth-cli"))
        .args(["scan", "--descriptor", &format!("addr({address})")])
        .args(["--rpc-url", &node.rpc_url()])
        .arg("--rpc-cookie")
        .arg(&node.params.cookie_file)
        .args(flags)
        .env_remove("STEALTH_RPC_USER")
        .env_remove("STEALTH_RPC_PASS")
        .stdin(Stdio::null())
        .output()
        .expect("run stealth-cli")
}

fn stealth_wallets_loaded(node: &Node) -> Vec<String> {
    node.client
        .call::<Vec<String>>("listwallets", &[])
        .expect("listwallets")
        .into_iter()
        .filter(|name| name.starts_with("_stealth"))
        .collect()
}

#[test]
fn a_history_above_max_txs_stops_with_the_count_and_the_flags() {
    let (node, aa) = node_with_an_address_paid_five_times();

    let stopped = scan(&node, &aa, &["--max-txs", "3"]);
    let stderr = String::from_utf8_lossy(&stopped.stderr);
    assert_eq!(stopped.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("5 transactions"), "{stderr}");
    assert!(stderr.contains("limit of 3"), "{stderr}");
    assert!(stderr.contains("--max-txs 5"), "{stderr}");
    assert!(stderr.contains("--no-limits"), "{stderr}");
    assert!(stopped.stdout.is_empty());
    assert_eq!(stealth_wallets_loaded(&node), Vec::<String>::new());

    for flags in [&["--max-txs", "5"][..], &["--no-limits"]] {
        let scanned = scan(&node, &aa, flags);
        let stdout = String::from_utf8_lossy(&scanned.stdout);
        assert!(
            stdout.contains("Scanned 5 transactions"),
            "{flags:?}: {stdout}{}",
            String::from_utf8_lossy(&scanned.stderr)
        );
    }
}

#[test]
fn the_default_limit_lets_a_small_history_through() {
    let (node, aa) = node_with_an_address_paid_five_times();
    let scanned = scan(&node, &aa, &[]);
    assert!(String::from_utf8_lossy(&scanned.stdout).contains("Scanned 5 transactions"));
}

/// Runs a scan on a pseudo-terminal, sends SIGINT once it asks whether to go
/// on, and returns what it printed and how it exited.
#[cfg(unix)]
fn interrupt_at_the_prompt(
    node: &Node,
    address: &Address,
    flags: &[&str],
    signals: usize,
) -> (String, Option<i32>) {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::ExitStatusExt;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let (mut master, mut slave) = (0, 0);
    // SAFETY: openpty writes two fresh descriptors, owned below.
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(opened, 0, "openpty failed");
    // SAFETY: both descriptors were just opened and are owned by nobody else.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };

    let mut child = Command::new(env!("CARGO_BIN_EXE_stealth-cli"))
        .args(["scan", "--descriptor", &format!("addr({address})")])
        .args(["--rpc-url", &node.rpc_url()])
        .arg("--rpc-cookie")
        .arg(&node.params.cookie_file)
        .args(flags)
        .env_remove("STEALTH_RPC_USER")
        .env_remove("STEALTH_RPC_PASS")
        .stdin(Stdio::from(slave.try_clone().expect("dup slave")))
        .stderr(Stdio::from(slave))
        .stdout(Stdio::null())
        .spawn()
        .expect("run stealth-cli");

    let (sent, shown) = mpsc::channel();
    std::thread::spawn(move || {
        let mut master = File::from(master);
        let mut buffer = [0u8; 4096];
        while let Ok(read) = master.read(&mut buffer) {
            if read == 0 || sent.send(buffer[..read].to_vec()).is_err() {
                return;
            }
        }
    });

    let mut printed = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !String::from_utf8_lossy(&printed).contains("[y/N]") {
        let left = deadline.saturating_duration_since(Instant::now());
        let chunk = shown.recv_timeout(left).unwrap_or_else(|_| {
            let _ = child.kill();
            panic!("no prompt: {}", String::from_utf8_lossy(&printed))
        });
        printed.extend(chunk);
    }
    // SAFETY: kill only sends a signal to the child started above.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    for _ in 1..signals {
        // Apart, so the kernel does not merge them; the child may be gone already.
        std::thread::sleep(Duration::from_millis(5));
        // SAFETY: as above; a child that already exited is not signalled.
        let _ = unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    }
    let status = child.wait().expect("wait for stealth-cli");
    while let Ok(chunk) = shown.recv_timeout(Duration::from_millis(200)) {
        printed.extend(chunk);
    }
    assert_eq!(status.signal(), None, "killed by a signal: {status:?}");
    (
        String::from_utf8_lossy(&printed).into_owned(),
        status.code(),
    )
}

#[cfg(unix)]
#[test]
fn ctrl_c_at_the_prompt_is_a_no_and_leaves_no_wallet_loaded() {
    let (node, aa) = node_with_an_address_paid_five_times();
    for flags in [
        &["--max-txs", "3"][..],
        &["--max-txs", "3", "--cache-wallet"],
    ] {
        let (printed, code) = interrupt_at_the_prompt(&node, &aa, flags, 1);
        assert_eq!(code, Some(2), "{flags:?}: {printed}");
        assert!(printed.contains("5 transactions"), "{flags:?}: {printed}");
        assert_eq!(
            stealth_wallets_loaded(&node),
            Vec::<String>::new(),
            "{flags:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_second_ctrl_c_right_after_the_no_still_shows_the_count_and_the_hint() {
    let (node, aa) = node_with_an_address_paid_five_times();
    let (printed, code) = interrupt_at_the_prompt(&node, &aa, &["--max-txs", "3"], 2);
    assert_eq!(code, Some(2), "{printed}");
    assert!(printed.contains("holds 5 transactions"), "{printed}");
    assert!(printed.contains("--no-limits"), "{printed}");
    assert_eq!(stealth_wallets_loaded(&node), Vec::<String>::new());
}

#[cfg(unix)]
#[test]
fn ctrl_c_outside_the_question_exits_at_once_with_130() {
    use std::net::TcpListener;
    use std::time::Duration;

    // A node that takes the connection and never answers keeps the scan waiting.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("port").port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_stealth-cli"))
        .args([
            "scan",
            "--descriptor",
            "addr(bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080)",
        ])
        .args(["--rpc-url", &format!("http://127.0.0.1:{port}")])
        .args(["--rpc-user", "user"])
        .env("STEALTH_RPC_PASS", "pass")
        .env_remove("STEALTH_RPC_COOKIE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("run stealth-cli");
    listener.set_nonblocking(true).expect("nonblocking");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let _held = loop {
        match listener.accept() {
            Ok((held, _)) => break held,
            Err(_) if std::time::Instant::now() < deadline => {
                assert!(child.try_wait().expect("poll").is_none(), "exited first");
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("the scan never connected: {error}"),
        }
    };
    // SAFETY: kill only sends a signal to the child started above.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for stealth-cli") {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("one Ctrl-C did not end the scan");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(130), "{status:?}");
}
