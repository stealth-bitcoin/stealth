//! The CLI against a regtest node, at the history limit.

use std::process::{Command, Output, Stdio};

use corepc_node::client::bitcoin::{Address, Amount};
use corepc_node::Node;

fn node_with_an_address_paid_five_times() -> (Node, Address) {
    node_with_an_address_paid_five_times_and(&[])
}

fn node_with_an_address_paid_five_times_and(args: &[&'static str]) -> (Node, Address) {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    conf.args.extend_from_slice(args);
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
    assert!(stderr.contains("--max-txs with at least 5,"), "{stderr}");
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
fn interrupt_at_the_prompt(node: &Node, input: &[String], flags: &[&str]) -> (String, Option<i32>) {
    let (printed, _, code) = answer_at_the_prompt(node, input, flags, None);
    (printed, code)
}

/// Runs a scan on a pseudo-terminal and, once it asks whether to go on,
/// types `typed` after `delay`, or sends SIGINT when `typed` is `None`.
/// Returns what it printed on the terminal, its stdout and how it exited.
#[cfg(unix)]
fn answer_at_the_prompt(
    node: &Node,
    input: &[String],
    flags: &[&str],
    typed: Option<(std::time::Duration, &str)>,
) -> (String, String, Option<i32>) {
    answer_at_the_prompt_typed_ahead(node, input, flags, "", typed)
}

/// Like [`answer_at_the_prompt`], typing `ahead` as soon as the scan starts.
#[cfg(unix)]
fn answer_at_the_prompt_typed_ahead(
    node: &Node,
    input: &[String],
    flags: &[&str],
    ahead: &str,
    typed: Option<(std::time::Duration, &str)>,
) -> (String, String, Option<i32>) {
    use std::fs::File;
    use std::io::{Read, Write};
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_stealth-cli"));
    child
        .arg("scan")
        .args(input)
        .args(["--rpc-url", &node.rpc_url()])
        .arg("--rpc-cookie")
        .arg(&node.params.cookie_file)
        .args(flags)
        .env_remove("STEALTH_RPC_USER")
        .env_remove("STEALTH_RPC_PASS")
        .stdin(Stdio::from(slave.try_clone().expect("dup slave")))
        .stderr(Stdio::from(slave))
        .stdout(Stdio::piped());
    controlled_by_the_terminal(&mut child);
    let mut child = child.spawn().expect("run stealth-cli");
    let mut stdout = child.stdout.take().expect("stdout");
    let mut keyboard = File::from(master.try_clone().expect("dup master"));
    keyboard.write_all(ahead.as_bytes()).expect("type ahead");

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
    match typed {
        Some((delay, answer)) => {
            std::thread::sleep(delay);
            keyboard
                .write_all(answer.as_bytes())
                .expect("type the answer");
        }
        // SAFETY: kill only sends a signal to the child started above.
        None => assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0),
    }
    let mut report = String::new();
    stdout.read_to_string(&mut report).expect("read stdout");
    let status = child.wait().expect("wait for stealth-cli");
    while let Ok(chunk) = shown.recv_timeout(Duration::from_millis(200)) {
        printed.extend(chunk);
    }
    assert_eq!(status.signal(), None, "killed by a signal: {status:?}");
    (
        String::from_utf8_lossy(&printed).into_owned(),
        report,
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
        let (printed, code) = interrupt_at_the_prompt(&node, &descriptor_input(&aa), flags);
        assert_eq!(code, Some(2), "{flags:?}: {printed}");
        assert!(printed.contains("5 transactions"), "{flags:?}: {printed}");
        let error = printed.find("error:").expect("the error");
        assert!(
            printed[..error].ends_with('\n'),
            "the error starts on its own line: {printed:?}"
        );
        assert_eq!(
            stealth_wallets_loaded(&node),
            Vec::<String>::new(),
            "{flags:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn ctrl_c_outside_the_question_dies_by_sigint_at_once() {
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
    // Shells stop a loop only for a child killed by the signal, as it was before.
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGINT), "{status:?}");
}

#[cfg(unix)]
fn descriptor_input(address: &Address) -> Vec<String> {
    vec!["--descriptor".into(), format!("addr({address})")]
}

#[cfg(unix)]
#[test]
fn a_utxo_scan_asks_about_the_utxo_files_addresses_and_ctrl_c_is_a_no() {
    let (node, aa) = node_with_an_address_paid_five_times();
    let alice = corepc_node::Client::new_with_auth(
        &format!("{}/wallet/alice", node.rpc_url()),
        corepc_node::client::client_sync::Auth::CookieFile(node.params.cookie_file.clone()),
    )
    .expect("alice client");
    let coins: Vec<serde_json::Value> = alice.call("listunspent", &[]).expect("listunspent");
    let utxos = std::env::temp_dir().join(format!("stealth-cli-utxos-{}.json", std::process::id()));
    let pasted = serde_json::json!([{
        "txid": coins[0]["txid"],
        "vout": coins[0]["vout"],
        "address": aa.to_string(),
    }]);
    std::fs::write(&utxos, pasted.to_string()).expect("write utxos");

    let input = vec!["--utxos".to_owned(), utxos.display().to_string()];
    let (printed, code) = interrupt_at_the_prompt(&node, &input, &["--max-txs", "3"]);
    let _ = std::fs::remove_file(&utxos);
    assert_eq!(code, Some(2), "{printed}");
    assert!(
        printed.contains(
            "The history of the addresses of the outputs in the UTXO file holds 5 transactions"
        ),
        "{printed}"
    );
    assert_eq!(stealth_wallets_loaded(&node), Vec::<String>::new());
}

#[cfg(unix)]
#[test]
fn a_yes_typed_after_the_node_closed_the_idle_connection_still_finishes_the_scan() {
    let (node, aa) = node_with_an_address_paid_five_times_and(&["-rpcservertimeout=1"]);
    let (printed, report, code) = answer_at_the_prompt(
        &node,
        &descriptor_input(&aa),
        &["--max-txs", "3"],
        Some((std::time::Duration::from_secs(3), "y\n")),
    );
    assert!(
        report.contains("Scanned 5 transactions"),
        "{printed}{report}"
    );
    assert!(matches!(code, Some(0 | 1)), "{code:?}: {printed}");
    assert_eq!(stealth_wallets_loaded(&node), Vec::<String>::new());
}

/// Makes the pseudo-terminal on stdin the child's controlling terminal, in a
/// session of its own, as a shell would.
#[cfg(unix)]
fn controlled_by_the_terminal(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: setsid and ioctl are async-signal-safe and touch only the child.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(unix)]
#[test]
fn a_scan_started_in_the_background_stops_with_the_hint_instead_of_asking() {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    let (node, aa) = node_with_an_address_paid_five_times();
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

    // A job-control shell on the terminal starts the scan as a background job.
    let mut shell = Command::new("bash");
    shell
        .args([
            "-c",
            "set -m; \"$0\" \"$@\" & echo $!; wait $!; echo \"exit $?\"",
        ])
        .arg(env!("CARGO_BIN_EXE_stealth-cli"))
        .args([
            "scan",
            "--descriptor",
            &format!("addr({aa})"),
            "--max-txs",
            "3",
        ])
        .args(["--rpc-url", &node.rpc_url()])
        .arg("--rpc-cookie")
        .arg(&node.params.cookie_file)
        .env_remove("STEALTH_RPC_USER")
        .env_remove("STEALTH_RPC_PASS")
        .stdin(Stdio::from(slave.try_clone().expect("dup slave")))
        .stderr(Stdio::from(slave))
        .stdout(Stdio::piped());
    controlled_by_the_terminal(&mut shell);
    let spawned = shell.spawn().expect("run bash");
    // The command holds the terminal's other end; the output ends only once it is gone.
    drop(shell);
    let mut shell = spawned;
    let mut lines = BufReader::new(shell.stdout.take().expect("stdout")).lines();
    let job: i32 = lines
        .next()
        .expect("job pid")
        .expect("read")
        .parse()
        .expect("pid");
    let terminal = std::thread::spawn(move || {
        let mut master = File::from(master);
        let mut shown = Vec::new();
        let _ = master.read_to_end(&mut shown);
        String::from_utf8_lossy(&shown).into_owned()
    });

    let deadline = Instant::now() + Duration::from_secs(60);
    while shell.try_wait().expect("poll bash").is_none() {
        if Instant::now() > deadline {
            // SAFETY: only the job and the shell started above are signalled.
            unsafe {
                libc::kill(job, libc::SIGKILL);
                libc::kill(shell.id() as i32, libc::SIGKILL);
            }
            panic!("the background scan never ended (stopped by SIGTTIN?)");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // A job stopped by SIGTTIN outlives the shell; it must not outlive the test.
    // SAFETY: only the job started above is signalled.
    let _ = unsafe { libc::kill(job, libc::SIGKILL) };
    let ended: Vec<String> = lines.map_while(Result::ok).collect();
    assert!(ended.iter().any(|line| line == "exit 2"), "{ended:?}");
    let shown = terminal.join().expect("terminal output");
    assert!(!shown.contains("[y/N]"), "{shown}");
    assert!(shown.contains("holds 5 transactions"), "{shown}");
    assert!(shown.contains("--no-limits"), "{shown}");
    assert_eq!(stealth_wallets_loaded(&node), Vec::<String>::new());
}

#[cfg(unix)]
#[test]
fn a_scan_started_with_sigint_ignored_keeps_ignoring_it() {
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    // A node that takes the connection and never answers keeps the scan waiting.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("port").port();
    let mut child = Command::new("bash")
        .args(["-c", "trap '' INT; exec \"$0\" \"$@\""])
        .arg(env!("CARGO_BIN_EXE_stealth-cli"))
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
    let deadline = Instant::now() + Duration::from_secs(30);
    let _held = loop {
        match listener.accept() {
            Ok((held, _)) => break held,
            Err(_) if Instant::now() < deadline => {
                assert!(child.try_wait().expect("poll").is_none(), "exited first");
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("the scan never connected: {error}"),
        }
    };
    // SAFETY: kill only sends signals to the child started above.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    std::thread::sleep(Duration::from_secs(1));
    let still_running = child.try_wait().expect("poll").is_none();
    // SAFETY: as above.
    let _ = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let _ = child.wait();
    assert!(still_running, "an inherited SIG_IGN must stay in force");
}

#[cfg(unix)]
#[test]
fn an_enter_typed_during_the_rescan_does_not_answer_the_question() {
    let (node, aa) = node_with_an_address_paid_five_times();
    let (printed, report, code) = answer_at_the_prompt_typed_ahead(
        &node,
        &descriptor_input(&aa),
        &["--max-txs", "3"],
        "\n",
        Some((std::time::Duration::from_millis(500), "y\n")),
    );
    assert!(
        report.contains("Scanned 5 transactions"),
        "{printed}{report}"
    );
    assert!(matches!(code, Some(0 | 1)), "{code:?}: {printed}");
}
