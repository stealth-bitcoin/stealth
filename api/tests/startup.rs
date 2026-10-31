use std::process::Command;

// The bind address is invalid, so a run that gets past origin parsing still exits.
fn api_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stealth-api"));
    command
        .env_remove("STEALTH_API_ALLOW_ORIGINS")
        .env("STEALTH_API_BIND", "not-an-address")
        .env("STEALTH_RPC_URL", "http://127.0.0.1:1")
        .env("STEALTH_RPC_USER", "u")
        .env("STEALTH_RPC_PASS", "p");
    command
}

fn run_api(args: &[&str], env_origins: Option<&str>) -> std::process::Output {
    let mut command = api_command();
    command.args(args);
    if let Some(value) = env_origins {
        command.env("STEALTH_API_ALLOW_ORIGINS", value);
    }
    command.output().unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn malformed_allow_origin_flag_stops_startup_with_a_clear_error() {
    let output = run_api(&["--allow-origin", "https://wallet.example.org/app"], None);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("--allow-origin"), "stderr: {stderr}");
    assert!(
        stderr.contains("https://wallet.example.org/app"),
        "stderr: {stderr}"
    );
}

#[test]
fn malformed_allow_origins_env_stops_startup_with_a_clear_error() {
    let output = run_api(&[], Some("https://ok.example,not a url"));
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(
        stderr.contains("STEALTH_API_ALLOW_ORIGINS"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("not a url"), "stderr: {stderr}");
}

#[test]
fn allow_origin_flag_without_a_value_stops_startup() {
    let output = run_api(&["--allow-origin"], None);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(
        stderr.contains("--allow-origin needs a value"),
        "stderr: {stderr}"
    );
}

#[test]
fn valid_allow_origin_flags_get_past_origin_parsing() {
    // The bind address is invalid on purpose, so startup fails right after the origins are accepted.
    let output = run_api(
        &[
            "--allow-origin",
            "https://wallet.example.org",
            "--allow-origin=http://10.0.0.5:5173",
        ],
        Some("https://other.example"),
    );
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("STEALTH_API_BIND"), "stderr: {stderr}");
}

struct RunningApi(std::process::Child);

impl Drop for RunningApi {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn preflight_allow_origin(port: u16, origin: &str) -> Option<String> {
    let response = reqwest::Client::new()
        .request(
            reqwest::Method::OPTIONS,
            format!("http://127.0.0.1:{port}/api/wallet/scan"),
        )
        .header("origin", origin)
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();
    response
        .headers()
        .get("access-control-allow-origin")
        .map(|value| value.to_str().unwrap().to_owned())
}

#[tokio::test]
async fn configured_origins_reach_the_running_server() {
    let (_api, port, _) = spawn_api_on_any_port(
        &[
            "--allow-origin",
            "https://flag.example",
            "--allow-origin=https://equals.example",
        ],
        &[("STEALTH_API_ALLOW_ORIGINS", "https://env.example")],
    );

    for origin in [
        "https://flag.example",
        "https://equals.example",
        "https://env.example",
        "http://localhost:5173",
    ] {
        let allowed = preflight_allow_origin(port, origin).await;
        assert_eq!(allowed.as_deref(), Some(origin), "origin {origin}");
    }
    assert_eq!(
        preflight_allow_origin(port, "https://evil.example").await,
        None
    );
}

#[test]
fn unknown_argument_stops_startup_naming_it() {
    let output = run_api(&["--allow-orgin", "https://wallet.example.org"], None);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(
        stderr.contains("unknown argument: --allow-orgin"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_argument_is_reported_not_panicked_on() {
    use std::os::unix::ffi::OsStrExt;

    let output = api_command()
        .arg("--allow-origin")
        .arg(std::ffi::OsStr::from_bytes(b"https://wallet\xff.example"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(!stderr.contains("panicked"), "stderr: {stderr}");
    assert!(stderr.contains("not valid UTF-8"), "stderr: {stderr}");
}

#[cfg(unix)]
#[test]
fn non_utf8_allow_origins_env_stops_startup() {
    use std::os::unix::ffi::OsStrExt;

    let output = api_command()
        .env(
            "STEALTH_API_ALLOW_ORIGINS",
            std::ffi::OsStr::from_bytes(b"https://wallet\xff.example"),
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(
        stderr.contains("STEALTH_API_ALLOW_ORIGINS"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("not valid UTF-8"), "stderr: {stderr}");
}

#[test]
fn help_prints_usage_and_exits_successfully() {
    for flag in ["--help", "-h"] {
        let output = run_api(&[flag], None);
        assert!(output.status.success(), "{flag}: {}", stderr(&output));
        let stdout = String::from_utf8_lossy(&output.stdout);
        for expected in [
            "--allow-origin",
            "STEALTH_API_ALLOW_ORIGINS",
            "STEALTH_API_BIND",
            "STEALTH_RPC_URL",
            "STEALTH_RPC_USER",
            "STEALTH_RPC_PASS",
            "STEALTH_RPC_COOKIE",
            "RUST_LOG",
            "used only when both are set",
            "HOME",
        ] {
            assert!(
                stdout.contains(expected),
                "{flag} output lacks {expected}: {stdout}"
            );
        }
    }
}

#[test]
fn help_does_not_hide_other_unknown_arguments() {
    let output = run_api(&["--hepl"], None);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown argument: --hepl"));
}

#[test]
fn startup_errors_print_the_plain_message() {
    let output = run_api(&["--allow-origin", "https://wallet.example.org/app"], None);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(!stderr.contains("Custom {"), "stderr: {stderr}");
    assert!(
        stderr.starts_with("Error: invalid --allow-origin value: invalid origin \"https://wallet.example.org/app\""),
        "stderr: {stderr}"
    );
}

#[test]
fn help_in_the_value_position_is_a_missing_value() {
    for flag in ["--help", "-h"] {
        let output = run_api(&["--allow-origin", flag], None);
        assert!(!output.status.success(), "{flag} printed usage instead");
        let stderr = stderr(&output);
        assert!(
            stderr.contains("--allow-origin needs a value"),
            "stderr: {stderr}"
        );
    }
}

#[test]
fn malformed_allow_host_flag_stops_startup_with_a_clear_error() {
    let output = run_api(&["--allow-host", "http://stealth.lan"], None);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(
        stderr.contains("invalid --allow-host value"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("http://stealth.lan"), "stderr: {stderr}");
}

#[test]
fn malformed_allow_hosts_env_stops_startup_with_a_clear_error() {
    let output = api_command()
        .env("STEALTH_API_ALLOW_HOSTS", "stealth.lan,*")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(
        stderr.contains("invalid STEALTH_API_ALLOW_HOSTS value"),
        "stderr: {stderr}"
    );
}

#[test]
fn allow_host_flag_without_a_value_stops_startup() {
    for args in [&["--allow-host"][..], &["--allow-host", "--help"][..]] {
        let output = run_api(args, None);
        assert!(!output.status.success(), "{args:?} succeeded");
        let stderr = stderr(&output);
        assert!(
            stderr.contains("--allow-host needs a value"),
            "stderr: {stderr}"
        );
    }
}

#[test]
fn help_lists_the_host_options() {
    let output = run_api(&["--help"], None);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in ["--allow-host", "STEALTH_API_ALLOW_HOSTS"] {
        assert!(stdout.contains(expected), "help lacks {expected}: {stdout}");
    }
}

// Binds to port 0 and reads the port the server reports, so no other process can take it first.
// Also returns the log lines printed up to that point.
fn spawn_api_on_any_port(args: &[&str], env: &[(&str, &str)]) -> (RunningApi, u16, Vec<String>) {
    use std::io::BufRead;

    let mut command = Command::new(env!("CARGO_BIN_EXE_stealth-api"));
    command
        .args(args)
        .env_remove("STEALTH_API_ALLOW_ORIGINS")
        .env_remove("STEALTH_API_ALLOW_HOSTS")
        .env("STEALTH_API_BIND", "127.0.0.1:0")
        .env("STEALTH_RPC_URL", "http://127.0.0.1:1")
        .env("STEALTH_RPC_USER", "u")
        .env("STEALTH_RPC_PASS", "p")
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    command.envs(env.iter().copied());
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let api = RunningApi(child);
    let mut lines = std::io::BufReader::new(stdout).lines();
    let mut startup_log = Vec::new();
    let port = lines
        .by_ref()
        .map_while(Result::ok)
        .find(|line| {
            startup_log.push(line.clone());
            line.contains("listening")
        })
        .and_then(|line| {
            let address = line.split("bind_addr=").nth(1)?;
            let after = address.split_whitespace().next()?.rsplit_once(':')?.1;
            let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<u16>().ok()
        })
        .expect("stealth-api did not report its listening port");
    // Keep draining stdout so the server never blocks on a full pipe.
    std::thread::spawn(move || lines.for_each(drop));
    (api, port, startup_log)
}

async fn status_with_host(port: u16, host: &str) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/api/wallet/scan"))
        .header("host", host)
        .json(&serde_json::json!({ "descriptor": "wpkh(x/0/*)" }))
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn running_server_checks_the_host_header() {
    let (_api, port, startup_log) = spawn_api_on_any_port(
        &[
            "--allow-host",
            "flag.example",
            "--allow-host=equals.example:8080",
        ],
        &[("STEALTH_API_ALLOW_HOSTS", "env.example")],
    );
    assert!(
        startup_log
            .iter()
            .any(|line| line.contains("Host check accepts")
                && line.contains("flag.example")
                && line.contains("env.example")),
        "startup log: {startup_log:?}"
    );
    assert!(
        startup_log
            .iter()
            .any(|line| line.contains("--allow-host flag.example has no port")),
        "startup log: {startup_log:?}"
    );

    for host in [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        "flag.example".to_owned(),
        "equals.example:8080".to_owned(),
        "env.example".to_owned(),
    ] {
        let status = status_with_host(port, &host).await;
        assert_ne!(status, reqwest::StatusCode::FORBIDDEN, "host {host}");
    }
    for host in [
        "attacker.example".to_owned(),
        format!("attacker.example:{port}"),
        "localhost:5173".to_owned(),
    ] {
        let status = status_with_host(port, &host).await;
        assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "host {host}");
    }
}

#[tokio::test]
async fn running_server_bound_to_every_interface_warns_about_host_names() {
    let (_api, port, startup_log) =
        spawn_api_on_any_port(&[], &[("STEALTH_API_BIND", "0.0.0.0:0")]);
    assert!(
        startup_log
            .iter()
            .any(|line| line.contains("WARN")
                && line.contains("only loopback Host names are accepted")),
        "startup log: {startup_log:?}"
    );
    assert_eq!(
        status_with_host(port, &format!("0.0.0.0:{port}")).await,
        reqwest::StatusCode::FORBIDDEN
    );
}

#[test]
fn allow_host_on_443_stops_startup_unless_the_api_listens_on_443() {
    // Port 1 cannot be bound without privileges, so a run that gets past the host check still exits.
    let mut child = api_command()
        .args(["--allow-host", "stealth.lan:443"])
        .env("STEALTH_API_BIND", "127.0.0.1:1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut exited = false;
    for _ in 0..100 {
        if child.try_wait().unwrap().is_some() {
            exited = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !exited {
        let _ = child.kill();
    }
    let output = child.wait_with_output().unwrap();
    assert!(exited, "stealth-api kept running");
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("stealth.lan:443"), "stderr: {stderr}");
    assert!(stderr.contains("without :443"), "stderr: {stderr}");
}
