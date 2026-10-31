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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
    let port = free_port();
    let _api = RunningApi(
        Command::new(env!("CARGO_BIN_EXE_stealth-api"))
            .args([
                "--allow-origin",
                "https://flag.example",
                "--allow-origin=https://equals.example",
            ])
            .env("STEALTH_API_ALLOW_ORIGINS", "https://env.example")
            .env("STEALTH_API_BIND", format!("127.0.0.1:{port}"))
            .env("STEALTH_RPC_URL", "http://127.0.0.1:1")
            .env("STEALTH_RPC_USER", "u")
            .env("STEALTH_RPC_PASS", "p")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut ready = false;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(ready, "stealth-api did not start listening on port {port}");

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
