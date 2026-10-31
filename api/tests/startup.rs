use std::process::Command;

fn run_api(args: &[&str], env_origins: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stealth-api"));
    command
        .args(args)
        .env_remove("STEALTH_API_ALLOW_ORIGINS")
        .env("STEALTH_API_BIND", "not-an-address")
        .env("STEALTH_RPC_URL", "http://127.0.0.1:1")
        .env("STEALTH_RPC_USER", "u")
        .env("STEALTH_RPC_PASS", "p");
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
    assert!(stderr.contains("--allow-origin"), "stderr: {stderr}");
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
