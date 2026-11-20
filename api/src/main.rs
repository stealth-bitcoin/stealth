use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ini::Ini;
use stealth_api::rpc::{self, RpcSettings};
use stealth_api::{app_with_hosts, AllowedHosts, AllowedOrigins};
use stealth_bitcoincore::BitcoinCoreRpc;
use stealth_engine::gateway::BlockchainGateway;
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
Usage: stealth-api [--allow-origin <origin>]... [--allow-host <host>]...

Options:
  --allow-origin <origin>  Also allow this web origin (scheme://host[:port]); repeatable
  --allow-host <host>      Also answer requests whose Host header is this host[:port]; repeatable
  -h, --help               Print this help

Environment:
  STEALTH_API_BIND           Listen address (default 127.0.0.1:20899)
  STEALTH_API_ALLOW_ORIGINS  Extra web origins, comma-separated
  STEALTH_API_ALLOW_HOSTS    Extra Host header values, comma-separated
  STEALTH_RPC_URL            bitcoind RPC endpoint (default: auto-detected)
  STEALTH_RPC_USER           RPC username (used only when both are set)
  STEALTH_RPC_PASS           RPC password (used only when both are set)
  STEALTH_RPC_COOKIE         Path to the RPC .cookie file
  RUST_LOG                   Log filter (default info)
  HOME                       Used to find the node's cookie under ~/.bitcoin

Without RPC credentials in the environment, the API reads ./bitcoin.conf and
then looks for a cookie file under ~/.bitcoin.

Loopback origins (localhost, 127.0.0.1, [::1]) are always allowed.
Requests must name the API in their Host header: localhost, 127.0.0.1 or [::1]
on the bound port, the bound address itself, or an added host; others get 403.
";

fn main() -> ExitCode {
    init_tracing();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let Some((origins, hosts)) = read_allowed()? else {
        print!("{USAGE}");
        return Ok(());
    };

    // `BitcoinCoreRpc` uses `reqwest::blocking::Client`, which must be
    // constructed outside a Tokio runtime.
    let gateway: Arc<dyn BlockchainGateway + Send + Sync> = Arc::new(build_gateway()?);
    let bind_addr = read_bind_addr()?;
    let hosts = hosts.bound_to(bind_addr).map_err(|error| {
        format!("invalid --allow-host or STEALTH_API_ALLOW_HOSTS value: {error}")
    })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_server(bind_addr, gateway.clone(), origins, hosts))?;
    // Keep one strong reference until after async serving ends so the blocking
    // client drops outside async context.
    drop(gateway);
    Ok(())
}

async fn run_server(
    bind_addr: SocketAddr,
    gateway: Arc<dyn BlockchainGateway + Send + Sync>,
    origins: AllowedOrigins,
    hosts: AllowedHosts,
) -> std::io::Result<()> {
    if !origins.extra().is_empty() {
        tracing::info!(extra = ?origins.extra(), "CORS allows loopback origins plus extra origins");
    }
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    // Read back the address so a bind to port 0 checks Host against the real port.
    let bind_addr = listener.local_addr()?;
    match host_check_notice(bind_addr, hosts.extra()) {
        Some(HostNotice::Warn(message)) => tracing::warn!(%bind_addr, "{message}"),
        Some(HostNotice::Info(message)) => tracing::info!("{message}"),
        None => {}
    }
    if let Some(message) = scoped_bind_warning(bind_addr) {
        tracing::warn!("{message}");
    }
    for message in portless_host_warnings(bind_addr, &hosts) {
        tracing::warn!("{message}");
    }
    let hosts = hosts.bound_to(bind_addr).map_err(std::io::Error::other)?;
    let app = app_with_hosts(Some(gateway), origins, hosts);

    tracing::info!(%bind_addr, "stealth-api listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Debug, PartialEq)]
enum HostNotice {
    Warn(String),
    Info(String),
}

fn host_check_notice(bind: SocketAddr, extra: &[String]) -> Option<HostNotice> {
    let unspecified = bind.ip().to_canonical().is_unspecified();
    if extra.is_empty() {
        return unspecified.then(|| {
            HostNotice::Warn(
                "bound to every interface, but only loopback Host names are accepted; add --allow-host for the name clients use".to_owned(),
            )
        });
    }
    let accepted = if unspecified {
        "loopback names"
    } else {
        "loopback names, the bound address"
    };
    Some(HostNotice::Info(format!(
        "Host check accepts {accepted} and extra hosts {extra:?}"
    )))
}

// A host added without a port only matches requests on port 80, which is right behind a proxy only.
fn portless_host_warnings(bind: SocketAddr, hosts: &AllowedHosts) -> Vec<String> {
    let port = bind.port();
    if port == 80 {
        return Vec::new();
    }
    let bound = AllowedHosts::for_bind(bind);
    hosts
        .added_without_port()
        .iter()
        .filter(|host| !bound.accepts(&format!("{host}:{port}")))
        .map(|host| {
            format!(
                "--allow-host {host} has no port: clients reaching the API directly send {host}:{port}, so add that form too unless a proxy serves {host} on port 80 or 443"
            )
        })
        .collect()
}

// Ipv6Addr has no zone, so the bound address is accepted in its unscoped form only.
fn scoped_bind_warning(bind: SocketAddr) -> Option<String> {
    match bind {
        SocketAddr::V6(v6) if v6.scope_id() != 0 => Some(format!(
            "bound to the scoped address {bind}: the Host check accepts it without its zone, as [{}]:{}, and a Host carrying a zone is refused",
            v6.ip(),
            v6.port()
        )),
        _ => None,
    }
}

fn read_bind_addr() -> Result<SocketAddr, String> {
    let raw = std::env::var("STEALTH_API_BIND").unwrap_or_else(|_| "127.0.0.1:20899".to_owned());
    raw.parse::<SocketAddr>()
        .map_err(|_| format!("invalid STEALTH_API_BIND value: {raw}"))
}

/// `None` when the user asked for `--help`.
fn read_allowed() -> Result<Option<(AllowedOrigins, AllowedHosts)>, String> {
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|arg| format!("argument is not valid UTF-8: {}", arg.to_string_lossy()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if wants_help(&args) {
        return Ok(None);
    }
    let origins_env = read_env("STEALTH_API_ALLOW_ORIGINS")?;
    let hosts_env = read_env("STEALTH_API_ALLOW_HOSTS")?;
    allowed_from(args.into_iter(), origins_env, hosts_env).map(Some)
}

fn read_env(name: &str) -> Result<Option<String>, String> {
    std::env::var_os(name)
        .map(|raw| {
            raw.into_string()
                .map_err(|raw| format!("{name} is not valid UTF-8: {}", raw.to_string_lossy()))
        })
        .transpose()
}

fn comma_separated(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

// A flag in the value position of --allow-origin or --allow-host is a missing value, not a request for help.
fn wants_help(args: &[String]) -> bool {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return true,
            "--allow-origin" | "--allow-host" => {
                args.next();
            }
            _ => {}
        }
    }
    false
}

fn allowed_from(
    mut args: impl Iterator<Item = String>,
    origins_env: Option<String>,
    hosts_env: Option<String>,
) -> Result<(AllowedOrigins, AllowedHosts), String> {
    let mut origins = AllowedOrigins::localhost();
    if let Some(raw) = origins_env {
        origins = origins
            .with_extra(comma_separated(&raw))
            .map_err(|error| format!("invalid STEALTH_API_ALLOW_ORIGINS value: {error}"))?;
    }
    let mut hosts = AllowedHosts::default();
    if let Some(raw) = hosts_env {
        hosts = hosts
            .with_extra(comma_separated(&raw))
            .map_err(|error| format!("invalid STEALTH_API_ALLOW_HOSTS value: {error}"))?;
    }

    let mut flagged_origins = Vec::new();
    let mut flagged_hosts = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--allow-origin" {
            let value = args.next().filter(|value| !value.starts_with('-')).ok_or(
                "--allow-origin needs a value, e.g. --allow-origin https://wallet.example.org",
            )?;
            flagged_origins.push(value);
        } else if let Some(value) = arg.strip_prefix("--allow-origin=") {
            flagged_origins.push(value.to_owned());
        } else if arg == "--allow-host" {
            let value = args
                .next()
                .filter(|value| !value.starts_with('-'))
                .ok_or("--allow-host needs a value, e.g. --allow-host stealth.lan:20899")?;
            flagged_hosts.push(value);
        } else if let Some(value) = arg.strip_prefix("--allow-host=") {
            flagged_hosts.push(value.to_owned());
        } else {
            return Err(format!("unknown argument: {arg} (see --help)"));
        }
    }
    let origins = origins
        .with_extra(flagged_origins)
        .map_err(|error| format!("invalid --allow-origin value: {error}"))?;
    let hosts = hosts
        .with_extra(flagged_hosts)
        .map_err(|error| format!("invalid --allow-host value: {error}"))?;
    Ok((origins, hosts))
}

fn build_gateway() -> Result<BitcoinCoreRpc, Box<dyn std::error::Error>> {
    let url = std::env::var("STEALTH_RPC_URL").unwrap_or_else(|_| auto_detect_rpc_url());
    let settings = RpcSettings {
        user: std::env::var("STEALTH_RPC_USER").ok(),
        pass: std::env::var("STEALTH_RPC_PASS").ok(),
        cookie: std::env::var_os("STEALTH_RPC_COOKIE").map(PathBuf::from),
        url,
    };
    Ok(rpc::build_gateway(
        &settings,
        read_bitcoin_conf_credentials,
        || detect_cookie_file(&settings.url),
    )?)
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .without_time()
        .try_init();
}

fn auto_detect_rpc_url() -> String {
    // Prefer regtest first for local development workflows.
    const CANDIDATES: [(&str, &str); 4] = [
        ("http://127.0.0.1:18443", "regtest"),
        ("http://127.0.0.1:8332", "mainnet"),
        ("http://127.0.0.1:18332", "testnet"),
        ("http://127.0.0.1:38332", "signet"),
    ];

    for (url, network) in CANDIDATES {
        if rpc_port_reachable(url) {
            tracing::info!(rpc_url = %url, %network, "auto-detected local bitcoind RPC");
            return url.to_owned();
        }
    }

    let fallback = "http://127.0.0.1:8332".to_owned();
    tracing::warn!(
        rpc_url = %fallback,
        "could not auto-detect a local bitcoind RPC port; using fallback"
    );
    fallback
}

fn rpc_port_reachable(url: &str) -> bool {
    let Some((host, port)) = host_port_from_url(url) else {
        return false;
    };

    let Ok(addrs) = (host.as_str(), port).to_socket_addrs() else {
        return false;
    };

    for addr in addrs {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok() {
            return true;
        }
    }
    false
}

fn host_port_from_url(url: &str) -> Option<(String, u16)> {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = without_scheme.split('/').next()?;
    let (host, port_str) = authority.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    Some((host.to_owned(), port))
}

fn detect_cookie_file(url: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let bitcoin_dir = PathBuf::from(home).join(".bitcoin");
    let port = host_port_from_url(url)
        .map(|(_, port)| port)
        .unwrap_or(8332);

    rpc::cookie_candidates_for_port(&bitcoin_dir, port)
        .into_iter()
        .find(|candidate| candidate.exists())
}

fn read_bitcoin_conf_credentials() -> Option<(String, String)> {
    let conf = Ini::load_from_file("bitcoin.conf").ok()?;
    let try_section = |props: &ini::Properties| -> Option<(String, String)> {
        let user = props.get("rpcuser")?;
        let pass = props.get("rpcpassword")?;
        Some((user.to_owned(), pass.to_owned()))
    };
    try_section(conf.general_section())
        .or_else(|| conf.section(Some("regtest")).and_then(try_section))
        .or_else(|| conf.section(Some("test")).and_then(try_section))
        .or_else(|| conf.section(Some("signet")).and_then(try_section))
        .or_else(|| conf.section(Some("main")).and_then(try_section))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(bind: &str, extra: &[&str]) -> Option<HostNotice> {
        let extra: Vec<String> = extra.iter().map(|host| (*host).to_owned()).collect();
        host_check_notice(bind.parse().unwrap(), &extra)
    }

    #[test]
    fn loopback_bind_without_extra_hosts_logs_nothing() {
        assert_eq!(notice("127.0.0.1:20899", &[]), None);
        assert_eq!(notice("[::1]:20899", &[]), None);
    }

    #[test]
    fn specific_address_without_extra_hosts_logs_nothing() {
        assert_eq!(notice("192.168.1.20:20899", &[]), None);
    }

    #[test]
    fn every_interface_without_extra_hosts_warns() {
        for bind in ["0.0.0.0:20899", "[::]:20899", "[::ffff:0.0.0.0]:20899"] {
            let Some(HostNotice::Warn(message)) = notice(bind, &[]) else {
                panic!("no warning for {bind}");
            };
            assert!(message.contains("only loopback"), "{message}");
            assert!(message.contains("--allow-host"), "{message}");
        }
    }

    #[test]
    fn extra_hosts_are_listed_in_an_info_line() {
        let Some(HostNotice::Info(message)) = notice("0.0.0.0:20899", &["stealth.lan"]) else {
            panic!("no info line");
        };
        assert!(message.contains("loopback names"), "{message}");
        assert!(!message.contains("bound address"), "{message}");
        assert!(message.contains("stealth.lan"), "{message}");

        let Some(HostNotice::Info(message)) = notice("192.168.1.20:20899", &["stealth.lan"]) else {
            panic!("no info line");
        };
        assert!(message.contains("the bound address"), "{message}");
        assert!(message.contains("stealth.lan"), "{message}");

        let Some(HostNotice::Info(message)) = notice("[::ffff:0.0.0.0]:20899", &["stealth.lan"])
        else {
            panic!("no info line");
        };
        assert!(!message.contains("bound address"), "{message}");
    }

    fn portless_warnings(bind: &str, extra: &[&str]) -> Vec<String> {
        let hosts = AllowedHosts::default().with_extra(extra).unwrap();
        portless_host_warnings(bind.parse().unwrap(), &hosts)
    }

    #[test]
    fn a_host_without_a_port_warns_when_the_api_is_not_on_port_80() {
        let warnings = portless_warnings(
            "0.0.0.0:20899",
            &[
                "stealth.lan",
                "proxy.lan:80",
                "other.lan:20899",
                "[fd00::1]:8080",
                "[fd00::2]",
            ],
        );
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("stealth.lan:20899"), "{}", warnings[0]);
        assert!(warnings[0].contains("port 80 or 443"), "{}", warnings[0]);
        assert!(warnings[1].contains("[fd00::2]:20899"), "{}", warnings[1]);
    }

    #[test]
    fn bound_to_443_the_advised_form_is_one_startup_accepts() {
        let warnings = portless_warnings("0.0.0.0:443", &["stealth.lan"]);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("stealth.lan:443"), "{}", warnings[0]);
        assert!(AllowedHosts::default()
            .with_extra(["stealth.lan:443"])
            .and_then(|hosts| hosts.bound_to("0.0.0.0:443".parse().unwrap()))
            .is_ok());
    }

    #[test]
    fn a_host_without_a_port_is_fine_on_port_80() {
        assert!(portless_warnings("0.0.0.0:80", &["stealth.lan"]).is_empty());
    }

    #[test]
    fn hosts_the_bound_port_already_accepts_get_no_portless_warning() {
        let warnings = portless_warnings(
            "0.0.0.0:20899",
            &["localhost", "127.0.0.1", "[::1]", "stealth.lan"],
        );
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("stealth.lan:20899"), "{}", warnings[0]);

        let warnings = portless_warnings("192.168.1.20:20899", &["192.168.1.20", "10.0.0.5"]);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("10.0.0.5:20899"), "{}", warnings[0]);
    }

    #[test]
    fn a_scoped_link_local_bind_warns() {
        let warning = scoped_bind_warning("[fe80::1%2]:20899".parse().unwrap())
            .unwrap_or_else(|| panic!("no warning"));
        assert!(warning.contains("[fe80::1%2]:20899"), "{warning}");
        assert!(warning.contains("[fe80::1]:20899"), "{warning}");
        assert!(warning.contains("without its zone"), "{warning}");
        assert!(warning.contains("carrying a zone is refused"), "{warning}");
        for bind in ["[fe80::1]:20899", "[::1]:20899", "127.0.0.1:20899"] {
            assert_eq!(scoped_bind_warning(bind.parse().unwrap()), None, "{bind}");
        }
    }
}
