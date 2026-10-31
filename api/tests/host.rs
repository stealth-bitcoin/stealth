use std::net::SocketAddr;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use stealth_api::{AllowedHosts, AllowedOrigins};
use tower::ServiceExt;

const SCAN_PATH: &str = "/api/wallet/scan";

fn app_bound_to(bind: &str, extra: &[&str]) -> Router {
    let bind: SocketAddr = bind.parse().unwrap();
    let hosts = AllowedHosts::for_bind(bind)
        .with_extra(extra.iter().copied())
        .unwrap();
    stealth_api::app_with_hosts(None, AllowedOrigins::localhost(), hosts)
}

fn scan_request(host: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(SCAN_PATH)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(host) = host {
        builder = builder.header(header::HOST, host);
    }
    builder
        .body(Body::from(r#"{"descriptor":"wpkh(x/0/*)"}"#))
        .unwrap()
}

// No gateway is configured, so a request that reaches the scan route gets 503.
async fn scan_status(app: Router, host: Option<&str>) -> StatusCode {
    app.oneshot(scan_request(host)).await.unwrap().status()
}

#[tokio::test]
async fn loopback_hosts_on_the_bound_port_reach_the_api() {
    for bind in ["127.0.0.1:20899", "[::1]:20899"] {
        for host in [
            "127.0.0.1:20899",
            "[::1]:20899",
            "localhost:20899",
            "LocalHost:20899",
        ] {
            let status = scan_status(app_bound_to(bind, &[]), Some(host)).await;
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "bind {bind}, host {host}"
            );
        }
    }
}

#[tokio::test]
async fn configured_host_names_reach_the_api() {
    let app = || app_bound_to("127.0.0.1:20899", &["stealth.lan:20899", "Wallet.Example"]);
    for host in ["stealth.lan:20899", "wallet.example", "WALLET.example"] {
        assert_eq!(
            scan_status(app(), Some(host)).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "host {host}"
        );
    }
    for host in ["stealth.lan", "stealth.lan:20900", "wallet.example:20899"] {
        assert_eq!(
            scan_status(app(), Some(host)).await,
            StatusCode::FORBIDDEN,
            "host {host}"
        );
    }
}

#[tokio::test]
async fn foreign_host_is_refused_with_a_plain_403() {
    for host in [
        "attacker.example",
        "attacker.example:20899",
        "localhost.attacker.example:20899",
        "127.0.0.1.attacker.example:20899",
        "0.0.0.0:20899",
        "",
    ] {
        let response = app_bound_to("127.0.0.1:20899", &[])
            .oneshot(scan_request(Some(host)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "host {host:?}");
        assert!(response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|value| value.to_str().unwrap().starts_with("text/plain")));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Host not allowed\n", "host {host:?}");
    }
}

#[tokio::test]
async fn loopback_host_on_another_port_is_refused() {
    for host in [
        "localhost:5173",
        "127.0.0.1:20900",
        "[::1]:80",
        "localhost",
        "127.0.0.1",
    ] {
        assert_eq!(
            scan_status(app_bound_to("127.0.0.1:20899", &[]), Some(host)).await,
            StatusCode::FORBIDDEN,
            "host {host}"
        );
    }
}

#[tokio::test]
async fn bound_to_port_80_the_port_may_be_left_out() {
    for host in ["localhost", "127.0.0.1", "localhost:80"] {
        assert_eq!(
            scan_status(app_bound_to("127.0.0.1:80", &[]), Some(host)).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "host {host}"
        );
    }
}

#[tokio::test]
async fn request_without_a_host_header_is_refused() {
    assert_eq!(
        scan_status(app_bound_to("127.0.0.1:20899", &[]), None).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn preflight_with_a_foreign_host_is_refused_before_cors_answers() {
    let request = |host: &str| {
        Request::builder()
            .method(Method::OPTIONS)
            .uri(SCAN_PATH)
            .header(header::HOST, host)
            .header(header::ORIGIN, "http://localhost:5173")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
            .body(Body::empty())
            .unwrap()
    };
    let app = || app_bound_to("127.0.0.1:20899", &[]);

    let response = app()
        .oneshot(request("attacker.example:20899"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!response
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));

    let response = app().oneshot(request("localhost:20899")).await.unwrap();
    assert!(response.status().is_success());
    assert!(response
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
}

#[tokio::test]
async fn unknown_path_with_a_foreign_host_is_refused_too() {
    let request = Request::builder()
        .uri("/nothing-here")
        .header(header::HOST, "attacker.example:20899")
        .body(Body::empty())
        .unwrap();
    let response = app_bound_to("127.0.0.1:20899", &[])
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bound_to_every_interface_only_loopback_and_configured_names_pass() {
    let app = || app_bound_to("0.0.0.0:20899", &["192.168.1.20:20899", "stealth.lan"]);
    for host in [
        "localhost:20899",
        "127.0.0.1:20899",
        "[::1]:20899",
        "192.168.1.20:20899",
        "stealth.lan",
    ] {
        assert_eq!(
            scan_status(app(), Some(host)).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "host {host}"
        );
    }
    for host in [
        "0.0.0.0:20899",
        "192.168.1.21:20899",
        "attacker.example:20899",
    ] {
        assert_eq!(
            scan_status(app(), Some(host)).await,
            StatusCode::FORBIDDEN,
            "host {host}"
        );
    }

    let ipv6_any = app_bound_to("[::]:20899", &[]);
    assert_eq!(
        scan_status(ipv6_any, Some("[::]:20899")).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn bound_to_a_specific_address_that_address_passes() {
    let app = || app_bound_to("192.168.1.20:20899", &[]);
    for host in ["192.168.1.20:20899", "localhost:20899"] {
        assert_eq!(
            scan_status(app(), Some(host)).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "host {host}"
        );
    }
    assert_eq!(
        scan_status(app(), Some("192.168.1.20:20900")).await,
        StatusCode::FORBIDDEN
    );
}

#[test]
fn configured_hosts_are_normalised() {
    let hosts = AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap())
        .with_extra([
            " Stealth.LAN:20899 ",
            "[0:0:0:0:0:0:0:1]:8080",
            "wallet.example",
            "wallet.example",
        ])
        .unwrap();
    assert_eq!(
        hosts.extra(),
        ["stealth.lan:20899", "[::1]:8080", "wallet.example"]
    );
}

#[test]
fn malformed_configured_hosts_are_rejected() {
    for raw in [
        "",
        "*",
        "*.example.org",
        "http://wallet.example.org",
        "wallet.example.org/",
        "wallet example.org",
        "wallet.example.org:notaport",
        "wallet.example.org:70000",
        "wallet.example.org:",
        "user@wallet.example.org",
        "[evil]",
        "bücher.example",
    ] {
        let result = AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap()).with_extra([raw]);
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{raw:?} was accepted"));
        assert!(
            error.to_string().contains(raw.trim()),
            "error for {raw:?}: {error}"
        );
    }
}

#[test]
fn a_configured_host_with_a_scheme_gets_a_specific_reason() {
    let result = AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap())
        .with_extra(["http://stealth.lan"]);
    let error = result
        .err()
        .unwrap_or_else(|| panic!("scheme was accepted"));
    assert!(error.to_string().contains("no scheme"), "error: {error}");
}

#[tokio::test]
async fn a_configured_host_on_port_80_matches_with_or_without_the_port() {
    let hosts = AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap())
        .with_extra(["stealth.lan:80", "[::1]:80"])
        .unwrap();
    assert_eq!(hosts.extra(), ["stealth.lan", "[::1]"]);
    let app = || app_bound_to("127.0.0.1:20899", &["stealth.lan:80"]);
    for host in ["stealth.lan", "stealth.lan:80"] {
        assert_eq!(
            scan_status(app(), Some(host)).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "host {host}"
        );
    }
    for host in ["stealth.lan:8080", "stealth.lan:20899"] {
        assert_eq!(
            scan_status(app(), Some(host)).await,
            StatusCode::FORBIDDEN,
            "host {host}"
        );
    }
}

#[test]
fn malformed_host_errors_talk_about_hosts_not_origins() {
    for (raw, reason) in [
        ("user@stealth.lan", "characters a host name cannot have"),
        ("stealth<lan", "characters a host name cannot have"),
        ("ex%61mple.lan", "cannot contain '%' or '\\'"),
        ("a\\b.lan", "cannot contain '%' or '\\'"),
        (
            "stealth.lan/",
            "a host has no path, query or trailing slash",
        ),
    ] {
        let result = AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap()).with_extra([raw]);
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{raw:?} was accepted"))
            .to_string();
        assert!(error.contains(reason), "error for {raw:?}: {error}");
        assert!(!error.contains("origin"), "error for {raw:?}: {error}");
        assert!(!error.contains("browser"), "error for {raw:?}: {error}");
    }
}

#[tokio::test]
async fn a_host_with_two_ports_is_refused() {
    for (bind, host) in [
        ("127.0.0.1:20899", "localhost:20911:80"),
        ("127.0.0.1:20899", "[::1]:20899:80"),
        ("127.0.0.1:20899", "localhost:80:20899"),
        ("127.0.0.1:20899", "localhost:20899:"),
        ("127.0.0.1:80", "localhost:80:80"),
        ("127.0.0.1:80", "[::1]:80:80"),
    ] {
        assert_eq!(
            scan_status(app_bound_to(bind, &[]), Some(host)).await,
            StatusCode::FORBIDDEN,
            "bind {bind}, host {host}"
        );
    }
    let app = app_bound_to("127.0.0.1:20899", &["stealth.lan"]);
    assert_eq!(
        scan_status(app, Some("stealth.lan:20899:80")).await,
        StatusCode::FORBIDDEN
    );
}

#[test]
fn a_configured_host_on_port_443_is_refused_with_a_hint() {
    let result =
        AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap()).with_extra(["stealth.lan:443"]);
    let error = result
        .err()
        .unwrap_or_else(|| panic!(":443 was accepted"))
        .to_string();
    assert!(error.contains("stealth.lan:443"), "error: {error}");
    assert!(error.contains("without :443"), "error: {error}");
    assert!(error.contains("default HTTPS port"), "error: {error}");
}

#[tokio::test]
async fn bound_to_an_ipv6_address_that_bracketed_address_passes() {
    let app = || app_bound_to("[fd00::1]:20899", &[]);
    assert_eq!(
        scan_status(app(), Some("[fd00::1]:20899")).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        scan_status(app(), Some("[fd00::2]:20899")).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn more_than_one_host_header_is_a_bad_request() {
    for hosts in [
        ["localhost:20899", "attacker.example"],
        ["attacker.example", "localhost:20899"],
        ["localhost:20899", "localhost:20899"],
    ] {
        let mut request = scan_request(Some(hosts[0]));
        request
            .headers_mut()
            .append(header::HOST, hosts[1].parse().unwrap());
        let response = app_bound_to("127.0.0.1:20899", &[])
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "hosts {hosts:?}"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"More than one Host header\n", "hosts {hosts:?}");
    }
}

// RFC 9112 section 3.2.2: the authority of an absolute-form target wins over Host.
#[tokio::test]
async fn an_absolute_form_target_is_judged_by_its_authority() {
    let request = |uri: &str, host: &str| {
        let mut request = scan_request(Some(host));
        *request.uri_mut() = uri.parse().unwrap();
        request
    };
    let status = |uri: &str, host: &str| {
        let request = request(uri, host);
        async move {
            app_bound_to("127.0.0.1:20899", &[])
                .oneshot(request)
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(
        status("http://attacker.example/api/wallet/scan", "localhost:20899").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status("http://localhost:20899/api/wallet/scan", "attacker.example").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        status(
            "http://user@localhost:20899/api/wallet/scan",
            "localhost:20899"
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn bound_to_an_ipv4_mapped_address_its_ipv4_form_passes() {
    let app = || app_bound_to("[::ffff:192.168.1.20]:20899", &[]);
    assert_eq!(
        scan_status(app(), Some("192.168.1.20:20899")).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        scan_status(app(), Some("192.168.1.21:20899")).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn an_https_target_without_a_port_means_port_443() {
    let status = |bind: &str, uri: &str| {
        let mut request = scan_request(Some("localhost"));
        *request.uri_mut() = uri.parse().unwrap();
        let app = app_bound_to(bind, &["stealth.lan"]);
        async move { app.oneshot(request).await.unwrap().status() }
    };
    for (bind, uri, expected) in [
        (
            "127.0.0.1:80",
            "https://localhost/api/wallet/scan",
            StatusCode::FORBIDDEN,
        ),
        (
            "127.0.0.1:80",
            "http://localhost/api/wallet/scan",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "127.0.0.1:443",
            "https://localhost/api/wallet/scan",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "127.0.0.1:443",
            "http://localhost/api/wallet/scan",
            StatusCode::FORBIDDEN,
        ),
        // A host added without a port stands for the scheme's default port.
        (
            "127.0.0.1:20899",
            "https://stealth.lan/api/wallet/scan",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "127.0.0.1:20899",
            "http://stealth.lan/api/wallet/scan",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "127.0.0.1:20899",
            "https://stealth.lan:443/api/wallet/scan",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "127.0.0.1:20899",
            "http://stealth.lan:443/api/wallet/scan",
            StatusCode::FORBIDDEN,
        ),
        (
            "127.0.0.1:20899",
            "https://stealth.lan:8443/api/wallet/scan",
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(status(bind, uri).await, expected, "bind {bind}, uri {uri}");
    }
}

#[tokio::test]
async fn an_ipv4_mapped_unspecified_bind_counts_as_every_interface() {
    let app = || app_bound_to("[::ffff:0.0.0.0]:20899", &[]);
    for host in ["0.0.0.0:20899", "[::ffff:0.0.0.0]:20899"] {
        assert_eq!(
            scan_status(app(), Some(host)).await,
            StatusCode::FORBIDDEN,
            "host {host}"
        );
    }
    assert_eq!(
        scan_status(app(), Some("localhost:20899")).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn hosts_written_without_a_port_are_remembered_as_written() {
    let hosts = AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap())
        .with_extra([
            "stealth.lan",
            "proxy.lan:80",
            "other.lan:20899",
            "[fd00::1]:8080",
            "[FD00::2]",
            "stealth.lan",
        ])
        .unwrap();
    assert_eq!(hosts.added_without_port(), ["stealth.lan", "[fd00::2]"]);
}

#[test]
fn a_configured_host_must_be_a_host_name_or_an_address() {
    let refuse = |raw: &str| {
        AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap())
            .with_extra([raw])
            .err()
            .unwrap_or_else(|| panic!("{raw:?} was accepted"))
            .to_string()
    };
    let error = refuse("a.lan,b.lan");
    assert!(
        error.contains("one host per --allow-host; the env var takes a comma list"),
        "error: {error}"
    );
    for raw in [
        "a\"b.lan",
        "a{b.lan",
        "a}b.lan",
        "a;b.lan",
        "a=b.lan",
        "a_b.lan:20899",
        "a!b.lan",
    ] {
        let error = refuse(raw);
        assert!(error.contains(raw), "error for {raw:?}: {error}");
        assert!(
            error.contains("letters, digits, '-' and '.'"),
            "error for {raw:?}: {error}"
        );
    }
    let hosts = AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap())
        .with_extra([
            "stealth-1.lan:20899",
            "192.168.1.20",
            "[fd00::1]:8080",
            "xn--bcher-kva.example",
        ])
        .unwrap();
    assert_eq!(hosts.extra().len(), 4);
}

#[tokio::test]
async fn an_https_target_matches_only_hosts_written_without_a_port() {
    let status = |uri: &str| {
        let mut request = scan_request(None);
        *request.uri_mut() = uri.parse().unwrap();
        let app = app_bound_to("127.0.0.1:20899", &["stealth.lan", "proxy.lan:80"]);
        async move { app.oneshot(request).await.unwrap().status() }
    };
    assert_eq!(
        status("https://stealth.lan/api/wallet/scan").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        status("https://proxy.lan/api/wallet/scan").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status("http://proxy.lan/api/wallet/scan").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn an_absolute_form_target_without_a_host_header_is_judged_by_its_authority() {
    let status = |uri: &str| {
        let mut request = scan_request(None);
        *request.uri_mut() = uri.parse().unwrap();
        async move {
            app_bound_to("127.0.0.1:20899", &[])
                .oneshot(request)
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(
        status("http://localhost:20899/api/wallet/scan").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        status("http://attacker.example:20899/api/wallet/scan").await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn a_port_with_leading_zeros_is_refused() {
    let app = || app_bound_to("127.0.0.1:20899", &["stealth.lan:8080"]);
    for host in [
        "localhost:020899",
        "localhost:0020899",
        "[::1]:020899",
        "stealth.lan:08080",
    ] {
        assert_eq!(
            scan_status(app(), Some(host)).await,
            StatusCode::FORBIDDEN,
            "host {host}"
        );
    }
    let mut request = scan_request(None);
    *request.uri_mut() = "http://localhost:020899/api/wallet/scan".parse().unwrap();
    assert_eq!(
        app().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    for raw in ["stealth.lan:08080", "[fd00::1]:0443", "stealth.lan:00"] {
        let error = AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap())
            .with_extra([raw])
            .err()
            .unwrap_or_else(|| panic!("{raw:?} was accepted"))
            .to_string();
        assert!(
            error.contains("leading zeros"),
            "error for {raw:?}: {error}"
        );
    }
}

#[tokio::test]
async fn bound_to_a_scoped_address_it_passes_without_its_zone() {
    let app = || app_bound_to("[fe80::1%2]:20899", &[]);
    for host in ["[fe80::1]:20899", "localhost:20899"] {
        assert_eq!(
            scan_status(app(), Some(host)).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "host {host}"
        );
    }
    for host in [
        "[fe80::1%252]:20899",
        "[fe80::1%2]:20899",
        "[fe80::1]:20900",
    ] {
        assert_eq!(
            scan_status(app(), Some(host)).await,
            StatusCode::FORBIDDEN,
            "host {host}"
        );
    }
}

#[tokio::test]
async fn bound_to_443_a_configured_host_on_443_is_kept_and_matches() {
    let hosts = AllowedHosts::for_bind("127.0.0.1:443".parse().unwrap())
        .with_extra(["stealth.lan:443"])
        .unwrap();
    assert_eq!(hosts.extra(), ["stealth.lan:443"]);

    let app = || app_bound_to("127.0.0.1:443", &["stealth.lan:443"]);
    assert_eq!(
        scan_status(app(), Some("stealth.lan:443")).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        scan_status(app(), Some("stealth.lan")).await,
        StatusCode::FORBIDDEN
    );
    for uri in [
        "https://stealth.lan/api/wallet/scan",
        "http://stealth.lan:443/api/wallet/scan",
    ] {
        let mut request = scan_request(None);
        *request.uri_mut() = uri.parse().unwrap();
        assert_eq!(
            app().oneshot(request).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "uri {uri}"
        );
    }
}

#[test]
fn a_configured_host_on_443_is_checked_once_the_bind_is_known() {
    let added = || {
        AllowedHosts::default()
            .with_extra(["stealth.lan:443"])
            .unwrap()
    };
    let error = added()
        .bound_to("127.0.0.1:20899".parse().unwrap())
        .err()
        .unwrap_or_else(|| panic!(":443 was accepted on port 20899"))
        .to_string();
    assert!(error.contains("stealth.lan:443"), "error: {error}");
    assert!(error.contains("without :443"), "error: {error}");
    assert!(added().bound_to("127.0.0.1:443".parse().unwrap()).is_ok());
}

#[tokio::test]
async fn the_scheme_of_an_absolute_form_target_ignores_case() {
    let status = |bind: &str, uri: &str| {
        let mut request = scan_request(None);
        *request.uri_mut() = uri.parse().unwrap();
        let app = app_bound_to(bind, &["stealth.lan"]);
        async move { app.oneshot(request).await.unwrap().status() }
    };
    assert_eq!(
        status("127.0.0.1:20899", "HTTPS://stealth.lan/api/wallet/scan").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        status("127.0.0.1:80", "HttpS://localhost/api/wallet/scan").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status("127.0.0.1:443", "HTTPS://localhost/api/wallet/scan").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn a_refused_request_carries_no_route_headers() {
    let get_scan = |host: &str| {
        Request::builder()
            .method(Method::GET)
            .uri(SCAN_PATH)
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap()
    };
    let response = app_bound_to("127.0.0.1:20899", &[])
        .oneshot(get_scan("attacker.example:20899"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !response.headers().contains_key(header::ALLOW),
        "headers: {:?}",
        response.headers()
    );

    let response = app_bound_to("127.0.0.1:20899", &[])
        .oneshot(get_scan("localhost:20899"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(response.headers().contains_key(header::ALLOW));
}

#[test]
fn an_unbracketed_ipv6_host_gets_a_bracket_hint() {
    for raw in ["::1", "fd00::1", "fe80::1:20899"] {
        let error = AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap())
            .with_extra([raw])
            .err()
            .unwrap_or_else(|| panic!("{raw:?} was accepted"))
            .to_string();
        assert!(
            error.contains("write an IPv6 address in brackets, like [::1]"),
            "error for {raw:?}: {error}"
        );
    }
}

#[test]
fn the_comma_and_bracket_hints_come_before_the_port_checks() {
    let error = |raw: &str| {
        AllowedHosts::for_bind("127.0.0.1:20899".parse().unwrap())
            .with_extra([raw])
            .err()
            .unwrap_or_else(|| panic!("{raw:?} was accepted"))
            .to_string()
    };
    let message = error("fd00:0db8::1");
    assert!(
        message.contains("write an IPv6 address in brackets, like [::1]"),
        "{message}"
    );
    let message = error("a.lan:1,b.lan:2");
    assert!(
        message.contains("one host per --allow-host; the env var takes a comma list"),
        "{message}"
    );
}
