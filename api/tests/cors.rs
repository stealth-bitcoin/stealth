use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request};
use axum::Router;
use tower::ServiceExt;

const SCAN_PATH: &str = "/api/wallet/scan";

async fn simple_request(app: Router, origin: &str) -> HeaderMap {
    let request = Request::builder()
        .method(Method::POST)
        .uri(SCAN_PATH)
        .header(header::ORIGIN, origin)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"descriptor":"wpkh(x/0/*)"}"#))
        .unwrap();
    app.oneshot(request).await.unwrap().headers().clone()
}

async fn preflight(app: Router, origin: &str) -> HeaderMap {
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri(SCAN_PATH)
        .header(header::ORIGIN, origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
        .body(Body::empty())
        .unwrap();
    app.oneshot(request).await.unwrap().headers().clone()
}

fn allowed_origin(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .map(|value| value.to_str().unwrap())
}

#[tokio::test]
async fn localhost_origin_on_any_port_is_allowed() {
    for origin in [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:65535",
        "http://localhost",
    ] {
        let headers = simple_request(stealth_api::app(), origin).await;
        assert_eq!(allowed_origin(&headers), Some(origin), "origin {origin}");
    }
}

#[tokio::test]
async fn loopback_ip_origins_are_allowed() {
    for origin in [
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8080",
        "http://[::1]:5173",
    ] {
        let headers = simple_request(stealth_api::app(), origin).await;
        assert_eq!(allowed_origin(&headers), Some(origin), "origin {origin}");
    }
}

#[tokio::test]
async fn foreign_origin_gets_no_allow_origin_header() {
    for origin in [
        "https://evil.example",
        "http://localhost.evil.example",
        "http://127.0.0.1.evil.example:5173",
        "http://evil.example:5173/http://localhost:5173",
        "https://localhost:5173",
        "http://localhost:99999",
        "http://localhost:",
        "null",
    ] {
        let headers = simple_request(stealth_api::app(), origin).await;
        assert_eq!(allowed_origin(&headers), None, "origin {origin}");
    }
}

#[tokio::test]
async fn preflight_from_localhost_is_allowed() {
    let headers = preflight(stealth_api::app(), "http://localhost:5173").await;
    assert_eq!(allowed_origin(&headers), Some("http://localhost:5173"));
    assert!(headers.contains_key(header::ACCESS_CONTROL_ALLOW_METHODS));
}

#[tokio::test]
async fn preflight_from_foreign_origin_gets_no_allow_origin_header() {
    let headers = preflight(stealth_api::app(), "https://evil.example").await;
    assert_eq!(allowed_origin(&headers), None);
}

#[tokio::test]
async fn request_without_origin_still_reaches_the_api() {
    // curl and the CLI send no Origin; CORS must not block them.
    let request = Request::builder()
        .method(Method::POST)
        .uri(SCAN_PATH)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"descriptor":"wpkh(x/0/*)"}"#))
        .unwrap();
    let response = stealth_api::app().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
}

fn app_allowing(extra: &[&str]) -> Router {
    let origins = stealth_api::AllowedOrigins::localhost()
        .with_extra(extra.iter().copied())
        .unwrap();
    stealth_api::app_with_cors(None, origins)
}

#[tokio::test]
async fn extra_origin_is_allowed_alongside_localhost() {
    let app = || app_allowing(&["https://wallet.example.org"]);

    let headers = simple_request(app(), "https://wallet.example.org").await;
    assert_eq!(allowed_origin(&headers), Some("https://wallet.example.org"));
    let headers = preflight(app(), "https://wallet.example.org").await;
    assert_eq!(allowed_origin(&headers), Some("https://wallet.example.org"));
    let headers = simple_request(app(), "http://localhost:5173").await;
    assert_eq!(allowed_origin(&headers), Some("http://localhost:5173"));
    let headers = simple_request(app(), "https://evil.example").await;
    assert_eq!(allowed_origin(&headers), None);
}

#[tokio::test]
async fn extra_origin_with_port_matches_only_that_port() {
    let app = || app_allowing(&["http://192.168.1.20:5173"]);

    let headers = simple_request(app(), "http://192.168.1.20:5173").await;
    assert_eq!(allowed_origin(&headers), Some("http://192.168.1.20:5173"));
    let headers = simple_request(app(), "http://192.168.1.20:5174").await;
    assert_eq!(allowed_origin(&headers), None);
}

#[test]
fn malformed_extra_origins_are_rejected() {
    for raw in [
        "",
        "wallet.example.org",
        "ftp://wallet.example.org",
        "https://",
        "https://wallet.example.org/",
        "https://wallet.example.org/app",
        "https://wallet.example.org?x=1",
        "https://user@wallet.example.org",
        "https://*.example.org",
        "*",
        "https://wallet.example.org:notaport",
        "https://wallet.example.org:70000",
        "https://wallet example.org",
    ] {
        let result = stealth_api::AllowedOrigins::localhost().with_extra([raw]);
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{raw:?} was accepted"));
        assert!(
            error.to_string().contains(raw),
            "error for {raw:?}: {error}"
        );
    }
}

#[test]
fn extra_origins_are_normalised_to_what_browsers_send() {
    for (raw, expected) in [
        (
            "https://wallet.example.org:443",
            "https://wallet.example.org",
        ),
        ("http://wallet.example.org:80", "http://wallet.example.org"),
        (
            "https://wallet.example.org:80",
            "https://wallet.example.org:80",
        ),
        (
            "http://wallet.example.org:05173",
            "http://wallet.example.org:5173",
        ),
        ("HTTPS://Wallet.Example.ORG", "https://wallet.example.org"),
        ("http://[0:0:0:0:0:0:0:1]:5173", "http://[::1]:5173"),
        ("http://[FE80:0:0:0:0:0:0:1]", "http://[fe80::1]"),
        (
            "https://xn--bcher-kva.example",
            "https://xn--bcher-kva.example",
        ),
    ] {
        let origins = stealth_api::AllowedOrigins::localhost()
            .with_extra([raw])
            .unwrap_or_else(|error| panic!("{raw:?} rejected: {error}"));
        assert_eq!(origins.extra(), [expected], "origin {raw:?}");
    }
}

#[tokio::test]
async fn extra_origin_with_default_port_matches_the_browser_origin() {
    let headers = simple_request(
        app_allowing(&["https://wallet.example.org:443"]),
        "https://wallet.example.org",
    )
    .await;
    assert_eq!(allowed_origin(&headers), Some("https://wallet.example.org"));
}

#[test]
fn bracketed_host_must_be_an_ipv6_address() {
    for raw in [
        "http://[evil]",
        "http://[127.0.0.1]:5173",
        "http://[::1%25eth0]",
        "http://[]",
    ] {
        let result = stealth_api::AllowedOrigins::localhost().with_extra([raw]);
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{raw:?} was accepted"));
        assert!(
            error.to_string().contains("IPv6"),
            "error for {raw:?}: {error}"
        );
    }
}

#[test]
fn non_ascii_host_is_refused_with_a_punycode_hint() {
    let result = stealth_api::AllowedOrigins::localhost().with_extra(["https://bücher.example"]);
    let error = result
        .err()
        .unwrap_or_else(|| panic!("non-ASCII host was accepted"));
    assert!(error.to_string().contains("punycode"), "error: {error}");
    assert!(
        error.to_string().contains("bücher.example"),
        "error: {error}"
    );
}

async fn private_network_preflight(app: Router, origin: &str) -> HeaderMap {
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri(SCAN_PATH)
        .header(header::ORIGIN, origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header("access-control-request-private-network", "true")
        .body(Body::empty())
        .unwrap();
    app.oneshot(request).await.unwrap().headers().clone()
}

fn allows_private_network(headers: &HeaderMap) -> bool {
    headers
        .get("access-control-allow-private-network")
        .is_some_and(|value| value == "true")
}

#[tokio::test]
async fn private_network_access_is_granted_to_extra_origins_only() {
    let app = || app_allowing(&["https://wallet.example.org"]);

    let headers = private_network_preflight(app(), "https://wallet.example.org").await;
    assert_eq!(allowed_origin(&headers), Some("https://wallet.example.org"));
    assert!(allows_private_network(&headers));

    let headers = private_network_preflight(app(), "http://localhost:5173").await;
    assert!(!allows_private_network(&headers));

    let headers = private_network_preflight(app(), "https://evil.example").await;
    assert!(!allows_private_network(&headers));
    assert_eq!(allowed_origin(&headers), None);
}

#[test]
fn hosts_a_browser_would_rewrite_are_refused() {
    for (raw, hint) in [
        ("http://192.168.010.5", "IPv4"),
        ("http://127.1", "IPv4"),
        ("http://0x7f000001", "IPv4"),
        ("http://127.0.0.0x1", "IPv4"),
        ("http://256.1.1.1", "IPv4"),
        ("http://1.2.3.4.5", "IPv4"),
        ("http://wallet.example.42", "IPv4"),
        ("http://ex%61mple.com", "%"),
        ("http://a\\b", "\\"),
    ] {
        let result = stealth_api::AllowedOrigins::localhost().with_extra([raw]);
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{raw:?} was accepted"));
        let message = error.to_string();
        assert!(message.contains(raw), "error for {raw:?}: {message}");
        assert!(message.contains(hint), "error for {raw:?}: {message}");
    }
}

#[test]
fn canonical_ipv4_and_names_with_digits_are_accepted() {
    for raw in [
        "http://192.168.10.5:5173",
        "http://0.0.0.0",
        "https://255.255.255.255",
        "https://1password.example",
        "https://wallet42.example",
        "https://wallet.example.",
    ] {
        let result = stealth_api::AllowedOrigins::localhost().with_extra([raw]);
        assert!(result.is_ok(), "{raw:?} was refused: {:?}", result.err());
    }
}

#[test]
fn forbidden_host_code_points_are_refused() {
    for raw in [
        "http://a<b.example",
        "http://a>b.example",
        "http://a^b.example",
        "http://a|b.example",
        "http://a[b.example",
        "http://a]b.example",
        "http://wallet.example]",
        "http://a:b:c.example",
        "http://a\tb.example",
        "http://a\u{7f}b.example",
        "http://a\0b.example",
    ] {
        let result = stealth_api::AllowedOrigins::localhost().with_extra([raw]);
        assert!(result.is_err(), "{raw:?} was accepted");
    }
}

#[test]
fn ipv4_mapped_ipv6_origins_are_refused_as_unsupported() {
    for raw in ["http://[::ffff:127.0.0.1]", "http://[::ffff:c0a8:105]:5173"] {
        let result = stealth_api::AllowedOrigins::localhost().with_extra([raw]);
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{raw:?} was accepted"));
        let message = error.to_string();
        assert!(
            message.contains("not supported"),
            "error for {raw:?}: {message}"
        );
        assert!(
            !message.contains("use the IPv4"),
            "error for {raw:?}: {message}"
        );
    }
}

#[test]
fn malformed_authority_gets_a_specific_reason() {
    for (raw, reason) in [
        ("http://[::1]x", "unexpected text after the IPv6 address"),
        (
            "http://[::1]x:5173",
            "unexpected text after the IPv6 address",
        ),
        ("http://[::1", "unclosed IPv6 bracket"),
        ("http://[::1:5173", "unclosed IPv6 bracket"),
        (
            "http://example.com:",
            "empty port is not allowed; remove the trailing colon",
        ),
        (
            "http://[::1]:",
            "empty port is not allowed; remove the trailing colon",
        ),
    ] {
        let result = stealth_api::AllowedOrigins::localhost().with_extra([raw]);
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{raw:?} was accepted"));
        assert!(
            error.to_string().contains(reason),
            "error for {raw:?}: {error}"
        );
    }
}
