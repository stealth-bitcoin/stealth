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
    // The Vite proxy and curl may send no Origin at all; CORS must not block them.
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
