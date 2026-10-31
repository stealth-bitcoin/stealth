use std::sync::Arc;

use axum::http::HeaderValue;
use thiserror::Error;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

/// Web origins allowed to call the API from a browser.
///
/// Loopback origins (`http://localhost`, `http://127.0.0.1` and `http://[::1]`,
/// on any port) are always allowed; anything else must be listed explicitly.
#[derive(Debug, Clone, Default)]
pub struct AllowedOrigins {
    extra: Vec<String>,
}

#[derive(Debug, Error)]
#[error("invalid origin \"{origin}\": {reason} (expected scheme://host[:port], e.g. https://wallet.example.org)")]
pub struct InvalidOrigin {
    origin: String,
    reason: &'static str,
}

impl AllowedOrigins {
    /// Loopback origins only.
    pub fn localhost() -> Self {
        Self::default()
    }

    /// Also allow each of `values`, which must be exact origins.
    pub fn with_extra<I, S>(mut self, values: I) -> Result<Self, InvalidOrigin>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for value in values {
            let origin = parse_origin(value.as_ref())?;
            if !self.extra.contains(&origin) {
                self.extra.push(origin);
            }
        }
        Ok(self)
    }

    /// The explicitly added origins, normalised to lowercase.
    pub fn extra(&self) -> &[String] {
        &self.extra
    }

    pub(crate) fn layer(&self) -> CorsLayer {
        let extra = Arc::new(self.extra.clone());
        let allow = AllowOrigin::predicate(move |origin: &HeaderValue, _| {
            let origin = origin.as_bytes();
            is_loopback_origin(origin)
                || extra
                    .iter()
                    .any(|allowed| allowed.as_bytes().eq_ignore_ascii_case(origin))
        });
        CorsLayer::new()
            .allow_origin(allow)
            .allow_methods(Any)
            .allow_headers(Any)
            .expose_headers(Any)
    }
}

fn is_loopback_origin(origin: &[u8]) -> bool {
    let Some(rest) = std::str::from_utf8(origin)
        .ok()
        .and_then(|origin| origin.strip_prefix("http://"))
    else {
        return false;
    };
    LOOPBACK_HOSTS.iter().any(|host| {
        rest.strip_prefix(host).is_some_and(|port| {
            port.is_empty() || port.strip_prefix(':').is_some_and(is_valid_port)
        })
    })
}

fn is_valid_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok()
}

fn parse_origin(raw: &str) -> Result<String, InvalidOrigin> {
    let invalid = |reason| InvalidOrigin {
        origin: raw.to_owned(),
        reason,
    };
    let origin = raw.trim().to_ascii_lowercase();
    let authority = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .ok_or_else(|| invalid("scheme must be http:// or https://"))?;
    if authority.is_empty() {
        return Err(invalid("host is missing"));
    }
    if authority.contains(['/', '?', '#']) {
        return Err(invalid("an origin has no path, query or trailing slash"));
    }
    if authority.contains(['@', '*'])
        || authority
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(invalid("host contains characters an origin cannot have"));
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(ipv6) => {
            let (address, after) = ipv6
                .split_once(']')
                .ok_or_else(|| invalid("unclosed IPv6 bracket"))?;
            let port = match after.strip_prefix(':') {
                Some(port) => Some(port),
                None if after.is_empty() => None,
                None => return Err(invalid("unexpected text after the IPv6 address")),
            };
            (address, port)
        }
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if host.is_empty() {
        return Err(invalid("host is missing"));
    }
    if port.is_some_and(|port| !is_valid_port(port)) {
        return Err(invalid("port must be a number from 0 to 65535"));
    }
    HeaderValue::from_str(&origin).map_err(|_| invalid("not a valid header value"))?;
    Ok(origin)
}
