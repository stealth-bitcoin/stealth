use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

use crate::cors::{parse_authority, AuthorityError};

const LOOPBACK_NAMES: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

const NOT_ON_443: &str = "write it without :443 unless the API itself listens on 443; clients leave the default HTTPS port out";

/// `Host` header values the API answers to; every other request gets 403.
///
/// The loopback names (`localhost`, `127.0.0.1` and `[::1]`) on the bound port
/// are always accepted, and so is the bound address itself unless it is the
/// unspecified `0.0.0.0` or `[::]`. Extra names are matched exactly, except
/// that `:80` and no port are the same.
#[derive(Debug, Clone, Default)]
pub struct AllowedHosts {
    bound_port: Option<u16>,
    bound: Vec<String>,
    extra: Vec<String>,
    without_port: Vec<String>,
}

#[derive(Debug, Error)]
#[error("invalid host \"{host}\": {reason} (expected host[:port], e.g. stealth.lan:20899)")]
pub struct InvalidHost {
    host: String,
    reason: &'static str,
}

impl AllowedHosts {
    /// The names a client on this machine uses to reach `bind`.
    pub fn for_bind(bind: SocketAddr) -> Self {
        Self::default().set_bound(bind)
    }

    /// Replace the bound address, keeping the extra names; an extra host on
    /// `:443` is refused unless the API listens on 443.
    pub fn bound_to(self, bind: SocketAddr) -> Result<Self, InvalidHost> {
        if bind.port() != 443 {
            if let Some(host) = self.extra.iter().find(|host| host.ends_with(":443")) {
                return Err(InvalidHost {
                    host: host.clone(),
                    reason: NOT_ON_443,
                });
            }
        }
        Ok(self.set_bound(bind))
    }

    fn set_bound(mut self, bind: SocketAddr) -> Self {
        let port = bind.port();
        self.bound_port = Some(port);
        let mut names: Vec<String> = LOOPBACK_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        // Clients reach a mapped address by its IPv4 form, and the parser refuses the mapped one.
        let ip = bind.ip().to_canonical();
        if !ip.is_unspecified() {
            let address = match ip {
                IpAddr::V4(v4) => v4.to_string(),
                IpAddr::V6(v6) => format!("[{v6}]"),
            };
            if !names.contains(&address) {
                names.push(address);
            }
        }
        self.bound = names
            .into_iter()
            .map(|name| with_port(name, Some(port)))
            .collect();
        self
    }

    /// Also accept each of `values`, written as `host` or `host:port`.
    pub fn with_extra<I, S>(mut self, values: I) -> Result<Self, InvalidHost>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for value in values {
            let (host, written_without_port) = parse_host(value.as_ref())?;
            // Without a bind yet, `bound_to` decides about :443 later.
            if host.ends_with(":443") && self.bound_port.is_some_and(|port| port != 443) {
                return Err(InvalidHost {
                    host,
                    reason: NOT_ON_443,
                });
            }
            if written_without_port && !self.without_port.contains(&host) {
                self.without_port.push(host.clone());
            }
            if !self.extra.contains(&host) {
                self.extra.push(host);
            }
        }
        Ok(self)
    }

    /// The added hosts that were written without a port.
    pub fn added_without_port(&self) -> &[String] {
        &self.without_port
    }

    /// The explicitly added host names, normalised.
    pub fn extra(&self) -> &[String] {
        &self.extra
    }

    /// Whether a request with this `Host` value would pass.
    pub fn accepts(&self, host: &str) -> bool {
        self.allows(host.as_bytes())
    }

    fn allows(&self, host: &[u8]) -> bool {
        let Some(host) = normalise(host) else {
            return false;
        };
        self.bound
            .iter()
            .chain(&self.extra)
            .any(|accepted| *accepted == host)
    }

    // An https target without a port is on 443, which a host written without a port stands for too.
    fn allows_https_default(&self, host: &[u8]) -> bool {
        let Some(host) = normalise(host) else {
            return false;
        };
        let on_443 = format!("{host}:443");
        self.bound.contains(&on_443)
            || self.extra.contains(&on_443)
            || self.without_port.contains(&host)
    }
}

pub(crate) async fn check_host(
    State(hosts): State<Arc<AllowedHosts>>,
    request: Request,
    next: Next,
) -> Response {
    let mut host_headers = request.headers().get_all(header::HOST).iter();
    let host_header = host_headers.next();
    // RFC 9112 section 3.2 makes a request with more than one Host a bad request.
    if host_headers.next().is_some() {
        return (StatusCode::BAD_REQUEST, "More than one Host header\n").into_response();
    }
    // An absolute-form target's authority takes precedence over Host (RFC 9112 section 3.2.2).
    let allowed = match request.uri().authority() {
        Some(authority) => {
            // `http` parses the scheme case-insensitively, so `HTTPS://` is this scheme too.
            let https = request.uri().scheme() == Some(&axum::http::uri::Scheme::HTTPS);
            let raw = authority.as_str();
            if https && matches!(authority.port_u16(), None | Some(443)) {
                let without_port = raw.strip_suffix(":443").unwrap_or(raw);
                hosts.allows_https_default(without_port.as_bytes())
            } else {
                hosts.allows(raw.as_bytes())
            }
        }
        None => host_header.is_some_and(|host| hosts.allows(host.as_bytes())),
    };
    if !allowed {
        return (StatusCode::FORBIDDEN, "Host not allowed\n").into_response();
    }
    next.run(request).await
}

fn parse_host(raw: &str) -> Result<(String, bool), InvalidHost> {
    let trimmed = raw.trim();
    let invalid = |reason| InvalidHost {
        host: trimmed.to_owned(),
        reason,
    };
    if !trimmed.is_ascii() {
        return Err(invalid(
            "host must be ASCII; use the punycode form (xn--...) of an internationalised name",
        ));
    }
    if trimmed.contains('*') {
        return Err(invalid(
            "wildcards are not supported; list each host explicitly",
        ));
    }
    if trimmed.contains("://") {
        return Err(invalid("a host has no scheme"));
    }
    if trimmed.contains(',') {
        return Err(invalid(
            "one host per --allow-host; the env var takes a comma list",
        ));
    }
    if !trimmed.starts_with('[') && trimmed.matches(':').count() > 1 {
        return Err(invalid("write an IPv6 address in brackets, like [::1]"));
    }
    if has_padded_port(trimmed) {
        return Err(invalid("a port has no leading zeros"));
    }
    let (host, port) = parse_authority(&trimmed.to_ascii_lowercase()).map_err(|error| {
        invalid(match error {
            AuthorityError::PathOrQuery => "a host has no path, query or trailing slash",
            AuthorityError::ForbiddenCharacter => {
                "host contains characters a host name cannot have"
            }
            AuthorityError::RewrittenCharacter => "host cannot contain '%' or '\\'",
            AuthorityError::Other(reason) => reason,
        })
    })?;
    let is_name_or_ipv4 = |host: &str| {
        host.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    };
    if !host.starts_with('[') && !is_name_or_ipv4(&host) {
        return Err(invalid(
            "a host name has only letters, digits, '-' and '.'; an IPv6 address goes in brackets",
        ));
    }
    Ok((with_port(host, port), port.is_none()))
}

// The Host value is parsed like a configured one, so only a single valid port is accepted.
fn normalise(host: &[u8]) -> Option<String> {
    let host = std::str::from_utf8(host).ok()?;
    if has_padded_port(host) {
        return None;
    }
    let (host, port) = parse_authority(&host.to_ascii_lowercase()).ok()?;
    Some(with_port(host, port))
}

// Clients never pad a port, so `localhost:020899` is not the API's own name.
fn has_padded_port(authority: &str) -> bool {
    let after_address = authority
        .rsplit_once(']')
        .map_or(authority, |(_, after)| after);
    after_address
        .split_once(':')
        .is_some_and(|(_, port)| port.len() > 1 && port.starts_with('0'))
}

// Clients leave the default HTTP port out of the Host header, so `:80` is stored as no port.
fn with_port(host: String, port: Option<u16>) -> String {
    match port {
        Some(port) if port != 80 => format!("{host}:{port}"),
        _ => host,
    }
}
