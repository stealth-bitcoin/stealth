use std::net::Ipv6Addr;
use std::sync::Arc;

use axum::http::HeaderValue;
use thiserror::Error;
use tower_http::cors::{AllowOrigin, AllowPrivateNetwork, Any, CorsLayer};

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

    /// The explicitly added origins, normalised to the form browsers send.
    pub fn extra(&self) -> &[String] {
        &self.extra
    }

    pub(crate) fn layer(&self) -> CorsLayer {
        let extra = Arc::new(self.extra.clone());
        let is_extra = move |origin: &HeaderValue| {
            extra
                .iter()
                .any(|allowed| allowed.as_bytes().eq_ignore_ascii_case(origin.as_bytes()))
        };
        let is_extra_for_network = is_extra.clone();
        let allow = AllowOrigin::predicate(move |origin: &HeaderValue, _| {
            is_loopback_origin(origin.as_bytes()) || is_extra(origin)
        });
        // Chrome asks before a public page reaches a loopback address; loopback pages never need it.
        let private_network = AllowPrivateNetwork::predicate(move |origin: &HeaderValue, _| {
            is_extra_for_network(origin)
        });
        CorsLayer::new()
            .allow_origin(allow)
            .allow_private_network(private_network)
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
            port.is_empty() || port.strip_prefix(':').and_then(parse_port).is_some()
        })
    })
}

fn parse_port(port: &str) -> Option<u16> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse().ok()
}

// Browsers parse a host whose last label is a number as IPv4 and rewrite it, so only the canonical form can match.
fn is_canonical_unless_ipv4(host: &str) -> bool {
    let without_dot = host.strip_suffix('.').unwrap_or(host);
    let last = without_dot.rsplit('.').next().unwrap_or_default();
    let all_digits = |label: &str| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit());
    let is_hex = last
        .strip_prefix("0x")
        .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()));
    if !all_digits(last) && !is_hex {
        return true;
    }
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            all_digits(octet)
                && (*octet == "0" || !octet.starts_with('0'))
                && octet.parse::<u8>().is_ok()
        })
}

fn parse_origin(raw: &str) -> Result<String, InvalidOrigin> {
    let invalid = |reason| InvalidOrigin {
        origin: raw.to_owned(),
        reason,
    };
    let trimmed = raw.trim();
    if !trimmed.is_ascii() {
        return Err(invalid(
            "host must be ASCII; use the punycode form (xn--...) of an internationalised name",
        ));
    }
    let origin = trimmed.to_ascii_lowercase();
    if origin.contains('*') {
        return Err(invalid(
            "wildcards are not supported; list each origin explicitly",
        ));
    }
    let (scheme, default_port, authority) = if let Some(rest) = origin.strip_prefix("http://") {
        ("http", 80, rest)
    } else if let Some(rest) = origin.strip_prefix("https://") {
        ("https", 443, rest)
    } else {
        return Err(invalid("scheme must be http:// or https://"));
    };
    if authority.is_empty() {
        return Err(invalid("host is missing"));
    }
    if authority.contains(['/', '?', '#']) {
        return Err(invalid("an origin has no path, query or trailing slash"));
    }
    if authority.contains(['@', '<', '>', '^', '|'])
        || authority
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(invalid("host contains characters an origin cannot have"));
    }
    if !authority.starts_with('[') && authority.contains(['[', ']']) {
        return Err(invalid(
            "square brackets are only allowed around an IPv6 address",
        ));
    }
    if !authority.starts_with('[') && authority.contains(['%', '\\']) {
        return Err(invalid(
            "host cannot contain '%' or '\\'; browsers rewrite them, so write the host as the browser shows it",
        ));
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let (address, after) = bracketed
                .split_once(']')
                .ok_or_else(|| invalid("unclosed IPv6 bracket"))?;
            let address: Ipv6Addr = address
                .parse()
                .map_err(|_| invalid("brackets must hold an IPv6 address"))?;
            // Browsers print these in hex and Rust in dotted form, so matching them would be fragile.
            if address.to_ipv4_mapped().is_some() {
                return Err(invalid("IPv4-mapped IPv6 addresses are not supported"));
            }
            let port = match after.strip_prefix(':') {
                Some(port) => Some(port),
                None if after.is_empty() => None,
                None => return Err(invalid("unexpected text after the IPv6 address")),
            };
            (format!("[{address}]"), port)
        }
        None => match authority.split_once(':') {
            Some((host, port)) => (host.to_owned(), Some(port)),
            None => (authority.to_owned(), None),
        },
    };
    if host.is_empty() {
        return Err(invalid("host is missing"));
    }
    if !is_canonical_unless_ipv4(&host) {
        return Err(invalid(
            "an IPv4 address must be four decimal numbers from 0 to 255 without leading zeros",
        ));
    }
    let port = match port {
        Some("") => {
            return Err(invalid(
                "empty port is not allowed; remove the trailing colon",
            ))
        }
        Some(port) => {
            Some(parse_port(port).ok_or_else(|| invalid("port must be a number from 0 to 65535"))?)
        }
        None => None,
    };
    // Browsers leave the scheme's default port out of the Origin header.
    let origin = match port {
        Some(port) if port != default_port => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    };
    HeaderValue::from_str(&origin).map_err(|_| invalid("not a valid header value"))?;
    Ok(origin)
}
