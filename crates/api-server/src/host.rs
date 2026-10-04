//! `Host` header checks. A browser page on another site can point its own
//! DNS name at 127.0.0.1 ("DNS rebinding") and then talk to the API as if it
//! were same-origin; refusing unexpected `Host` values stops that.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;

/// Which `Host` values the server answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPolicy {
    /// Any host (`FLOWSENTINEL_ALLOWED_HOSTS=*`).
    Any,
    /// These host names or addresses, lowercase, without ports.
    Allowed(Vec<String>),
}

/// Names that always reach a loopback listener.
const LOOPBACK_NAMES: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

impl HostPolicy {
    /// The default for a listener on `addr`: loopback names, plus the
    /// address itself when it is a specific one.
    pub fn default_for(addr: SocketAddr) -> Self {
        let mut names: Vec<String> = LOOPBACK_NAMES.iter().map(|n| (*n).to_owned()).collect();
        let ip = addr.ip();
        if !ip.is_unspecified() && !ip.is_loopback() {
            names.push(ip.to_string());
        }
        Self::Allowed(names)
    }

    /// Parses a comma-separated list; `*` alone allows any host.
    pub fn parse(list: &str) -> Option<Self> {
        let list = list.trim();
        if list == "*" {
            return Some(Self::Any);
        }
        let mut names = Vec::new();
        for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let valid = item.len() <= 253
                && item
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
            if !valid {
                return None;
            }
            names.push(item.to_ascii_lowercase());
        }
        (!names.is_empty()).then_some(Self::Allowed(names))
    }

    /// Whether a request with this `Host` header value is answered. A
    /// request without one (not sent by browsers) is allowed.
    pub fn allows(&self, host: Option<&str>) -> bool {
        let Self::Allowed(names) = self else {
            return true;
        };
        let Some(host) = host else {
            return true;
        };
        let Some(name) = host_name(host) else {
            return false;
        };
        names.contains(&name)
    }
}

/// The host part of a `Host` header (`name`, `name:port`, `[v6]:port`),
/// lowercase.
pub fn host_name(value: &str) -> Option<String> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let port_ok = after.is_empty() || after.strip_prefix(':').is_some_and(is_port);
        return (port_ok && inside.parse::<IpAddr>().is_ok()).then(|| inside.to_ascii_lowercase());
    }
    let (name, port) = match value.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') => (name, Some(port)),
        _ => (value, None),
    };
    if name.is_empty() || port.is_some_and(|p| !is_port(p)) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

fn is_port(text: &str) -> bool {
    !text.is_empty() && text.len() <= 5 && text.bytes().all(|b| b.is_ascii_digit())
}

/// Middleware: answers `421 Misdirected Request` for unexpected hosts.
pub async fn guard(
    State(policy): State<Arc<HostPolicy>>,
    request: Request,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .map(|v| v.to_str().unwrap_or("\u{fffd}"));
    if policy.allows(host) {
        next.run(request).await
    } else {
        ApiError::new(
            StatusCode::MISDIRECTED_REQUEST,
            "invalid_host",
            "this server does not answer requests for that host name; \
             see FLOWSENTINEL_ALLOWED_HOSTS",
        )
        .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names_are_parsed() {
        assert_eq!(host_name("LocalHost:8080").as_deref(), Some("localhost"));
        assert_eq!(host_name("127.0.0.1").as_deref(), Some("127.0.0.1"));
        assert_eq!(host_name("[::1]:8080").as_deref(), Some("::1"));
        assert_eq!(host_name("[::1]").as_deref(), Some("::1"));
        assert_eq!(host_name("::1").as_deref(), Some("::1"));
        assert_eq!(host_name("example.com:abc"), None);
        assert_eq!(host_name("[nope]:80"), None);
        assert_eq!(host_name(":80"), None);
    }

    #[test]
    fn loopback_listeners_answer_only_loopback_names() {
        let policy = HostPolicy::default_for("127.0.0.1:8080".parse().unwrap());
        for ok in [
            "localhost:8080",
            "127.0.0.1:8080",
            "[::1]:8080",
            "LOCALHOST",
        ] {
            assert!(policy.allows(Some(ok)), "{ok}");
        }
        for bad in [
            "rebind.attacker.example:8080",
            "127.0.0.1.nip.io",
            "",
            "\u{fffd}",
        ] {
            assert!(!policy.allows(Some(bad)), "{bad}");
        }
        assert!(policy.allows(None));
        let specific = HostPolicy::default_for("192.0.2.5:8080".parse().unwrap());
        assert!(specific.allows(Some("192.0.2.5:8080")));
        let any_addr = HostPolicy::default_for("0.0.0.0:8080".parse().unwrap());
        assert!(!any_addr.allows(Some("0.0.0.0:8080")));
    }

    #[test]
    fn lists_are_validated() {
        assert_eq!(HostPolicy::parse(" * "), Some(HostPolicy::Any));
        assert_eq!(
            HostPolicy::parse("Analyzer.example, 192.0.2.5"),
            Some(HostPolicy::Allowed(vec![
                "analyzer.example".into(),
                "192.0.2.5".into()
            ]))
        );
        assert_eq!(HostPolicy::parse("bad host"), None);
        assert_eq!(HostPolicy::parse(" , "), None);
        assert!(HostPolicy::Any.allows(Some("anything")));
    }
}
