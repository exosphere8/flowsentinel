//! FlowSentinel API server.
//!
//! Milestone 0 exposes only `GET /health`. The router and configuration live in
//! the library so they can be exercised by tests without binding a real port.

use std::net::SocketAddr;

use axum::{Json, Router, routing::get};
use serde::Serialize;

/// Service name reported by the health endpoint.
pub const SERVICE_NAME: &str = "flowsentinel-api";

/// Environment variable that overrides the listen address.
pub const ADDR_ENV_VAR: &str = "FLOWSENTINEL_API_ADDR";

/// Default listen address: loopback only, so a fresh install is not reachable
/// from the network.
pub const DEFAULT_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8080);

/// Body returned by `GET /health`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
}

/// Liveness check. Reports only that the process is serving HTTP; it does not
/// touch any backing service.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: SERVICE_NAME,
    })
}

/// Builds the application router.
pub fn app() -> Router {
    Router::new().route("/health", get(health))
}

/// Runtime configuration for the API server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub addr: SocketAddr,
}

/// Errors produced while loading [`Config`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "invalid FLOWSENTINEL_API_ADDR value {value:?}: expected IP:PORT, for example 127.0.0.1:8080"
    )]
    InvalidAddr { value: String },
}

impl Default for Config {
    fn default() -> Self {
        Self { addr: DEFAULT_ADDR }
    }
}

impl Config {
    /// Loads configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Loads configuration from an arbitrary key lookup. Unset or blank values
    /// fall back to defaults.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let addr = match lookup(ADDR_ENV_VAR) {
            Some(raw) if !raw.trim().is_empty() => raw
                .trim()
                .parse()
                .map_err(|_| ConfigError::InvalidAddr { value: raw })?,
            _ => DEFAULT_ADDR,
        };
        Ok(Self { addr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_with(value: Option<&str>) -> impl Fn(&str) -> Option<String> {
        let value = value.map(str::to_owned);
        move |key| (key == ADDR_ENV_VAR).then(|| value.clone()).flatten()
    }

    #[test]
    fn defaults_to_loopback_8080() {
        let config = Config::from_lookup(lookup_with(None)).unwrap();
        assert_eq!(config.addr.to_string(), "127.0.0.1:8080");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn blank_value_uses_default() {
        let config = Config::from_lookup(lookup_with(Some("   "))).unwrap();
        assert_eq!(config.addr, DEFAULT_ADDR);
    }

    #[test]
    fn accepts_ipv4_and_ipv6_overrides() {
        let v4 = Config::from_lookup(lookup_with(Some("127.0.0.1:9090"))).unwrap();
        assert_eq!(v4.addr.port(), 9090);
        let v6 = Config::from_lookup(lookup_with(Some(" [::1]:8081 "))).unwrap();
        assert_eq!(v6.addr.to_string(), "[::1]:8081");
    }

    #[test]
    fn rejects_invalid_address() {
        for bad in [
            "localhost:8080",
            "127.0.0.1",
            "127.0.0.1:99999",
            "not an addr",
        ] {
            let err = Config::from_lookup(lookup_with(Some(bad))).unwrap_err();
            assert_eq!(
                err,
                ConfigError::InvalidAddr {
                    value: bad.to_owned()
                }
            );
            assert!(err.to_string().contains("FLOWSENTINEL_API_ADDR"));
        }
    }
}
