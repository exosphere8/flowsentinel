//! FlowSentinel API server.
//!
//! The router, handlers and configuration live in the library so tests can
//! drive them in-process without binding a real port. [`app`] serves only
//! `GET /health`; [`app_with_state`] adds the `/api/v1` endpoints backed by
//! PostgreSQL.

pub mod error;
pub mod extract;
pub mod host;
pub mod openapi;
pub mod routes;
pub mod state;
pub mod upload;

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use utoipa::OpenApi;

pub use state::{ApiConfig, AppState};

/// Service name reported by the health endpoint.
pub const SERVICE_NAME: &str = "flowsentinel-api";

/// Environment variable that overrides the listen address.
pub const ADDR_ENV_VAR: &str = "FLOWSENTINEL_API_ADDR";
/// PostgreSQL connection URL (required to serve the API).
pub const DATABASE_URL_ENV_VAR: &str = "FLOWSENTINEL_DATABASE_URL";
pub const MAX_UPLOAD_MB_ENV_VAR: &str = "FLOWSENTINEL_MAX_UPLOAD_MB";
pub const UPLOAD_DIR_ENV_VAR: &str = "FLOWSENTINEL_UPLOAD_DIR";
pub const MAX_IMPORTS_ENV_VAR: &str = "FLOWSENTINEL_MAX_CONCURRENT_IMPORTS";
pub const DB_CONNECTIONS_ENV_VAR: &str = "FLOWSENTINEL_DB_MAX_CONNECTIONS";
/// Comma-separated `Host` names the server answers, or `*` for any.
pub const ALLOWED_HOSTS_ENV_VAR: &str = "FLOWSENTINEL_ALLOWED_HOSTS";
/// Packets analyzed per import.
pub const MAX_PACKETS_ENV_VAR: &str = "FLOWSENTINEL_MAX_PACKETS";
/// Processing time per import analysis pass, in seconds.
pub const MAX_ANALYSIS_SECONDS_ENV_VAR: &str = "FLOWSENTINEL_MAX_ANALYSIS_SECONDS";
/// Time limit for one filtered list query, in seconds.
pub const QUERY_TIMEOUT_ENV_VAR: &str = "FLOWSENTINEL_QUERY_TIMEOUT_SECONDS";

/// Default listen address: loopback only, so a fresh install is not reachable
/// from the network.
pub const DEFAULT_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8080);
pub const DEFAULT_MAX_UPLOAD_MB: u64 = 512;
pub const DEFAULT_MAX_IMPORTS: usize = 2;
pub const DEFAULT_DB_CONNECTIONS: u32 = 10;
pub const DEFAULT_MAX_PACKETS: u64 = 1_000_000;
pub const DEFAULT_MAX_ANALYSIS_SECONDS: u64 = 600;
pub const DEFAULT_QUERY_TIMEOUT_SECONDS: u64 = 10;

/// Largest JSON request body (only the retention settings take one).
const MAX_JSON_BODY_BYTES: usize = 16 * 1024;

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

/// Builds the health-only router (no `Host` check: it reveals nothing).
pub fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .fallback(error::not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
}

/// Builds the full router: `/health`, `/api/v1/...` and the OpenAPI
/// description. Requests for unexpected `Host` names are refused.
pub fn app_with_state(state: AppState) -> Router {
    let policy = Arc::new(state.config.host_policy.clone());
    let api = Router::new()
        .route(
            "/captures",
            get(routes::list_captures).post(routes::import_capture),
        )
        .route(
            "/captures/{id}",
            get(routes::get_capture).delete(routes::delete_capture),
        )
        .route("/captures/{id}/packets", get(routes::list_packets))
        .route("/captures/{id}/packets/{index}", get(routes::get_packet))
        .route("/captures/{id}/flows", get(routes::list_flows))
        .route("/captures/{id}/flows/{flow_id}", get(routes::get_flow))
        .route("/captures/{id}/dns", get(routes::list_dns))
        .route("/captures/{id}/http", get(routes::list_http))
        .route("/captures/{id}/tls", get(routes::list_tls))
        .route(
            "/settings/retention",
            get(routes::get_retention).put(routes::put_retention),
        )
        .route("/filters/validate", get(routes::validate_filter))
        .route("/filters/fields", get(routes::filter_fields))
        .route("/openapi.json", get(openapi_json))
        // Uploads stream their raw body under their own limit; this caps
        // everything read through the JSON extractor.
        .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES))
        .with_state(state);
    Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api)
        .fallback(error::not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
        .layer(middleware::from_fn_with_state(policy, host::guard))
}

async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(openapi::ApiDoc::openapi())
}

/// Runtime configuration for the API server.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub addr: SocketAddr,
    /// Required to serve `/api/v1`. Never logged or printed.
    pub database_url: Option<String>,
    pub max_upload_bytes: u64,
    /// Directory for temporary upload files (default: the system temporary
    /// directory).
    pub upload_dir: Option<PathBuf>,
    pub max_concurrent_imports: usize,
    pub db_max_connections: u32,
    /// `None`: loopback names (and the listen address if specific).
    pub allowed_hosts: Option<host::HostPolicy>,
    pub max_packets: u64,
    pub max_analysis_seconds: u64,
    pub query_timeout_seconds: u64,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("addr", &self.addr)
            .field(
                "database_url",
                &self.database_url.as_ref().map(|_| "[redacted]"),
            )
            .field("max_upload_bytes", &self.max_upload_bytes)
            .field("upload_dir", &self.upload_dir)
            .field("max_concurrent_imports", &self.max_concurrent_imports)
            .field("db_max_connections", &self.db_max_connections)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("max_packets", &self.max_packets)
            .field("max_analysis_seconds", &self.max_analysis_seconds)
            .field("query_timeout_seconds", &self.query_timeout_seconds)
            .finish()
    }
}

/// Errors produced while loading [`Config`]. Messages never include the
/// database URL, which may contain a password.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "invalid FLOWSENTINEL_API_ADDR value {value:?}: expected IP:PORT, for example 127.0.0.1:8080"
    )]
    InvalidAddr { value: String },
    #[error("invalid {variable} value {value:?}: expected a whole number from {min} to {max}")]
    InvalidNumber {
        variable: &'static str,
        value: String,
        min: u64,
        max: u64,
    },
    #[error(
        "invalid FLOWSENTINEL_DATABASE_URL: expected postgres://USER:PASSWORD@HOST:PORT/DATABASE"
    )]
    InvalidDatabaseUrl,
    #[error(
        "invalid FLOWSENTINEL_ALLOWED_HOSTS value {value:?}: expected comma-separated host names or addresses, or *"
    )]
    InvalidAllowedHosts { value: String },
}

impl Default for Config {
    fn default() -> Self {
        Self {
            addr: DEFAULT_ADDR,
            database_url: None,
            max_upload_bytes: DEFAULT_MAX_UPLOAD_MB * 1024 * 1024,
            upload_dir: None,
            max_concurrent_imports: DEFAULT_MAX_IMPORTS,
            db_max_connections: DEFAULT_DB_CONNECTIONS,
            allowed_hosts: None,
            max_packets: DEFAULT_MAX_PACKETS,
            max_analysis_seconds: DEFAULT_MAX_ANALYSIS_SECONDS,
            query_timeout_seconds: DEFAULT_QUERY_TIMEOUT_SECONDS,
        }
    }
}

fn number(
    lookup: &impl Fn(&str) -> Option<String>,
    variable: &'static str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ConfigError> {
    match lookup(variable) {
        Some(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|v| (min..=max).contains(v))
            .ok_or(ConfigError::InvalidNumber {
                variable,
                value: raw,
                min,
                max,
            }),
        _ => Ok(default),
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
        let database_url = match lookup(DATABASE_URL_ENV_VAR) {
            Some(raw) if !raw.trim().is_empty() => {
                let url = raw.trim().to_owned();
                let scheme_ok = url.starts_with("postgres://") || url.starts_with("postgresql://");
                if !scheme_ok {
                    return Err(ConfigError::InvalidDatabaseUrl);
                }
                Some(url)
            }
            _ => None,
        };
        let max_upload_mb = number(
            &lookup,
            MAX_UPLOAD_MB_ENV_VAR,
            DEFAULT_MAX_UPLOAD_MB,
            1,
            65_536,
        )?;
        let max_imports = number(
            &lookup,
            MAX_IMPORTS_ENV_VAR,
            DEFAULT_MAX_IMPORTS as u64,
            1,
            16,
        )?;
        let connections = number(
            &lookup,
            DB_CONNECTIONS_ENV_VAR,
            u64::from(DEFAULT_DB_CONNECTIONS),
            1,
            100,
        )?;
        let max_packets = number(
            &lookup,
            MAX_PACKETS_ENV_VAR,
            DEFAULT_MAX_PACKETS,
            1,
            1_000_000,
        )?;
        let max_analysis_seconds = number(
            &lookup,
            MAX_ANALYSIS_SECONDS_ENV_VAR,
            DEFAULT_MAX_ANALYSIS_SECONDS,
            1,
            3_600,
        )?;
        let allowed_hosts = match lookup(ALLOWED_HOSTS_ENV_VAR) {
            Some(raw) if !raw.trim().is_empty() => Some(
                host::HostPolicy::parse(&raw)
                    .ok_or(ConfigError::InvalidAllowedHosts { value: raw })?,
            ),
            _ => None,
        };
        let query_timeout_seconds = number(
            &lookup,
            QUERY_TIMEOUT_ENV_VAR,
            DEFAULT_QUERY_TIMEOUT_SECONDS,
            1,
            300,
        )?;
        let upload_dir = lookup(UPLOAD_DIR_ENV_VAR)
            .map(|raw| raw.trim().to_owned())
            .filter(|raw| !raw.is_empty())
            .map(PathBuf::from);
        Ok(Self {
            addr,
            database_url,
            max_upload_bytes: max_upload_mb * 1024 * 1024,
            upload_dir,
            max_concurrent_imports: usize::try_from(max_imports).unwrap_or(DEFAULT_MAX_IMPORTS),
            db_max_connections: u32::try_from(connections).unwrap_or(DEFAULT_DB_CONNECTIONS),
            allowed_hosts,
            max_packets,
            max_analysis_seconds,
            query_timeout_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_with(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    #[test]
    fn defaults_to_loopback_8080() {
        let config = Config::from_lookup(lookup_with(&[])).unwrap();
        assert_eq!(config.addr.to_string(), "127.0.0.1:8080");
        assert_eq!(config, Config::default());
        assert_eq!(config.max_upload_bytes, 512 * 1024 * 1024);
        assert_eq!(config.database_url, None);
    }

    #[test]
    fn blank_value_uses_default() {
        let config = Config::from_lookup(lookup_with(&[(ADDR_ENV_VAR, "   ")])).unwrap();
        assert_eq!(config.addr, DEFAULT_ADDR);
    }

    #[test]
    fn accepts_ipv4_and_ipv6_overrides() {
        let v4 = Config::from_lookup(lookup_with(&[(ADDR_ENV_VAR, "127.0.0.1:9090")])).unwrap();
        assert_eq!(v4.addr.port(), 9090);
        let v6 = Config::from_lookup(lookup_with(&[(ADDR_ENV_VAR, " [::1]:8081 ")])).unwrap();
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
            let err = Config::from_lookup(lookup_with(&[(ADDR_ENV_VAR, bad)])).unwrap_err();
            assert_eq!(
                err,
                ConfigError::InvalidAddr {
                    value: bad.to_owned()
                }
            );
            assert!(err.to_string().contains("FLOWSENTINEL_API_ADDR"));
        }
    }

    #[test]
    fn numbers_are_range_checked() {
        for (variable, bad) in [
            (MAX_UPLOAD_MB_ENV_VAR, "0"),
            (MAX_UPLOAD_MB_ENV_VAR, "65537"),
            (MAX_IMPORTS_ENV_VAR, "17"),
            (DB_CONNECTIONS_ENV_VAR, "-1"),
            (DB_CONNECTIONS_ENV_VAR, "ten"),
            (MAX_PACKETS_ENV_VAR, "1000001"),
            (MAX_ANALYSIS_SECONDS_ENV_VAR, "0"),
            (ALLOWED_HOSTS_ENV_VAR, "bad host"),
            (QUERY_TIMEOUT_ENV_VAR, "0"),
            (QUERY_TIMEOUT_ENV_VAR, "301"),
        ] {
            let err = Config::from_lookup(lookup_with(&[(variable, bad)])).unwrap_err();
            assert!(err.to_string().contains(variable), "{err}");
        }
        let ok = Config::from_lookup(lookup_with(&[
            (MAX_UPLOAD_MB_ENV_VAR, "64"),
            (MAX_IMPORTS_ENV_VAR, "4"),
            (DB_CONNECTIONS_ENV_VAR, "20"),
            (UPLOAD_DIR_ENV_VAR, "/var/tmp"),
        ]))
        .unwrap();
        assert_eq!(ok.max_upload_bytes, 64 * 1024 * 1024);
        assert_eq!(ok.max_concurrent_imports, 4);
        assert_eq!(ok.db_max_connections, 20);
        assert_eq!(ok.upload_dir, Some(PathBuf::from("/var/tmp")));
    }

    #[test]
    fn database_url_is_validated_and_never_shown() {
        let secret = "postgres://fs:hunter2-secret@127.0.0.1:5432/fs";
        let config = Config::from_lookup(lookup_with(&[(DATABASE_URL_ENV_VAR, secret)])).unwrap();
        assert_eq!(config.database_url.as_deref(), Some(secret));
        assert!(!format!("{config:?}").contains("hunter2"));
        let err = Config::from_lookup(lookup_with(&[(
            DATABASE_URL_ENV_VAR,
            "mysql://u:hunter2@h/db",
        )]))
        .unwrap_err();
        assert_eq!(err, ConfigError::InvalidDatabaseUrl);
        assert!(!err.to_string().contains("hunter2"));
    }
}
