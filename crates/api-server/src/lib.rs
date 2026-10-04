//! FlowSentinel API server.
//!
//! The router, handlers and configuration live in the library so tests can
//! drive them in-process without binding a real port. [`app`] serves only
//! `GET /health`; [`app_with_state`] adds the `/api/v1` endpoints backed by
//! PostgreSQL and, when configured, the built dashboard.

pub mod accounts;
pub mod audit;
pub mod auth;
pub mod bootstrap;
pub mod dashboard;
pub mod error;
pub mod extract;
pub mod healthcheck;
pub mod host;
pub mod live;
pub mod openapi;
pub mod ratelimit;
pub mod routes;
pub mod state;
pub mod upload;

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{get, patch, post, put};
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
/// Optional TOML file with detection thresholds.
pub const DETECTION_CONFIG_ENV_VAR: &str = "FLOWSENTINEL_DETECTION_CONFIG";
/// Optional directory with the built dashboard (`frontend/dist`).
pub const DASHBOARD_DIR_ENV_VAR: &str = "FLOWSENTINEL_DASHBOARD_DIR";
/// Minutes without a request after which a session ends.
pub const SESSION_IDLE_ENV_VAR: &str = "FLOWSENTINEL_SESSION_IDLE_MINUTES";
/// Hours after sign-in after which a session ends.
pub const SESSION_MAX_ENV_VAR: &str = "FLOWSENTINEL_SESSION_MAX_HOURS";
/// `true` to mark the session cookie `Secure` (needs HTTPS in front).
pub const SECURE_COOKIES_ENV_VAR: &str = "FLOWSENTINEL_SECURE_COOKIES";
/// Days audit events are kept.
pub const AUDIT_RETENTION_ENV_VAR: &str = "FLOWSENTINEL_AUDIT_RETENTION_DAYS";
/// Name of the first admin account created from the password file.
pub const ADMIN_USERNAME_ENV_VAR: &str = "FLOWSENTINEL_ADMIN_USERNAME";
/// File holding the first admin's password; used only while no account
/// exists.
pub const ADMIN_PASSWORD_FILE_ENV_VAR: &str = "FLOWSENTINEL_ADMIN_PASSWORD_FILE";
/// `true` to allow live capture (off by default).
pub const LIVE_CAPTURE_ENV_VAR: &str = "FLOWSENTINEL_LIVE_CAPTURE";
/// Comma-separated interfaces live capture may use (default: any).
pub const LIVE_INTERFACES_ENV_VAR: &str = "FLOWSENTINEL_LIVE_INTERFACES";
/// Longest live capture, in seconds.
pub const LIVE_MAX_SECONDS_ENV_VAR: &str = "FLOWSENTINEL_LIVE_MAX_SECONDS";

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
pub const DEFAULT_SESSION_IDLE_MINUTES: u64 = 30;
pub const DEFAULT_SESSION_MAX_HOURS: u64 = 12;
pub const DEFAULT_AUDIT_RETENTION_DAYS: u64 = 365;
pub const DEFAULT_ADMIN_USERNAME: &str = "admin";
pub const DEFAULT_LIVE_MAX_SECONDS: u64 = 600;

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
    dashboard::with_security_headers(
        Router::new()
            .route("/health", get(health))
            .fallback(error::not_found)
            .method_not_allowed_fallback(error::method_not_allowed),
    )
}

/// Builds the full router: `/health`, `/api/v1/...` with the OpenAPI
/// description, and the dashboard at `/` when `dashboard_dir` is set.
/// Unknown `/api/v1` paths always get a JSON error, never the dashboard.
/// Requests for unexpected `Host` names are refused.
///
/// Every `/api/v1` route except `POST /auth/login` needs a signed-in
/// session; handlers that change data also check the account's role.
pub fn app_with_state(state: AppState) -> Router {
    let policy = Arc::new(state.config.host_policy.clone());
    let dashboard_dir = state.config.dashboard_dir.clone();
    let public = Router::new().route("/auth/login", post(accounts::login));
    let protected = Router::new()
        .route("/auth/session", get(accounts::session))
        .route("/auth/logout", post(accounts::logout))
        .route("/auth/password", put(accounts::change_password))
        .route(
            "/users",
            get(accounts::list_users).post(accounts::create_user),
        )
        .route(
            "/users/{id}",
            patch(accounts::update_user).delete(accounts::delete_user),
        )
        .route("/audit", get(accounts::list_audit))
        .route("/live/interfaces", get(live::interfaces))
        .route("/live/captures", post(live::start))
        .route("/live/captures/current", get(live::status))
        .route("/live/captures/current/stop", post(live::stop))
        .route("/overview", get(routes::overview))
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
        .route("/captures/{id}/alerts", get(routes::list_alerts))
        .route(
            "/captures/{id}/alerts/{alert_id}",
            get(routes::get_alert).patch(routes::update_alert),
        )
        .route("/rules", get(routes::list_rules))
        .route("/filters/validate", get(routes::validate_filter))
        .route("/filters/fields", get(routes::filter_fields))
        .route("/openapi.json", get(openapi_json))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ));
    let api = public
        .merge(protected)
        .fallback(error::not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
        // Uploads stream their raw body under their own limit; this caps
        // everything read through the JSON extractor.
        .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES))
        .layer(middleware::from_fn(auth::same_origin))
        .with_state(state);
    let router = Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api);
    let router = match dashboard_dir {
        Some(dir) => router.fallback_service(dashboard::router(&dir)),
        None => router.fallback(error::not_found),
    };
    dashboard::with_security_headers(
        router
            .method_not_allowed_fallback(error::method_not_allowed)
            .layer(middleware::from_fn_with_state(policy, host::guard)),
    )
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
    /// Detection thresholds file (default: built-in thresholds).
    pub detection_config: Option<PathBuf>,
    /// Built dashboard to serve at `/` (default: none).
    pub dashboard_dir: Option<PathBuf>,
    pub auth: auth::AuthConfig,
    /// Name for the first admin account.
    pub admin_username: String,
    /// Password file for the first admin account.
    pub admin_password_file: Option<PathBuf>,
    pub live_capture: bool,
    pub live_interfaces: Option<Vec<String>>,
    pub live_max_seconds: u64,
}

impl Config {
    /// The live-capture settings: the largest limits are the import limits
    /// (packets, upload size) and `FLOWSENTINEL_LIVE_MAX_SECONDS`.
    pub fn live(&self) -> live::LiveConfig {
        live::LiveConfig {
            enabled: self.live_capture,
            interfaces: self.live_interfaces.clone(),
            max: live_capture::LiveLimits {
                max_packets: self.max_packets,
                max_bytes: self.max_upload_bytes,
                max_duration: std::time::Duration::from_secs(self.live_max_seconds),
                snaplen: *live_capture::limits::SNAPLEN_RANGE.end(),
            },
        }
    }
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
            .field("detection_config", &self.detection_config)
            .field("dashboard_dir", &self.dashboard_dir)
            .field("auth", &self.auth)
            .field("admin_username", &self.admin_username)
            .field("admin_password_file", &self.admin_password_file)
            .field("live_capture", &self.live_capture)
            .field("live_interfaces", &self.live_interfaces)
            .field("live_max_seconds", &self.live_max_seconds)
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
    #[error(
        "invalid FLOWSENTINEL_LIVE_INTERFACES value {value:?}: expected comma-separated interface names"
    )]
    InvalidInterfaces { value: String },
    #[error("invalid {variable} value {value:?}: expected true or false")]
    InvalidBool {
        variable: &'static str,
        value: String,
    },
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
            detection_config: None,
            dashboard_dir: None,
            auth: auth::AuthConfig::default(),
            admin_username: DEFAULT_ADMIN_USERNAME.to_owned(),
            admin_password_file: None,
            live_capture: false,
            live_interfaces: None,
            live_max_seconds: DEFAULT_LIVE_MAX_SECONDS,
        }
    }
}

fn boolean(
    lookup: &impl Fn(&str) -> Option<String>,
    variable: &'static str,
) -> Result<bool, ConfigError> {
    match lookup(variable) {
        Some(raw) if !raw.trim().is_empty() => match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(ConfigError::InvalidBool {
                variable,
                value: raw,
            }),
        },
        _ => Ok(false),
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
        let path = |variable| {
            lookup(variable)
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty())
                .map(PathBuf::from)
        };
        let upload_dir = path(UPLOAD_DIR_ENV_VAR);
        let detection_config = path(DETECTION_CONFIG_ENV_VAR);
        let dashboard_dir = path(DASHBOARD_DIR_ENV_VAR);
        let idle_minutes = number(
            &lookup,
            SESSION_IDLE_ENV_VAR,
            DEFAULT_SESSION_IDLE_MINUTES,
            1,
            1_440,
        )?;
        let max_hours = number(
            &lookup,
            SESSION_MAX_ENV_VAR,
            DEFAULT_SESSION_MAX_HOURS,
            1,
            720,
        )?;
        let audit_days = number(
            &lookup,
            AUDIT_RETENTION_ENV_VAR,
            DEFAULT_AUDIT_RETENTION_DAYS,
            1,
            3_650,
        )?;
        let secure_cookies = boolean(&lookup, SECURE_COOKIES_ENV_VAR)?;
        let live_capture = boolean(&lookup, LIVE_CAPTURE_ENV_VAR)?;
        let live_max_seconds = number(
            &lookup,
            LIVE_MAX_SECONDS_ENV_VAR,
            DEFAULT_LIVE_MAX_SECONDS,
            1,
            3_600,
        )?;
        let live_interfaces = match lookup(LIVE_INTERFACES_ENV_VAR) {
            Some(raw) if !raw.trim().is_empty() => {
                let names: Vec<String> = raw
                    .split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
                    .collect();
                let valid = !names.is_empty()
                    && names
                        .iter()
                        .all(|n| n.len() <= 256 && !n.chars().any(char::is_control));
                if !valid {
                    return Err(ConfigError::InvalidInterfaces { value: raw });
                }
                Some(names)
            }
            _ => None,
        };
        let admin_username = lookup(ADMIN_USERNAME_ENV_VAR)
            .map(|raw| raw.trim().to_owned())
            .filter(|raw| !raw.is_empty())
            .unwrap_or_else(|| DEFAULT_ADMIN_USERNAME.to_owned());
        let admin_password_file = path(ADMIN_PASSWORD_FILE_ENV_VAR);
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
            detection_config,
            dashboard_dir,
            auth: auth::AuthConfig {
                session_idle: std::time::Duration::from_secs(idle_minutes * 60),
                session_lifetime: std::time::Duration::from_secs(max_hours * 3600),
                secure_cookies,
                audit_retention_days: u32::try_from(audit_days)
                    .unwrap_or(DEFAULT_AUDIT_RETENTION_DAYS as u32),
            },
            admin_username,
            admin_password_file,
            live_capture,
            live_interfaces,
            live_max_seconds,
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
            (SESSION_IDLE_ENV_VAR, "0"),
            (SESSION_IDLE_ENV_VAR, "1441"),
            (SESSION_MAX_ENV_VAR, "721"),
            (AUDIT_RETENTION_ENV_VAR, "0"),
            (SECURE_COOKIES_ENV_VAR, "maybe"),
            (LIVE_CAPTURE_ENV_VAR, "on"),
            (LIVE_MAX_SECONDS_ENV_VAR, "3601"),
            (LIVE_INTERFACES_ENV_VAR, " , "),
        ] {
            let err = Config::from_lookup(lookup_with(&[(variable, bad)])).unwrap_err();
            assert!(err.to_string().contains(variable), "{err}");
        }
        let ok = Config::from_lookup(lookup_with(&[
            (MAX_UPLOAD_MB_ENV_VAR, "64"),
            (MAX_IMPORTS_ENV_VAR, "4"),
            (DB_CONNECTIONS_ENV_VAR, "20"),
            (UPLOAD_DIR_ENV_VAR, "/var/tmp"),
            (
                DETECTION_CONFIG_ENV_VAR,
                " /etc/flowsentinel/detection.toml ",
            ),
            (DASHBOARD_DIR_ENV_VAR, "frontend/dist"),
        ]))
        .unwrap();
        assert_eq!(ok.max_upload_bytes, 64 * 1024 * 1024);
        assert_eq!(ok.max_concurrent_imports, 4);
        assert_eq!(ok.db_max_connections, 20);
        assert_eq!(ok.upload_dir, Some(PathBuf::from("/var/tmp")));
        assert_eq!(
            ok.detection_config,
            Some(PathBuf::from("/etc/flowsentinel/detection.toml"))
        );
        assert_eq!(ok.dashboard_dir, Some(PathBuf::from("frontend/dist")));
    }

    #[test]
    fn session_settings_are_read() {
        let config = Config::from_lookup(lookup_with(&[
            (SESSION_IDLE_ENV_VAR, "15"),
            (SESSION_MAX_ENV_VAR, "8"),
            (SECURE_COOKIES_ENV_VAR, " TRUE "),
            (AUDIT_RETENTION_ENV_VAR, "90"),
            (ADMIN_USERNAME_ENV_VAR, "root-admin"),
            (ADMIN_PASSWORD_FILE_ENV_VAR, "/run/secrets/admin"),
        ]))
        .unwrap();
        assert_eq!(config.auth.session_idle.as_secs(), 900);
        assert_eq!(config.auth.session_lifetime.as_secs(), 8 * 3600);
        assert!(config.auth.secure_cookies);
        assert_eq!(config.auth.audit_retention_days, 90);
        assert_eq!(config.admin_username, "root-admin");
        assert_eq!(
            config.admin_password_file,
            Some(PathBuf::from("/run/secrets/admin"))
        );
        let defaults = Config::default();
        assert!(!defaults.live_capture);
        assert_eq!(defaults.live().max.max_duration.as_secs(), 600);
        let live = Config::from_lookup(lookup_with(&[
            (LIVE_CAPTURE_ENV_VAR, "true"),
            (LIVE_INTERFACES_ENV_VAR, "eth0, lo"),
            (LIVE_MAX_SECONDS_ENV_VAR, "120"),
        ]))
        .unwrap();
        let settings = live.live();
        assert!(settings.enabled);
        assert_eq!(
            settings.interfaces,
            Some(vec!["eth0".to_owned(), "lo".to_owned()])
        );
        assert_eq!(settings.max.max_duration.as_secs(), 120);
        assert_eq!(settings.max.max_packets, DEFAULT_MAX_PACKETS);
        assert!(!defaults.auth.secure_cookies);
        assert_eq!(defaults.auth.session_idle.as_secs(), 1800);
        assert_eq!(defaults.admin_username, "admin");
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
