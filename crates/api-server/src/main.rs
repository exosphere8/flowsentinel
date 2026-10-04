use std::process::ExitCode;
use std::time::Duration;

use api_server::host::HostPolicy;
use api_server::{
    ApiConfig, AppState, Config, DATABASE_URL_ENV_VAR, app_with_state, healthcheck, upload,
};
use capture::CaptureLimits;
use detection_engine::DetectionConfig;
use flow_engine::FlowConfig;
use storage::Storage;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

/// How often expired captures are deleted.
const PURGE_INTERVAL: Duration = Duration::from_secs(3600);
/// How long in-flight requests may run after a shutdown signal.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);
/// Time allowed for `api-server healthcheck`.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        None => {}
        Some("healthcheck") => return run_healthcheck().await,
        Some(other) => {
            eprintln!("error: unknown argument {other:?}; usage: api-server [healthcheck]");
            return ExitCode::from(2);
        }
    }
    init_tracing();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(error = %err, "invalid configuration");
            return ExitCode::FAILURE;
        }
    };
    let Some(database_url) = config.database_url.as_deref() else {
        tracing::error!(
            variable = DATABASE_URL_ENV_VAR,
            "invalid configuration: set FLOWSENTINEL_DATABASE_URL to the PostgreSQL URL, \
             for example postgres://flowsentinel:PASSWORD@127.0.0.1:5432/flowsentinel"
        );
        return ExitCode::FAILURE;
    };
    let upload_dir = config.upload_dir.clone().unwrap_or_else(std::env::temp_dir);
    if !upload_dir.is_dir() {
        tracing::error!(
            path = %upload_dir.display(),
            "invalid configuration: FLOWSENTINEL_UPLOAD_DIR is not a directory"
        );
        return ExitCode::FAILURE;
    }
    // Uploads left behind by a server that was killed mid-import hold raw
    // capture bytes; remove them before accepting new ones.
    match upload::remove_stale(&upload_dir) {
        Ok(0) => {}
        Ok(removed) => tracing::warn!(
            files = removed,
            "removed upload files left by an earlier run"
        ),
        Err(err) => {
            tracing::error!(path = %upload_dir.display(), error = %err, "cannot clean the upload directory");
            return ExitCode::FAILURE;
        }
    }

    let host_policy = config
        .allowed_hosts
        .clone()
        .unwrap_or_else(|| HostPolicy::default_for(config.addr));
    if config.addr.ip().is_unspecified() && config.allowed_hosts.is_none() {
        tracing::warn!(
            "listening on all addresses but answering only loopback host names; \
             set FLOWSENTINEL_ALLOWED_HOSTS to the names clients use"
        );
    }

    let detection = match &config.detection_config {
        None => DetectionConfig::default(),
        Some(path) => match DetectionConfig::load(path) {
            Ok(detection) => {
                tracing::info!(path = %path.display(), "detection configuration loaded");
                detection
            }
            Err(err) => {
                tracing::error!(
                    path = %path.display(),
                    error = %err,
                    "invalid configuration: FLOWSENTINEL_DETECTION_CONFIG"
                );
                return ExitCode::FAILURE;
            }
        },
    };

    if let Some(dir) = &config.dashboard_dir {
        if !dir.join("index.html").is_file() {
            tracing::error!(
                path = %dir.display(),
                "invalid configuration: FLOWSENTINEL_DASHBOARD_DIR has no index.html; \
                 build the dashboard with `npm run build` in frontend/"
            );
            return ExitCode::FAILURE;
        }
        tracing::info!(path = %dir.display(), "serving the dashboard at /");
    }

    if !config.addr.ip().is_loopback() {
        tracing::warn!(
            addr = %config.addr,
            "listening on a non-loopback address; the API has no authentication yet"
        );
    }

    let storage = match Storage::connect(database_url, config.db_max_connections).await {
        Ok(storage) => {
            storage.with_query_timeout(Duration::from_secs(config.query_timeout_seconds))
        }
        Err(err) => {
            tracing::error!(error = %err, "cannot connect to PostgreSQL");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = storage.migrate().await {
        tracing::error!(error = %err, "database migration failed");
        return ExitCode::FAILURE;
    }
    tracing::info!("database schema is up to date");
    tokio::spawn(purge_expired(storage.clone()));

    // An upload can never exceed the analysis size limit.
    let capture_limits = CaptureLimits {
        max_file_size_bytes: config.max_upload_bytes,
        max_packets: config.max_packets,
        max_duration: Duration::from_secs(config.max_analysis_seconds),
    };
    let state = AppState::new(
        storage,
        ApiConfig {
            max_upload_bytes: config.max_upload_bytes,
            upload_dir,
            capture_limits,
            flow_config: FlowConfig::default(),
            host_policy,
            detection,
            dashboard_dir: config.dashboard_dir.clone(),
        },
        config.max_concurrent_imports,
    );

    let listener = match TcpListener::bind(config.addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(addr = %config.addr, error = %err, "failed to bind listener");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(addr = %config.addr, "flowsentinel-api listening");

    // After a shutdown signal, in-flight requests get SHUTDOWN_GRACE to
    // finish; then they are dropped, which deletes their upload files.
    let (stopping, stopped) = tokio::sync::oneshot::channel::<()>();
    let serve = axum::serve(listener, app_with_state(state)).with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = stopping.send(());
    });
    let deadline = async move {
        if stopped.await.is_ok() {
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        result = serve => {
            if let Err(err) = result {
                tracing::error!(error = %err, "server error");
                return ExitCode::FAILURE;
            }
        }
        () = deadline => {
            tracing::warn!(
                seconds = SHUTDOWN_GRACE.as_secs(),
                "requests still running after the shutdown grace period were cancelled"
            );
        }
    }

    tracing::info!("flowsentinel-api stopped");
    ExitCode::SUCCESS
}

/// Probes `GET /health` on the configured address; exit code 0 when the
/// server answers `200`. Used by container health checks.
async fn run_healthcheck() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    match healthcheck::probe(config.addr, HEALTHCHECK_TIMEOUT).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("unhealthy: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Deletes expired captures at startup and then every hour.
async fn purge_expired(storage: Storage) {
    let mut interval = tokio::time::interval(PURGE_INTERVAL);
    loop {
        interval.tick().await;
        match storage.purge_expired().await {
            Ok(0) => {}
            Ok(deleted) => tracing::info!(sessions = deleted, "expired captures deleted"),
            Err(err) => tracing::warn!(error = %err, "retention purge failed; will retry"),
        }
    }
}

/// Structured JSON logs to stdout. Verbosity comes from `RUST_LOG`
/// (default `info`).
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .init();
}

/// Resolves on Ctrl+C, or SIGTERM on Unix, so in-flight requests can finish.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "failed to listen for Ctrl+C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
