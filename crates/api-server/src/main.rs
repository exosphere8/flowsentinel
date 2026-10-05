use std::process::ExitCode;
use std::time::Duration;

use std::net::SocketAddr;

use api_server::auth::AuthConfig;
use api_server::host::HostPolicy;
use api_server::{
    ApiConfig, AppState, Config, DATABASE_URL_ENV_VAR, app_with_state, bootstrap, healthcheck,
    upload,
};
use capture::CaptureLimits;
use detection_engine::DetectionConfig;
use flow_engine::FlowConfig;
use storage::Storage;
use tokio::net::TcpListener;

/// How often expired captures are deleted.
const PURGE_INTERVAL: Duration = Duration::from_secs(3600);
/// How long in-flight requests may run after a shutdown signal.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);
const USAGE: &str = "usage: flowsentinel-api [healthcheck | create-user --username NAME --role admin|analyst|viewer]";
/// Time allowed for `api-server healthcheck`.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => {}
        Some("healthcheck") if args.len() == 1 => return run_healthcheck().await,
        Some("create-user") => return run_create_user(args.get(1..).unwrap_or_default()).await,
        Some(_) => {
            eprintln!("error: unknown arguments; {USAGE}");
            return ExitCode::from(2);
        }
    }
    let telemetry = match api_server::telemetry::init(|key| std::env::var(key).ok()) {
        Ok(telemetry) => telemetry,
        Err(err) => {
            eprintln!("error: cannot set up tracing: {err}");
            return ExitCode::FAILURE;
        }
    };
    if telemetry.exporting() {
        tracing::info!("exporting traces with OpenTelemetry");
    }
    let code = run().await;
    telemetry.shutdown();
    code
}

async fn run() -> ExitCode {
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
    if let Err(err) = upload::check_directory(&upload_dir) {
        tracing::error!(
            path = %upload_dir.display(),
            error = %err,
            "invalid configuration: FLOWSENTINEL_UPLOAD_DIR"
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

    if !config.addr.ip().is_loopback() && !config.auth.secure_cookies {
        tracing::warn!(
            addr = %config.addr,
            "listening on a non-loopback address with FLOWSENTINEL_SECURE_COOKIES=false; \
             serve the API through HTTPS and set FLOWSENTINEL_SECURE_COOKIES=true"
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
    if let Err(err) = ensure_accounts(&storage, &config).await {
        tracing::error!(error = %err, "invalid configuration: FLOWSENTINEL_ADMIN_PASSWORD_FILE");
        return ExitCode::FAILURE;
    }
    tokio::spawn(purge_expired(storage.clone(), config.auth));

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
            auth: config.auth,
            live: config.live(),
        },
        config.max_concurrent_imports,
    );

    if let Some(addr) = config.metrics_addr {
        if let Err(code) = serve_metrics(addr, &state, config.max_concurrent_imports).await {
            return code;
        }
    }

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
    // Client addresses are recorded in the audit log and limit sign-in
    // attempts.
    let app = app_with_state(state).into_make_service_with_connect_info::<SocketAddr>();
    let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
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

/// Serves `GET /metrics` on its own listener, so it can be reachable by a
/// metrics collector without exposing the API, or the reverse.
async fn serve_metrics(
    addr: SocketAddr,
    state: &AppState,
    max_imports: usize,
) -> Result<(), ExitCode> {
    let listener = TcpListener::bind(addr).await.map_err(|err| {
        tracing::error!(addr = %addr, error = %err, "failed to bind the metrics listener");
        ExitCode::FAILURE
    })?;
    if !addr.ip().is_loopback() {
        tracing::warn!(
            addr = %addr,
            "metrics are served without authentication on a non-loopback address; \
             restrict who can reach it"
        );
    }
    let pool = state.storage.pool().clone();
    let imports = std::sync::Arc::clone(&state.import_slots);
    let gauges: api_server::observability::GaugeSource = std::sync::Arc::new(move || {
        let in_progress = max_imports.saturating_sub(imports.available_permits());
        vec![
            (
                "flowsentinel_db_connections",
                "Open database connections.",
                f64::from(pool.size()),
            ),
            (
                "flowsentinel_db_idle_connections",
                "Idle database connections.",
                pool.num_idle() as f64,
            ),
            (
                "flowsentinel_imports_in_progress",
                "Imports and live captures holding an import slot.",
                in_progress as f64,
            ),
        ]
    });
    let router =
        api_server::observability::metrics_router(std::sync::Arc::clone(&state.metrics), gauges);
    tracing::info!(addr = %addr, "serving metrics at /metrics");
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router).await {
            tracing::error!(error = %err, "metrics listener failed");
        }
    });
    Ok(())
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

/// Deletes expired captures, ended sign-in sessions and old audit events
/// at startup and then every hour.
async fn purge_expired(storage: Storage, auth: AuthConfig) {
    let mut interval = tokio::time::interval(PURGE_INTERVAL);
    loop {
        interval.tick().await;
        match storage.purge_expired().await {
            Ok(0) => {}
            Ok(deleted) => tracing::info!(sessions = deleted, "expired captures deleted"),
            Err(err) => tracing::warn!(error = %err, "retention purge failed; will retry"),
        }
        if let Err(err) = storage.purge_auth_sessions(auth.session_idle).await {
            tracing::warn!(error = %err, "sign-in session purge failed; will retry");
        }
        match storage.purge_audit(auth.audit_retention_days).await {
            Ok(0) => {}
            Ok(deleted) => tracing::info!(events = deleted, "old audit events deleted"),
            Err(err) => tracing::warn!(error = %err, "audit purge failed; will retry"),
        }
    }
}

/// Creates the first admin from `FLOWSENTINEL_ADMIN_PASSWORD_FILE` while no
/// account exists, and warns when there is still no account.
async fn ensure_accounts(storage: &Storage, config: &Config) -> Result<(), String> {
    let existing = storage.count_users().await.map_err(|e| e.to_string())?;
    if let (Some(_), true) = (&config.admin_password_file, existing > 0) {
        tracing::info!(
            "accounts exist; FLOWSENTINEL_ADMIN_PASSWORD_FILE is ignored and can be removed"
        );
    } else if let Some(path) = &config.admin_password_file {
        let password = bootstrap::read_password_file(path)?;
        match bootstrap::first_admin(storage, &config.admin_username, password).await? {
            Some(user) => tracing::info!(username = %user.username, "first admin account created"),
            None => tracing::info!(
                "accounts exist; FLOWSENTINEL_ADMIN_PASSWORD_FILE is ignored and can be removed"
            ),
        }
    }
    if storage.count_users().await.map_err(|e| e.to_string())? == 0 {
        tracing::warn!(
            "no accounts exist, so nobody can sign in; create an admin with \
             `flowsentinel-api create-user --username NAME --role admin` (password on stdin) \
             or FLOWSENTINEL_ADMIN_PASSWORD_FILE"
        );
    }
    Ok(())
}

/// `create-user --username NAME --role ROLE`: reads the password from
/// standard input (up to the first line ending), creates the account and
/// exits.
async fn run_create_user(args: &[String]) -> ExitCode {
    let mut username = None;
    let mut role = None;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        match (flag.as_str(), rest.next()) {
            ("--username", Some(value)) => username = Some(value.clone()),
            ("--role", Some(value)) => role = storage::Role::parse(value),
            _ => {
                eprintln!("error: unexpected argument {flag:?}; {USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(username), Some(role)) = (username, role) else {
        eprintln!("error: --username and a valid --role are required; {USAGE}");
        return ExitCode::from(2);
    };
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let Some(database_url) = config.database_url.as_deref() else {
        eprintln!("error: set FLOWSENTINEL_DATABASE_URL");
        return ExitCode::FAILURE;
    };
    let typed = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let read = if typed {
        eprintln!("Password (input is visible; prefer piping it in), then Enter:");
        bootstrap::read_password_line(std::io::stdin().lock())
    } else {
        bootstrap::read_password(std::io::stdin().lock())
    };
    let password = match read {
        // Only the first line counts.
        Ok(text) => text.lines().next().unwrap_or_default().to_owned(),
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let storage = match Storage::connect(database_url, 2).await {
        Ok(storage) => storage,
        Err(err) => {
            eprintln!("error: cannot connect to PostgreSQL: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = storage.migrate().await {
        eprintln!("error: {err}");
        return ExitCode::FAILURE;
    }
    match bootstrap::create_user(&storage, &username, role, password).await {
        Ok(user) => {
            println!("created account {} with role {}", user.username, user.role);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
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
