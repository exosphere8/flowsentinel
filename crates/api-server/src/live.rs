//! Authorized live capture (`/api/v1/live/...`, admin only).
//!
//! Live capture is off unless `FLOWSENTINEL_LIVE_CAPTURE=true`, and needs a
//! build with the `live-capture` feature (libpcap). At most one capture runs
//! at a time. It writes a private temporary capture file within the
//! requested limits; when it stops, the file is imported like an upload
//! (metadata only, source `live`) and deleted.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use live_capture::limits::{self, LiveLimits};
use live_capture::{OpenRequest, Running, SourceError, SourceFactory, bpf, session};
use serde::{Deserialize, Serialize};
use serde_json::json;
use storage::{AuditOutcome, CaptureSource, NewAuditEvent};
use tokio::sync::Mutex;
use utoipa::ToSchema;

use crate::audit;
use crate::auth::{Admin, Authorized, ClientIp, CurrentUser};
use crate::error::{ApiError, ErrorBody, ErrorResponse};
use crate::extract::ApiJson;
use crate::routes::{store_file, upload_file_name};
use crate::state::AppState;
use crate::upload::UPLOAD_PREFIX;

/// Server-side live-capture settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveConfig {
    /// `FLOWSENTINEL_LIVE_CAPTURE`: off by default.
    pub enabled: bool,
    /// `FLOWSENTINEL_LIVE_INTERFACES`: if set, only these interfaces.
    pub interfaces: Option<Vec<String>>,
    /// The largest limits a request may ask for.
    pub max: LiveLimits,
}

/// Body of `POST /live/captures`. Limits left out take the defaults
/// (60 s, 100,000 packets, 100 MiB, 65,535-byte snapshots) within the
/// server's maximums.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveStart {
    /// An interface name from `GET /live/interfaces`.
    pub interface: String,
    /// Optional BPF capture filter, for example `tcp port 443`.
    #[serde(default)]
    pub filter: String,
    /// Capture traffic not addressed to this host. Off by default.
    #[serde(default)]
    pub promiscuous: bool,
    pub max_packets: Option<u64>,
    pub max_bytes: Option<u64>,
    pub max_seconds: Option<u64>,
    pub snaplen: Option<u32>,
    /// Must be `true`: you confirm that you own this network or are
    /// authorized to capture its traffic.
    pub authorized: bool,
}

/// A network interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub loopback: bool,
    pub up: bool,
}

/// The applied limits of a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct AppliedLiveLimits {
    pub max_packets: u64,
    pub max_bytes: u64,
    pub max_seconds: u64,
    pub snaplen: u32,
}

/// The current or most recent live capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct LiveStatus {
    /// `idle` (none yet), `capturing`, `importing`, `finished` or `failed`.
    pub state: String,
    pub interface: Option<String>,
    pub filter: Option<String>,
    pub promiscuous: bool,
    pub limits: Option<AppliedLiveLimits>,
    pub started_by: Option<String>,
    /// RFC 3339 UTC.
    pub started_at: Option<String>,
    pub elapsed_seconds: u64,
    pub packets_seen: u64,
    pub packets_written: u64,
    pub bytes_written: u64,
    /// Dropped because the file writer fell behind.
    pub dropped_backpressure: u64,
    /// Dropped by the kernel or the interface, as the system reports them.
    pub dropped_by_system: u64,
    /// `requested`, `packet_limit_reached`, `byte_limit_reached`,
    /// `time_limit_reached` or `source_ended`.
    pub stop_reason: Option<String>,
    /// The stored capture, once imported.
    pub capture_id: Option<i64>,
    pub error: Option<ErrorBody>,
}

impl LiveStatus {
    fn idle() -> Self {
        Self {
            state: "idle".to_owned(),
            interface: None,
            filter: None,
            promiscuous: false,
            limits: None,
            started_by: None,
            started_at: None,
            elapsed_seconds: 0,
            packets_seen: 0,
            packets_written: 0,
            bytes_written: 0,
            dropped_backpressure: 0,
            dropped_by_system: 0,
            stop_reason: None,
            capture_id: None,
            error: None,
        }
    }
}

struct Current {
    status: LiveStatus,
    started: Option<Instant>,
    running: Option<Running>,
}

/// Owns the source factory and the one capture slot.
pub struct LiveManager {
    factory: Arc<dyn SourceFactory>,
    current: Mutex<Current>,
}

impl std::fmt::Debug for LiveManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveManager").finish_non_exhaustive()
    }
}

impl LiveManager {
    pub fn new(factory: Arc<dyn SourceFactory>) -> Self {
        Self {
            factory,
            current: Mutex::new(Current {
                status: LiveStatus::idle(),
                started: None,
                running: None,
            }),
        }
    }

    /// The status, with live counters while capturing.
    pub async fn status(&self) -> LiveStatus {
        let current = self.current.lock().await;
        let mut status = current.status.clone();
        if let (Some(running), Some(started)) = (&current.running, current.started) {
            let c = running.counters();
            status.elapsed_seconds = started.elapsed().as_secs();
            status.packets_seen = c.seen;
            status.packets_written = c.written;
            status.bytes_written = c.bytes;
            status.dropped_backpressure = c.dropped_backpressure;
            status.dropped_by_system = c.kernel_dropped.saturating_add(c.interface_dropped);
        }
        status
    }
}

fn now_rfc3339() -> Option<String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    storage::rfc3339_from_nanos(i64::try_from(nanos).ok()?)
}

fn source_error(err: &SourceError) -> ApiError {
    let status = match err {
        SourceError::Unavailable => StatusCode::NOT_IMPLEMENTED,
        SourceError::PermissionDenied => StatusCode::SERVICE_UNAVAILABLE,
        SourceError::NoSuchInterface(_) | SourceError::InvalidFilter(_) => StatusCode::BAD_REQUEST,
        SourceError::Failed(_) => {
            tracing::error!(error = %err, "live capture failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    ApiError::new(status, err.code(), err.to_string())
}

fn check_enabled(state: &AppState) -> Result<(), ApiError> {
    if !state.config.live.enabled {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "live_capture_disabled",
            "live capture is turned off; an operator can enable it with FLOWSENTINEL_LIVE_CAPTURE=true",
        ));
    }
    if !state.live.factory.available() {
        return Err(source_error(&SourceError::Unavailable));
    }
    Ok(())
}

fn allowed(state: &AppState, interface: &str) -> bool {
    state
        .config
        .live
        .interfaces
        .as_ref()
        .is_none_or(|list| list.iter().any(|name| name == interface))
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| ApiError::internal("live capture task", &e))
}

/// List the interfaces live capture may use (admin).
#[utoipa::path(
    get,
    path = "/api/v1/live/interfaces",
    tag = "live",
    responses(
        (status = 200, description = "Interfaces, filtered by FLOWSENTINEL_LIVE_INTERFACES", body = Vec<Interface>),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the admin role", body = ErrorResponse),
        (status = 501, description = "This build has no live capture", body = ErrorResponse),
        (status = 503, description = "Live capture is turned off, or the server lacks capture permission", body = ErrorResponse),
    )
)]
pub async fn interfaces(
    State(state): State<AppState>,
    _admin: Authorized<Admin>,
) -> Result<Json<Vec<Interface>>, ApiError> {
    check_enabled(&state)?;
    let factory = Arc::clone(&state.live.factory);
    let found = blocking(move || factory.interfaces())
        .await?
        .map_err(|e| source_error(&e))?;
    Ok(Json(
        found
            .into_iter()
            .filter(|i| allowed(&state, &i.name))
            .map(|i| Interface {
                name: i.name,
                description: i.description,
                addresses: i.addresses,
                loopback: i.loopback,
                up: i.up,
            })
            .collect(),
    ))
}

/// The current or most recent live capture (admin).
#[utoipa::path(
    get,
    path = "/api/v1/live/captures/current",
    tag = "live",
    responses(
        (status = 200, description = "Status and counters", body = LiveStatus),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the admin role", body = ErrorResponse),
    )
)]
pub async fn status(State(state): State<AppState>, _admin: Authorized<Admin>) -> Json<LiveStatus> {
    Json(state.live.status().await)
}

/// Start a live capture (admin).
///
/// Requires `"authorized": true`. Promiscuous mode is off unless requested.
/// At most one capture runs at a time; it stops at its first limit or when
/// asked, and is then imported as a capture with source `live`.
#[utoipa::path(
    post,
    path = "/api/v1/live/captures",
    tag = "live",
    request_body = LiveStart,
    responses(
        (status = 202, description = "Capturing", body = LiveStatus),
        (status = 400, description = "Not confirmed as authorized, unknown interface, invalid filter or limit", body = ErrorResponse),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the admin role, interface not allowed, or missing CSRF token", body = ErrorResponse),
        (status = 409, description = "A capture is already running", body = ErrorResponse),
        (status = 429, description = "Too many imports in progress", body = ErrorResponse),
        (status = 501, description = "This build has no live capture", body = ErrorResponse),
        (status = 503, description = "Live capture is turned off, or the server lacks capture permission", body = ErrorResponse),
    )
)]
pub async fn start(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    admin: Authorized<Admin>,
    ApiJson(request): ApiJson<LiveStart>,
) -> Result<(StatusCode, Json<LiveStatus>), ApiError> {
    let interface: String = request.interface.chars().take(64).collect();
    match begin(&state, client_ip, admin.user(), request).await {
        Ok(status) => Ok((StatusCode::ACCEPTED, Json(status))),
        Err(err) => {
            // Refused attempts are audited too, for example an interface
            // outside the allowlist.
            let outcome = if err.status == StatusCode::FORBIDDEN {
                AuditOutcome::Denied
            } else {
                AuditOutcome::Failure
            };
            audit::record(
                &state,
                NewAuditEvent {
                    client_ip,
                    outcome,
                    target_type: Some("interface"),
                    target_id: Some(interface),
                    details: json!({ "code": err.code }),
                    ..audit::by(admin.user(), "live.start")
                },
            )
            .await;
            Err(err)
        }
    }
}

/// Checks a start request and starts the capture. Once the capture runs,
/// everything else happens in spawned tasks, so a client that disconnects
/// cannot leave the slot stuck.
async fn begin(
    state: &AppState,
    client_ip: Option<std::net::IpAddr>,
    user: &CurrentUser,
    request: LiveStart,
) -> Result<LiveStatus, ApiError> {
    check_enabled(state)?;
    if !request.authorized {
        return Err(ApiError::bad_request(
            "authorization_required",
            "confirm that you own this network or are authorized to capture its traffic \
             (\"authorized\": true)",
        ));
    }
    if !allowed(state, &request.interface) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "interface_not_allowed",
            "this interface is not in FLOWSENTINEL_LIVE_INTERFACES",
        ));
    }
    let limits = limits::resolve(
        &state.config.live.max,
        request.max_packets,
        request.max_bytes,
        request.max_seconds,
        request.snaplen,
    )
    .map_err(|e| ApiError::bad_request("invalid_limit", e.to_string()))?;
    bpf::check_text(&request.filter)
        .map_err(|e| ApiError::bad_request("invalid_capture_filter", e.to_string()))?;
    let factory = Arc::clone(&state.live.factory);
    let filter = request.filter.clone();
    blocking(move || factory.check_filter(&filter))
        .await?
        .map_err(|e| source_error(&e))?;

    let mut current = state.live.current.lock().await;
    if matches!(current.status.state.as_str(), "capturing" | "importing") {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "live_capture_running",
            "a live capture is already running; stop it first",
        ));
    }
    // The import slot is held from the start, so the capture can always be
    // stored when it ends.
    let Ok(permit) = Arc::clone(&state.import_slots).try_acquire_owned() else {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "import_busy",
            "too many imports are in progress; try again shortly",
        ));
    };
    let open = OpenRequest {
        interface: request.interface.clone(),
        filter: request.filter.clone(),
        promiscuous: request.promiscuous,
        snaplen: limits.snaplen,
    };
    let factory = Arc::clone(&state.live.factory);
    let source = blocking(move || factory.open(&open))
        .await?
        .map_err(|e| source_error(&e))?;
    let file = tempfile::Builder::new()
        .prefix(UPLOAD_PREFIX)
        .suffix(".pcap")
        .tempfile_in(&state.config.upload_dir)
        .map_err(|e| ApiError::internal("creating the capture file", &e))?;
    let out = std::io::BufWriter::with_capacity(
        256 * 1024,
        file.reopen()
            .map_err(|e| ApiError::internal("opening the capture file", &e))?,
    );
    let running = session::start(source, limits, out)
        .map_err(|e| ApiError::internal("starting the capture threads", &e))?;

    let applied = AppliedLiveLimits {
        max_packets: limits.max_packets,
        max_bytes: limits.max_bytes,
        max_seconds: limits.max_duration.as_secs(),
        snaplen: limits.snaplen,
    };
    current.status = LiveStatus {
        state: "capturing".to_owned(),
        interface: Some(request.interface.clone()),
        filter: Some(request.filter.clone()),
        promiscuous: request.promiscuous,
        limits: Some(applied),
        started_by: Some(user.username.clone()),
        started_at: now_rfc3339(),
        ..LiveStatus::idle()
    };
    current.started = Some(Instant::now());
    current.running = Some(running);
    // Spawned before anything else is awaited: from here on the capture
    // finishes and is imported whatever happens to this request.
    tokio::spawn(finish_when_done(
        state.clone(),
        user.clone(),
        client_ip,
        file,
        Arc::new(permit),
        request.interface.clone(),
    ));
    drop(current);
    tracing::info!(
        interface = %request.interface,
        promiscuous = request.promiscuous,
        "live capture started"
    );
    let started = NewAuditEvent {
        client_ip,
        target_type: Some("interface"),
        target_id: Some(request.interface.chars().take(64).collect()),
        details: json!({
            "filter": request.filter,
            "promiscuous": request.promiscuous,
            "limits": applied,
        }),
        ..audit::by(user, "live.start")
    };
    let audit_state = state.clone();
    tokio::spawn(async move { audit::record(&audit_state, started).await });
    Ok(state.live.status().await)
}

/// Stop the running live capture (admin). It is then imported.
#[utoipa::path(
    post,
    path = "/api/v1/live/captures/current/stop",
    tag = "live",
    responses(
        (status = 202, description = "Stopping", body = LiveStatus),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the admin role, or missing CSRF token", body = ErrorResponse),
        (status = 409, description = "No capture is running", body = ErrorResponse),
    )
)]
pub async fn stop(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    admin: Authorized<Admin>,
) -> Result<(StatusCode, Json<LiveStatus>), ApiError> {
    {
        let current = state.live.current.lock().await;
        let Some(running) = &current.running else {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "no_live_capture",
                "no live capture is running",
            ));
        };
        running.stop();
    }
    audit::record(
        &state,
        NewAuditEvent {
            client_ip,
            ..audit::by(admin.user(), "live.stop")
        },
    )
    .await;
    Ok((StatusCode::ACCEPTED, Json(state.live.status().await)))
}

/// Waits for the capture threads, imports the file, deletes it and records
/// the outcome.
async fn finish_when_done(
    state: AppState,
    started_by: CurrentUser,
    client_ip: Option<std::net::IpAddr>,
    file: tempfile::NamedTempFile,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    interface: String,
) {
    let running = loop {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut current = state.live.current.lock().await;
        if current.running.as_ref().is_none_or(Running::is_finished) {
            let snapshot = current.running.as_ref().map(Running::counters);
            if let (Some(c), Some(started)) = (snapshot, current.started) {
                let status = &mut current.status;
                status.elapsed_seconds = started.elapsed().as_secs();
                status.packets_seen = c.seen;
                status.packets_written = c.written;
                status.bytes_written = c.bytes;
                status.dropped_backpressure = c.dropped_backpressure;
                status.dropped_by_system = c.kernel_dropped.saturating_add(c.interface_dropped);
            }
            status_state(&mut current.status, "importing");
            current.started = None;
            break current.running.take();
        }
    };
    let finished = match running {
        Some(running) => tokio::task::spawn_blocking(move || running.join())
            .await
            .map_err(|_| live_capture::LiveError::Thread)
            .and_then(|r| r),
        None => Err(live_capture::LiveError::Thread),
    };

    let outcome = match finished {
        Err(err) => Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "capture_failed",
            err.to_string(),
        )),
        Ok(done) => {
            {
                let mut current = state.live.current.lock().await;
                current.status.stop_reason = Some(done.reason.code().to_owned());
                let c = done.counters;
                current.status.packets_seen = c.seen;
                current.status.packets_written = c.written;
                current.status.bytes_written = c.bytes;
                current.status.dropped_backpressure = c.dropped_backpressure;
                current.status.dropped_by_system =
                    c.kernel_dropped.saturating_add(c.interface_dropped);
            }
            let seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let name = upload_file_name(&format!("live-{interface}-{seconds}.pcap"))
                .unwrap_or_else(|_| format!("live-{seconds}.pcap"));
            store_file(
                &state,
                file.path(),
                &name,
                &done.sha256,
                CaptureSource::Live,
                permit,
            )
            .await
            .map(|detail| (detail, done))
        }
    };
    // The temporary file holds packet contents; delete it now.
    drop(file);

    let mut current = state.live.current.lock().await;
    let event = match outcome {
        Ok((detail, done)) => {
            status_state(&mut current.status, "finished");
            current.status.capture_id = Some(detail.session.id);
            tracing::info!(session_id = detail.session.id, "live capture stored");
            NewAuditEvent {
                client_ip,
                target_type: Some("capture"),
                target_id: Some(detail.session.id.to_string()),
                details: json!({
                    "reason": done.reason.code(),
                    "packets": done.counters.written,
                    "dropped_backpressure": done.counters.dropped_backpressure,
                    "dropped_by_system": done.counters.kernel_dropped
                        .saturating_add(done.counters.interface_dropped),
                }),
                ..audit::by(&started_by, "live.finish")
            }
        }
        Err(err) => {
            status_state(&mut current.status, "failed");
            current.status.error = Some(ErrorBody {
                code: err.code.to_owned(),
                message: err.message.clone(),
                position: None,
            });
            tracing::warn!(code = err.code, "live capture failed");
            NewAuditEvent {
                client_ip,
                outcome: AuditOutcome::Failure,
                details: json!({ "code": err.code }),
                ..audit::by(&started_by, "live.finish")
            }
        }
    };
    drop(current);
    audit::record(&state, event).await;
}

fn status_state(status: &mut LiveStatus, state: &str) {
    state.clone_into(&mut status.state);
}
