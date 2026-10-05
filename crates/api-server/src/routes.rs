//! `/api/v1` handlers.

use std::path::PathBuf;
use std::sync::Arc;

use analysis::{AnalysisConfig, analyze_file_with_detection, replay_packets};
use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use capture::{CaptureError, ErrorCategory, MonotonicClock, display_file_name};
use detection_engine::{AlertStatus, Detector, NATURE, RULES};
use filter_language::{CompiledFilter, FieldType, Param, Piece, Target, compile};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder};
use storage::{
    AlertFilter, AlertRow, AlertSort, CaptureSource, DnsEvent, FlowDetail, FlowSort,
    FlowSummaryRow, HttpEvent, ImportMeta, Overview, PacketDetail, PacketRow, PacketSort,
    PacketSummary, Page, Paged, RetentionSettings, Session, SessionDetail, SessionSort,
    SqlCondition, StorageError, TlsEvent,
};
use utoipa::{IntoParams, ToSchema};

use crate::audit;
use crate::auth::{Admin, Analyst, Authorized, ClientIp};
use crate::error::{ApiError, ErrorResponse};
use crate::extract::{ApiJson, ApiPath, ApiQuery};
use crate::state::AppState;
use crate::upload;

const DEFAULT_PER_PAGE: u32 = 50;
/// Packets per batch handed from the analysis thread to the database.
const IMPORT_BATCH: usize = 1_000;
/// Batches buffered between the analysis thread and the database writer.
const IMPORT_QUEUE: usize = 4;
/// Media types accepted for uploads.
const UPLOAD_TYPES: [&str; 2] = ["application/vnd.tcpdump.pcap", "application/octet-stream"];

pub(crate) fn page_of(page: Option<u32>, per_page: Option<u32>) -> Result<Page, ApiError> {
    let page = page.unwrap_or(1);
    let per_page = per_page.unwrap_or(DEFAULT_PER_PAGE);
    if page == 0 || page > Page::MAX_PAGE {
        return Err(ApiError::bad_request(
            "invalid_page",
            format!("page must be between 1 and {}", Page::MAX_PAGE),
        ));
    }
    if per_page == 0 || per_page > Page::MAX_PER_PAGE {
        return Err(ApiError::bad_request(
            "invalid_per_page",
            format!("per_page must be between 1 and {}", Page::MAX_PER_PAGE),
        ));
    }
    Ok(Page::new(page, per_page))
}

/// Pagination only.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct PageParams {
    /// 1-based page number (default 1, at most 1000000).
    #[param(minimum = 1, maximum = 1000000)]
    pub page: Option<u32>,
    /// Items per page, 1-500 (default 50).
    #[param(minimum = 1, maximum = 500)]
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct SessionListParams {
    /// 1-based page number (default 1, at most 1000000).
    #[param(minimum = 1, maximum = 1000000)]
    pub page: Option<u32>,
    /// Items per page, 1-500 (default 50).
    #[param(minimum = 1, maximum = 500)]
    pub per_page: Option<u32>,
    /// `newest` (default), `oldest`, `packets` or `size`.
    pub sort: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct PacketListParams {
    /// 1-based page number (default 1, at most 1000000).
    #[param(minimum = 1, maximum = 1000000)]
    pub page: Option<u32>,
    /// Items per page, 1-500 (default 50).
    #[param(minimum = 1, maximum = 500)]
    pub per_page: Option<u32>,
    /// `index` (default), `-index`, `time` or `-length`.
    pub sort: Option<String>,
    /// Only packets of this flow.
    pub flow_id: Option<i64>,
    /// Display filter over packet fields, for example
    /// `tcp.port == 443 and not ip.addr == 192.0.2.0/24`.
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct FlowListParams {
    /// 1-based page number (default 1, at most 1000000).
    #[param(minimum = 1, maximum = 1000000)]
    pub page: Option<u32>,
    /// Items per page, 1-500 (default 50).
    #[param(minimum = 1, maximum = 500)]
    pub per_page: Option<u32>,
    /// `start` (default), `-bytes`, `-packets` or `-duration`.
    pub sort: Option<String>,
    /// Display filter over flow fields, for example `flow.bytes > 1000000`.
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct AlertListParams {
    /// 1-based page number (default 1, at most 1000000).
    pub page: Option<u32>,
    /// Items per page, 1-500 (default 50).
    pub per_page: Option<u32>,
    /// `severity` (default: most severe first), `time` or `id`.
    pub sort: Option<String>,
    /// Only alerts of this severity: `low`, `medium` or `high`.
    pub severity: Option<String>,
    /// Only alerts with this status: `open`, `acknowledged`, `resolved` or
    /// `false_positive`.
    pub status: Option<String>,
    /// Only alerts of this rule, for example `FS-SCAN-SYN`.
    pub rule: Option<String>,
}

/// A triage status change.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AlertUpdate {
    /// `open`, `acknowledged`, `resolved` or `false_positive`.
    pub status: String,
}

/// One detection rule.
#[derive(Debug, Serialize, ToSchema)]
pub struct RuleInfo {
    /// Stable identifier, for example `FS-SCAN-SYN`.
    pub id: &'static str,
    pub name: &'static str,
    /// `low`, `medium` or `high`.
    pub severity: &'static str,
    pub description: &'static str,
    /// Why an alert from this rule may be wrong.
    pub uncertainty: &'static str,
    pub likely_false_positives: Vec<&'static str>,
    /// MITRE ATT&CK techniques the pattern can relate to, as context only.
    pub mitre_attack: Vec<&'static str>,
    /// Every alert is a heuristic indicator, not proof of compromise.
    pub nature: &'static str,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct FilterParams {
    /// `packets` or `flows`.
    pub target: String,
    /// The filter to check.
    pub filter: String,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct TargetParams {
    /// `packets` or `flows`.
    pub target: String,
}

/// A valid filter.
#[derive(Debug, Serialize, ToSchema)]
pub struct FilterCheck {
    pub valid: bool,
    pub target: &'static str,
    /// The filter in canonical form (keywords lowercased, values quoted).
    pub normalized: String,
    /// Values bound as query parameters.
    pub parameters: usize,
}

/// One filterable field.
#[derive(Debug, Serialize, ToSchema)]
pub struct FilterField {
    pub name: &'static str,
    /// `ip address or cidr`, `unsigned integer`, `number`, `text`,
    /// `keyword` or `boolean`.
    #[serde(rename = "type")]
    pub field_type: &'static str,
    pub description: &'static str,
    /// Operators the field accepts.
    pub operators: Vec<&'static str>,
    /// Allowed values, for keyword fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<&'static str>>,
    /// Largest allowed value, for integer fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct UploadParams {
    /// Original file name; must end in `.pcap`. Only the final path
    /// component is kept, sanitized and shortened to 128 characters.
    pub file_name: String,
}

fn invalid_sort(allowed: &str) -> ApiError {
    ApiError::bad_request("invalid_sort", format!("sort must be one of: {allowed}"))
}

fn session_sort(value: Option<&str>) -> Result<SessionSort, ApiError> {
    Ok(match value {
        None | Some("newest") => SessionSort::NewestFirst,
        Some("oldest") => SessionSort::OldestFirst,
        Some("packets") => SessionSort::MostPackets,
        Some("size") => SessionSort::Largest,
        Some(_) => return Err(invalid_sort("newest, oldest, packets, size")),
    })
}

fn packet_sort(value: Option<&str>) -> Result<PacketSort, ApiError> {
    Ok(match value {
        None | Some("index") => PacketSort::Index,
        Some("-index") => PacketSort::IndexDesc,
        Some("time") => PacketSort::Time,
        Some("-length") => PacketSort::LengthDesc,
        Some(_) => return Err(invalid_sort("index, -index, time, -length")),
    })
}

fn alert_sort(value: Option<&str>) -> Result<AlertSort, ApiError> {
    Ok(match value {
        None | Some("severity") => AlertSort::Severity,
        Some("time") => AlertSort::Time,
        Some("id") => AlertSort::Id,
        Some(_) => return Err(invalid_sort("severity, time, id")),
    })
}

fn alert_status(value: &str) -> Result<AlertStatus, ApiError> {
    AlertStatus::parse(value).ok_or_else(|| {
        ApiError::bad_request(
            "invalid_status",
            "status must be one of: open, acknowledged, resolved, false_positive",
        )
    })
}

/// Validates the alert list restrictions against the fixed sets of values.
fn alert_filter(params: &AlertListParams) -> Result<AlertFilter, ApiError> {
    let severity = match params.severity.as_deref() {
        None => None,
        Some(value @ ("low" | "medium" | "high")) => Some(value.to_owned()),
        Some(_) => {
            return Err(ApiError::bad_request(
                "invalid_severity",
                "severity must be one of: low, medium, high",
            ));
        }
    };
    let status = params
        .status
        .as_deref()
        .map(|value| alert_status(value).map(|s| s.as_str().to_owned()))
        .transpose()?;
    let rule_id = match params.rule.as_deref() {
        None => None,
        Some(value) => match RULES.iter().find(|rule| rule.id == value) {
            Some(rule) => Some(rule.id.to_owned()),
            None => {
                return Err(ApiError::bad_request(
                    "invalid_rule",
                    "rule must be a rule ID from GET /api/v1/rules",
                ));
            }
        },
    };
    Ok(AlertFilter {
        severity,
        status,
        rule_id,
    })
}

fn flow_sort(value: Option<&str>) -> Result<FlowSort, ApiError> {
    Ok(match value {
        None | Some("start") => FlowSort::Start,
        Some("-bytes") => FlowSort::BytesDesc,
        Some("-packets") => FlowSort::PacketsDesc,
        Some("-duration") => FlowSort::DurationDesc,
        Some(_) => return Err(invalid_sort("start, -bytes, -packets, -duration")),
    })
}

async fn require_session(state: &AppState, id: i64) -> Result<(), ApiError> {
    if state.storage.session_exists(id).await? {
        Ok(())
    } else {
        Err(ApiError::not_found("capture"))
    }
}

/// The conditions of one list request, all of which must hold.
#[derive(Default)]
struct Conditions {
    flow_id: Option<i64>,
    filter: Option<CompiledFilter>,
}

impl Conditions {
    fn as_condition(&self) -> Option<&dyn SqlCondition> {
        let empty = self.flow_id.is_none() && self.filter.is_none();
        (!empty).then_some(self as &dyn SqlCondition)
    }
}

impl SqlCondition for Conditions {
    fn push(&self, builder: &mut QueryBuilder<'_, Postgres>) {
        builder.push("TRUE");
        if let Some(flow_id) = self.flow_id {
            builder.push(" AND flow_id = ");
            builder.push_bind(flow_id);
        }
        if let Some(filter) = &self.filter {
            // Translated pieces are fixed SQL text and bound parameters.
            builder.push(" AND (");
            for piece in &filter.pieces {
                match piece {
                    Piece::Sql(text) => {
                        builder.push(*text);
                    }
                    Piece::Param(Param::Text(text)) => {
                        builder.push_bind(text.clone());
                    }
                    Piece::Param(Param::Int(value)) => {
                        builder.push_bind(*value);
                    }
                    Piece::Param(Param::Float(value)) => {
                        builder.push_bind(*value);
                    }
                }
            }
            builder.push(")");
        }
    }
}

fn target_of(value: &str) -> Result<Target, ApiError> {
    match value {
        "packets" => Ok(Target::Packets),
        "flows" => Ok(Target::Flows),
        _ => Err(ApiError::bad_request(
            "invalid_target",
            "target must be packets or flows",
        )),
    }
}

/// Compiles an optional filter; a blank filter means none. The text is not
/// trimmed, so error positions match what the client sent and what
/// `/filters/validate` reports.
fn compile_filter(text: Option<&str>, target: Target) -> Result<Option<CompiledFilter>, ApiError> {
    match text {
        None => Ok(None),
        Some(text) if text.chars().all(|c| c.is_ascii_whitespace()) => Ok(None),
        Some(text) => compile(text, target)
            .map(Some)
            .map_err(|err| ApiError::filter(&err)),
    }
}

/// How long a filtered list waits for a filter slot before `429`.
const FILTER_SLOT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// A permit to run a filtered list query. Waits up to [`FILTER_SLOT_WAIT`]
/// for one, then answers `429`. Taken before the read slot, so filtered
/// requests waiting their turn hold no database slot.
async fn filter_permit(
    state: &AppState,
    filter: Option<&CompiledFilter>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, ApiError> {
    if filter.is_none() {
        return Ok(None);
    }
    let acquire = Arc::clone(&state.filter_slots).acquire_owned();
    match tokio::time::timeout(FILTER_SLOT_WAIT, acquire).await {
        Ok(Ok(permit)) => Ok(Some(permit)),
        _ => Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "filter_busy",
            "too many filtered queries are running; try again shortly",
        )),
    }
}

/// Maps a capture error for an upload. The temporary file's random name is
/// replaced by the client's file name in the message.
fn capture_error(err: &CaptureError, temp_name: &str, file_name: &str) -> ApiError {
    match err.category() {
        ErrorCategory::Io => ApiError::internal("reading upload", err),
        ErrorCategory::Input | ErrorCategory::Malformed => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            err.code(),
            err.to_string().replace(temp_name, file_name),
        ),
    }
}

/// The stored name of an upload: the last component of `name` (`/` and `\\`
/// are separators on every platform), sanitized and shortened to 128
/// characters with the `.pcap` extension kept.
pub(crate) fn upload_file_name(name: &str) -> Result<String, ApiError> {
    let last = name.rsplit(['/', '\\']).next().unwrap_or_default();
    if !last.to_ascii_lowercase().ends_with(".pcap") || last.len() <= ".pcap".len() {
        return Err(ApiError::bad_request(
            "unsupported_extension",
            "file_name must be a name ending in .pcap (pcapng is not supported)",
        ));
    }
    let shown = display_file_name(std::path::Path::new(last));
    Ok(match shown.strip_suffix("...") {
        Some(cut) => format!("{cut}...pcap"),
        None => shown,
    })
}

/// A classic libpcap file, sent as the raw request body.
pub struct PcapFile;

impl utoipa::PartialSchema for PcapFile {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .format(Some(utoipa::openapi::SchemaFormat::KnownFormat(
                utoipa::openapi::KnownFormat::Binary,
            )))
            .into()
    }
}

impl ToSchema for PcapFile {}

fn check_upload_headers(headers: &HeaderMap, max_bytes: u64) -> Result<(), ApiError> {
    let media_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(|v| v.trim().to_ascii_lowercase());
    if !media_type.is_some_and(|t| UPLOAD_TYPES.contains(&t.as_str())) {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "send the capture as the raw request body with Content-Type \
             application/vnd.tcpdump.pcap or application/octet-stream",
        ));
    }
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > max_bytes) {
        return Err(upload::too_large(max_bytes));
    }
    Ok(())
}

/// Import a classic `.pcap` file.
///
/// Send the file as the raw request body. It is streamed to a private
/// temporary file (size-limited), analyzed in two passes, stored as metadata
/// only in one transaction, and the temporary file is deleted.
#[utoipa::path(
    post,
    path = "/api/v1/captures",
    tag = "captures",
    params(UploadParams),
    request_body(
        content(
            (PcapFile = "application/vnd.tcpdump.pcap"),
            (PcapFile = "application/octet-stream"),
        ),
        description = "Classic libpcap file, as the raw request body"
    ),
    responses(
        (status = 201, description = "Imported", body = SessionDetail),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 408, description = "Upload stalled or too slow", body = ErrorResponse),
        (status = 413, description = "Upload too large", body = ErrorResponse),
        (status = 415, description = "Wrong content type", body = ErrorResponse),
        (status = 422, description = "Not a supported or valid capture", body = ErrorResponse),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the analyst role, or a missing CSRF token", body = ErrorResponse),
        (status = 429, description = "Too many imports in progress", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn import_capture(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    analyst: Authorized<Analyst>,
    ApiQuery(params): ApiQuery<UploadParams>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let result = import_upload(&state, &params, &headers, body).await;
    let file_name = upload_file_name(&params.file_name).unwrap_or_default();
    let event = match &result {
        Ok((detail, _)) => storage::NewAuditEvent {
            target_type: Some("capture"),
            target_id: Some(detail.session.id.to_string()),
            details: json!({
                "file_name": file_name,
                "sha256": detail.session.sha256,
                "packets": detail.session.packets_processed,
                "alerts": detail.session.alerts_total,
            }),
            ..audit::by(analyst.user(), "capture.import")
        },
        Err(err) => storage::NewAuditEvent {
            outcome: storage::AuditOutcome::Failure,
            details: json!({ "file_name": file_name, "code": err.code }),
            ..audit::by(analyst.user(), "capture.import")
        },
    };
    audit::record(&state, storage::NewAuditEvent { client_ip, ..event }).await;
    result.map(|(_, response)| response)
}

/// Streams, analyzes and stores one upload. Returns the stored capture and
/// the `201` response.
async fn import_upload(
    state: &AppState,
    params: &UploadParams,
    headers: &HeaderMap,
    body: Body,
) -> Result<(SessionDetail, Response), ApiError> {
    let file_name = upload_file_name(&params.file_name)?;
    check_upload_headers(headers, state.config.max_upload_bytes)?;
    // The permit is shared with the analysis threads, so the slot stays taken
    // until they finish, even if the client disconnects first.
    let Ok(permit) = Arc::clone(&state.import_slots).try_acquire_owned() else {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "import_busy",
            "too many imports are in progress; try again shortly",
        ));
    };
    let permit = Arc::new(permit);

    let received = upload::receive(
        body,
        &state.config.upload_dir,
        state.config.max_upload_bytes,
    )
    .await?;
    let session = store_file(
        state,
        received.file.path(),
        &file_name,
        &received.sha256,
        CaptureSource::Upload,
        permit,
    )
    .await?;
    tracing::info!(
        session_id = session.session.id,
        packets = session.session.packets_processed,
        packets_stored = session.session.packets_stored,
        flows = session.session.flows_total,
        alerts = session.session.alerts_total,
        size_bytes = received.size_bytes,
        "capture imported"
    );
    let location = HeaderValue::try_from(format!("/api/v1/captures/{}", session.session.id))
        .map_err(|e| ApiError::internal("location header", &e))?;
    let response = (
        StatusCode::CREATED,
        [(header::LOCATION, location)],
        Json(&session),
    )
        .into_response();
    Ok((session, response))
}

/// Analyzes the capture file at `path` in two passes and stores its
/// metadata in one transaction. `permit` is an import slot, held until the
/// analysis threads finish. The caller deletes the file.
pub(crate) async fn store_file(
    state: &AppState,
    path: &std::path::Path,
    file_name: &str,
    sha256: &str,
    source: CaptureSource,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> Result<SessionDetail, ApiError> {
    let file_name = file_name.to_owned();
    let retention = state.storage.retention().await?;
    let config = AnalysisConfig {
        limits: state.config.capture_limits,
        flows: state.config.flow_config,
        replay_packets: u64::try_from(retention.max_packets_stored).unwrap_or(0),
    };
    let path: PathBuf = path.to_owned();
    let temp_name = display_file_name(&path);
    // The configuration was validated at startup.
    let detector = Detector::new(state.config.detection.clone())
        .map_err(|e| ApiError::internal("detection configuration", &e))?;

    // Pass 1: summaries, flows and detections.
    let first_path = path.clone();
    let held = Arc::clone(&permit);
    let analysis = tokio::task::spawn_blocking(move || {
        let _held = held;
        analyze_file_with_detection(&first_path, &config, detector, &MonotonicClock::start())
    })
    .await
    .map_err(|e| ApiError::internal("analysis task", &e))?
    .map_err(|err| capture_error(&err, &temp_name, &file_name))?;

    let meta = ImportMeta {
        file_name: file_name.clone(),
        sha256: sha256.to_owned(),
        source,
        ttl_days: retention.session_ttl_days,
    };
    let mut import = state.storage.begin_import(&analysis, &meta).await?;

    // Pass 2: packets, streamed through a bounded queue into the transaction.
    let analysis = Arc::new(analysis);
    let (sender, mut receiver) =
        tokio::sync::mpsc::channel::<Result<Vec<PacketRow>, StorageError>>(IMPORT_QUEUE);
    let replay_analysis = Arc::clone(&analysis);
    let held = Arc::clone(&permit);
    let replay = tokio::task::spawn_blocking(move || {
        let _held = held;
        replay_packets(
            &path,
            &config,
            &replay_analysis,
            IMPORT_BATCH,
            &mut |packets| {
                let rows = packets.iter().map(PacketRow::from_analyzed).collect();
                // A send error means the writer stopped; stop reading.
                sender.blocking_send(rows).is_ok()
            },
        )
    });
    let mut write_error = None;
    while let Some(batch) = receiver.recv().await {
        let written = match batch {
            Ok(rows) => import.add_packets(rows).await,
            Err(err) => Err(err),
        };
        if let Err(err) = written {
            write_error = Some(err);
            break;
        }
    }
    drop(receiver);
    let replay = replay
        .await
        .map_err(|e| ApiError::internal("analysis task", &e))?
        .map_err(|e| ApiError::internal("replaying upload", &e))?;
    if let Some(err) = write_error {
        return Err(err.into());
    }
    if replay.stopped
        || replay.packets != analysis.replayable_packets
        || replay.fingerprint != analysis.fingerprint
    {
        return Err(ApiError::internal(
            "import",
            &"the uploaded file changed between analysis passes",
        ));
    }

    Ok(import.commit(&state.storage).await?)
}

/// Totals across all captures, alert counts and the newest captures.
#[utoipa::path(
    get,
    path = "/api/v1/overview",
    tag = "captures",
    responses((status = 200, description = "Totals", body = Overview))
)]
pub async fn overview(State(state): State<AppState>) -> Result<Json<Overview>, ApiError> {
    let _slot = state.read_slot().await?;
    Ok(Json(state.storage.overview().await?))
}

/// List imported captures.
#[utoipa::path(
    get,
    path = "/api/v1/captures",
    tag = "captures",
    params(SessionListParams),
    responses(
        (status = 200, description = "A page of captures", body = Paged<Session>),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn list_captures(
    State(state): State<AppState>,
    ApiQuery(params): ApiQuery<SessionListParams>,
) -> Result<Json<Paged<Session>>, ApiError> {
    let _slot = state.read_slot().await?;
    let page = page_of(params.page, params.per_page)?;
    let sort = session_sort(params.sort.as_deref())?;
    Ok(Json(state.storage.list_sessions(page, sort).await?))
}

/// Get one capture with its summaries.
#[utoipa::path(
    get,
    path = "/api/v1/captures/{id}",
    tag = "captures",
    params(("id" = i64, Path, description = "Capture ID")),
    responses(
        (status = 200, description = "The capture", body = SessionDetail),
        (status = 400, description = "Invalid ID", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn get_capture(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<i64>,
) -> Result<Json<SessionDetail>, ApiError> {
    let _slot = state.read_slot().await?;
    state
        .storage
        .get_session(id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("capture"))
}

/// Delete a capture and all its stored metadata.
#[utoipa::path(
    delete,
    path = "/api/v1/captures/{id}",
    tag = "captures",
    params(("id" = i64, Path, description = "Capture ID")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the admin role, or a missing CSRF token", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn delete_capture(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    admin: Authorized<Admin>,
    ApiPath(id): ApiPath<i64>,
) -> Result<StatusCode, ApiError> {
    let deleted = {
        let _slot = state.read_slot().await?;
        state.storage.delete_session(id).await?
    };
    if !deleted {
        return Err(ApiError::not_found("capture"));
    }
    tracing::info!(session_id = id, "capture deleted");
    audit::record(
        &state,
        storage::NewAuditEvent {
            client_ip,
            target_type: Some("capture"),
            target_id: Some(id.to_string()),
            ..audit::by(admin.user(), "capture.delete")
        },
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// List a capture's packets.
#[utoipa::path(
    get,
    path = "/api/v1/captures/{id}/packets",
    tag = "packets",
    params(("id" = i64, Path, description = "Capture ID"), PacketListParams),
    responses(
        (status = 200, description = "A page of packets", body = Paged<PacketSummary>),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 404, description = "Capture not found", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn list_packets(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<i64>,
    ApiQuery(params): ApiQuery<PacketListParams>,
) -> Result<Json<Paged<PacketSummary>>, ApiError> {
    let page = page_of(params.page, params.per_page)?;
    let sort = packet_sort(params.sort.as_deref())?;
    let conditions = Conditions {
        flow_id: params.flow_id,
        filter: compile_filter(params.filter.as_deref(), Target::Packets)?,
    };
    let _permit = filter_permit(&state, conditions.filter.as_ref()).await?;
    let _slot = state.read_slot().await?;
    require_session(&state, id).await?;
    Ok(Json(
        state
            .storage
            .list_packets(id, page, sort, conditions.as_condition())
            .await?,
    ))
}

/// Get one packet with its decoded protocol tree.
#[utoipa::path(
    get,
    path = "/api/v1/captures/{id}/packets/{index}",
    tag = "packets",
    params(
        ("id" = i64, Path, description = "Capture ID"),
        ("index" = i64, Path, description = "1-based packet index"),
    ),
    responses(
        (status = 200, description = "The packet", body = PacketDetail),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn get_packet(
    State(state): State<AppState>,
    ApiPath((id, index)): ApiPath<(i64, i64)>,
) -> Result<Json<PacketDetail>, ApiError> {
    let _slot = state.read_slot().await?;
    state
        .storage
        .get_packet(id, index)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("packet"))
}

/// List a capture's flows.
#[utoipa::path(
    get,
    path = "/api/v1/captures/{id}/flows",
    tag = "flows",
    params(("id" = i64, Path, description = "Capture ID"), FlowListParams),
    responses(
        (status = 200, description = "A page of flows", body = Paged<FlowSummaryRow>),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 404, description = "Capture not found", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn list_flows(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<i64>,
    ApiQuery(params): ApiQuery<FlowListParams>,
) -> Result<Json<Paged<FlowSummaryRow>>, ApiError> {
    let page = page_of(params.page, params.per_page)?;
    let sort = flow_sort(params.sort.as_deref())?;
    let conditions = Conditions {
        flow_id: None,
        filter: compile_filter(params.filter.as_deref(), Target::Flows)?,
    };
    let _permit = filter_permit(&state, conditions.filter.as_ref()).await?;
    let _slot = state.read_slot().await?;
    require_session(&state, id).await?;
    Ok(Json(
        state
            .storage
            .list_flows(id, page, sort, conditions.as_condition())
            .await?,
    ))
}

/// Get one flow with its full statistics.
#[utoipa::path(
    get,
    path = "/api/v1/captures/{id}/flows/{flow_id}",
    tag = "flows",
    params(
        ("id" = i64, Path, description = "Capture ID"),
        ("flow_id" = i64, Path, description = "Flow ID within the capture"),
    ),
    responses(
        (status = 200, description = "The flow", body = FlowDetail),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn get_flow(
    State(state): State<AppState>,
    ApiPath((id, flow_id)): ApiPath<(i64, i64)>,
) -> Result<Json<FlowDetail>, ApiError> {
    let _slot = state.read_slot().await?;
    state
        .storage
        .get_flow(id, flow_id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("flow"))
}

/// List DNS messages of a capture.
#[utoipa::path(
    get,
    path = "/api/v1/captures/{id}/dns",
    tag = "application",
    params(("id" = i64, Path, description = "Capture ID"), PageParams),
    responses(
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 200, description = "A page of DNS events", body = Paged<DnsEvent>),
        (status = 404, description = "Capture not found", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn list_dns(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<i64>,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<DnsEvent>>, ApiError> {
    let _slot = state.read_slot().await?;
    let page = page_of(params.page, params.per_page)?;
    require_session(&state, id).await?;
    Ok(Json(state.storage.list_dns_events(id, page).await?))
}

/// List HTTP request and response metadata of a capture.
#[utoipa::path(
    get,
    path = "/api/v1/captures/{id}/http",
    tag = "application",
    params(("id" = i64, Path, description = "Capture ID"), PageParams),
    responses(
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 200, description = "A page of HTTP events", body = Paged<HttpEvent>),
        (status = 404, description = "Capture not found", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn list_http(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<i64>,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<HttpEvent>>, ApiError> {
    let _slot = state.read_slot().await?;
    let page = page_of(params.page, params.per_page)?;
    require_session(&state, id).await?;
    Ok(Json(state.storage.list_http_events(id, page).await?))
}

/// List visible TLS handshake metadata of a capture. Nothing is decrypted.
#[utoipa::path(
    get,
    path = "/api/v1/captures/{id}/tls",
    tag = "application",
    params(("id" = i64, Path, description = "Capture ID"), PageParams),
    responses(
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 200, description = "A page of TLS handshake events", body = Paged<TlsEvent>),
        (status = 404, description = "Capture not found", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn list_tls(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<i64>,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<TlsEvent>>, ApiError> {
    let _slot = state.read_slot().await?;
    let page = page_of(params.page, params.per_page)?;
    require_session(&state, id).await?;
    Ok(Json(state.storage.list_tls_events(id, page).await?))
}

/// List a capture's alerts.
///
/// Alerts are heuristic indicators that deserve review, not proof of
/// compromise. Each carries its evidence, its uncertainty and likely false
/// positives.
#[utoipa::path(
    get,
    path = "/api/v1/captures/{id}/alerts",
    tag = "alerts",
    params(("id" = i64, Path, description = "Capture ID"), AlertListParams),
    responses(
        (status = 200, description = "A page of alerts", body = Paged<AlertRow>),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 404, description = "Capture not found", body = ErrorResponse),
    )
)]
pub async fn list_alerts(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<i64>,
    ApiQuery(params): ApiQuery<AlertListParams>,
) -> Result<Json<Paged<AlertRow>>, ApiError> {
    let page = page_of(params.page, params.per_page)?;
    let sort = alert_sort(params.sort.as_deref())?;
    let filter = alert_filter(&params)?;
    let _slot = state.read_slot().await?;
    require_session(&state, id).await?;
    Ok(Json(
        state.storage.list_alerts(id, page, sort, &filter).await?,
    ))
}

/// Get one alert with its evidence.
#[utoipa::path(
    get,
    path = "/api/v1/captures/{id}/alerts/{alert_id}",
    tag = "alerts",
    params(
        ("id" = i64, Path, description = "Capture ID"),
        ("alert_id" = i64, Path, description = "Alert ID within the capture"),
    ),
    responses(
        (status = 200, description = "The alert", body = AlertRow),
        (status = 404, description = "Not found", body = ErrorResponse),
    )
)]
pub async fn get_alert(
    State(state): State<AppState>,
    ApiPath((id, alert_id)): ApiPath<(i64, i64)>,
) -> Result<Json<AlertRow>, ApiError> {
    let _slot = state.read_slot().await?;
    state
        .storage
        .get_alert(id, alert_id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("alert"))
}

/// Change an alert's triage status. Nothing else about an alert can change.
#[utoipa::path(
    patch,
    path = "/api/v1/captures/{id}/alerts/{alert_id}",
    tag = "alerts",
    params(
        ("id" = i64, Path, description = "Capture ID"),
        ("alert_id" = i64, Path, description = "Alert ID within the capture"),
    ),
    request_body = AlertUpdate,
    responses(
        (status = 200, description = "The updated alert", body = AlertRow),
        (status = 400, description = "Invalid status", body = ErrorResponse),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the analyst role, or a missing CSRF token", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 422, description = "Malformed body", body = ErrorResponse),
    )
)]
pub async fn update_alert(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    analyst: Authorized<Analyst>,
    ApiPath((id, alert_id)): ApiPath<(i64, i64)>,
    ApiJson(update): ApiJson<AlertUpdate>,
) -> Result<Json<AlertRow>, ApiError> {
    let status = alert_status(&update.status)?;
    let alert = {
        let _slot = state.read_slot().await?;
        state
            .storage
            .set_alert_status(id, alert_id, status)
            .await?
            .ok_or_else(|| ApiError::not_found("alert"))?
    };
    tracing::info!(
        session_id = id,
        alert_id,
        status = status.as_str(),
        "alert status changed"
    );
    audit::record(
        &state,
        storage::NewAuditEvent {
            client_ip,
            target_type: Some("alert"),
            target_id: Some(format!("{id}/{alert_id}")),
            details: json!({ "status": status.as_str(), "rule_id": alert.rule_id }),
            ..audit::by(analyst.user(), "alert.status_change")
        },
    )
    .await;
    Ok(Json(alert))
}

/// List the detection rules.
#[utoipa::path(
    get,
    path = "/api/v1/rules",
    tag = "alerts",
    responses((status = 200, description = "The rule catalog", body = Vec<RuleInfo>))
)]
pub async fn list_rules() -> Json<Vec<RuleInfo>> {
    Json(
        RULES
            .iter()
            .map(|rule| RuleInfo {
                id: rule.id,
                name: rule.name,
                severity: rule.severity.as_str(),
                description: rule.description,
                uncertainty: rule.uncertainty,
                likely_false_positives: rule.likely_false_positives.to_vec(),
                mitre_attack: rule.mitre_attack.to_vec(),
                nature: NATURE,
            })
            .collect(),
    )
}

/// Check a display filter without running it.
#[utoipa::path(
    get,
    path = "/api/v1/filters/validate",
    tag = "filters",
    params(FilterParams),
    responses(
        (status = 200, description = "The filter is valid", body = FilterCheck),
        (status = 400, description = "Invalid filter, with the position of the problem", body = ErrorResponse),
    )
)]
pub async fn validate_filter(
    ApiQuery(params): ApiQuery<FilterParams>,
) -> Result<Json<FilterCheck>, ApiError> {
    let target = target_of(&params.target)?;
    let filter = compile(&params.filter, target).map_err(|err| ApiError::filter(&err))?;
    Ok(Json(FilterCheck {
        valid: true,
        target: if target == Target::Packets {
            "packets"
        } else {
            "flows"
        },
        parameters: filter.param_count(),
        normalized: filter.normalized,
    }))
}

/// List the fields a filter may use.
#[utoipa::path(
    get,
    path = "/api/v1/filters/fields",
    tag = "filters",
    params(TargetParams),
    responses(
        (status = 200, description = "Filterable fields", body = Vec<FilterField>),
        (status = 400, description = "Invalid target", body = ErrorResponse),
    )
)]
pub async fn filter_fields(
    ApiQuery(params): ApiQuery<TargetParams>,
) -> Result<Json<Vec<FilterField>>, ApiError> {
    let target = target_of(&params.target)?;
    let fields = filter_language::fields(target)
        .iter()
        .map(|field| {
            let (values, max) = match field.field_type {
                FieldType::Enum(values) => (Some(values.to_vec()), None),
                FieldType::UInt { max } => (None, Some(max)),
                _ => (None, None),
            };
            FilterField {
                name: field.name,
                field_type: field.field_type.name(),
                description: field.description,
                operators: filter_language::operators(field.field_type).to_vec(),
                values,
                max,
            }
        })
        .collect();
    Ok(Json(fields))
}

/// Get retention settings.
#[utoipa::path(
    get,
    path = "/api/v1/settings/retention",
    tag = "settings",
    responses(
        (status = 200, description = "Current settings", body = RetentionSettings),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn get_retention(
    State(state): State<AppState>,
) -> Result<Json<RetentionSettings>, ApiError> {
    let _slot = state.read_slot().await?;
    Ok(Json(state.storage.retention().await?))
}

/// Replace retention settings.
#[utoipa::path(
    put,
    path = "/api/v1/settings/retention",
    tag = "settings",
    request_body = RetentionSettings,
    responses(
        (status = 200, description = "Updated settings", body = RetentionSettings),
        (status = 400, description = "Out of range", body = ErrorResponse),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the admin role, or a missing CSRF token", body = ErrorResponse),
        (status = 422, description = "Malformed body", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn put_retention(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    admin: Authorized<Admin>,
    ApiJson(settings): ApiJson<RetentionSettings>,
) -> Result<Json<RetentionSettings>, ApiError> {
    let slot = state.read_slot().await?;
    if !(1..=3650).contains(&settings.session_ttl_days) {
        return Err(ApiError::bad_request(
            "invalid_ttl",
            "session_ttl_days must be between 1 and 3650",
        ));
    }
    if !(0..=1_000_000).contains(&settings.max_packets_stored) {
        return Err(ApiError::bad_request(
            "invalid_max_packets",
            "max_packets_stored must be between 0 and 1000000",
        ));
    }
    let updated = state.storage.update_retention(settings).await?;
    drop(slot);
    tracing::info!(
        session_ttl_days = updated.session_ttl_days,
        max_packets_stored = updated.max_packets_stored,
        "retention settings updated"
    );
    audit::record(
        &state,
        storage::NewAuditEvent {
            client_ip,
            target_type: Some("settings"),
            target_id: Some("retention".to_owned()),
            details: json!({
                "session_ttl_days": updated.session_ttl_days,
                "max_packets_stored": updated.max_packets_stored,
            }),
            ..audit::by(admin.user(), "settings.retention_change")
        },
    )
    .await;
    Ok(Json(updated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_are_validated() {
        assert!(page_of(None, None).is_ok());
        assert_eq!(page_of(Some(0), None).unwrap_err().code, "invalid_page");
        assert_eq!(
            page_of(Some(1_000_001), None).unwrap_err().code,
            "invalid_page"
        );
        assert_eq!(page_of(None, Some(0)).unwrap_err().code, "invalid_per_page");
        assert_eq!(
            page_of(None, Some(501)).unwrap_err().code,
            "invalid_per_page"
        );
    }

    #[test]
    fn sorts_are_a_fixed_set() {
        assert!(packet_sort(Some("index; DROP TABLE packets")).is_err());
        assert_eq!(flow_sort(Some("-bytes")).unwrap(), FlowSort::BytesDesc);
        assert_eq!(session_sort(None).unwrap(), SessionSort::NewestFirst);
        assert_eq!(alert_sort(Some("time")).unwrap(), AlertSort::Time);
        assert!(alert_sort(Some("severity_rank")).is_err());
    }

    #[test]
    fn alert_filters_are_a_fixed_set() {
        let params =
            |severity: Option<&str>, status: Option<&str>, rule: Option<&str>| AlertListParams {
                page: None,
                per_page: None,
                sort: None,
                severity: severity.map(str::to_owned),
                status: status.map(str::to_owned),
                rule: rule.map(str::to_owned),
            };
        let ok = alert_filter(&params(
            Some("high"),
            Some("false_positive"),
            Some("FS-BEACON"),
        ))
        .unwrap();
        assert_eq!(ok.severity.as_deref(), Some("high"));
        assert_eq!(ok.status.as_deref(), Some("false_positive"));
        assert_eq!(ok.rule_id.as_deref(), Some("FS-BEACON"));
        for (bad, code) in [
            (params(Some("HIGH"), None, None), "invalid_severity"),
            (params(None, Some("closed"), None), "invalid_status"),
            (params(None, None, Some("FS-NOPE' OR 1=1")), "invalid_rule"),
        ] {
            assert_eq!(alert_filter(&bad).unwrap_err().code, code);
        }
    }

    #[test]
    fn upload_headers_are_checked() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            check_upload_headers(&headers, 10).unwrap_err().code,
            "unsupported_media_type"
        );
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data"),
        );
        assert!(check_upload_headers(&headers, 10).is_err());
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/Octet-Stream; charset=binary"),
        );
        assert!(check_upload_headers(&headers, 10).is_ok());
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("11"));
        assert_eq!(
            check_upload_headers(&headers, 10).unwrap_err().code,
            "upload_too_large"
        );
    }
}
