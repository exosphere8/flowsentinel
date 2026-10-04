//! `/api/v1` handlers.

use std::path::PathBuf;
use std::sync::Arc;

use analysis::{AnalysisConfig, analyze_file, replay_packets};
use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use capture::{CaptureError, ErrorCategory, MonotonicClock, display_file_name};
use serde::Deserialize;
use sqlx::{Postgres, QueryBuilder};
use storage::{
    DnsEvent, FlowDetail, FlowSort, FlowSummaryRow, HttpEvent, ImportMeta, PacketDetail, PacketRow,
    PacketSort, PacketSummary, Page, Paged, RetentionSettings, Session, SessionDetail, SessionSort,
    SqlCondition, StorageError, TlsEvent,
};
use utoipa::{IntoParams, ToSchema};

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

fn page_of(page: Option<u32>, per_page: Option<u32>) -> Result<Page, ApiError> {
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

/// `flow_id = $n`.
struct FlowIs(i64);

impl SqlCondition for FlowIs {
    fn push(&self, builder: &mut QueryBuilder<'_, Postgres>) {
        builder.push("flow_id = ");
        builder.push_bind(self.0);
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
fn upload_file_name(name: &str) -> Result<String, ApiError> {
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
        (status = 429, description = "Too many imports in progress", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn import_capture(
    State(state): State<AppState>,
    ApiQuery(params): ApiQuery<UploadParams>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let file_name = upload_file_name(&params.file_name)?;
    check_upload_headers(&headers, state.config.max_upload_bytes)?;
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
    let retention = state.storage.retention().await?;
    let config = AnalysisConfig {
        limits: state.config.capture_limits,
        flows: state.config.flow_config,
        replay_packets: u64::try_from(retention.max_packets_stored).unwrap_or(0),
    };
    let path: PathBuf = received.file.path().to_owned();
    let temp_name = display_file_name(&path);

    // Pass 1: summaries and flows.
    let first_path = path.clone();
    let held = Arc::clone(&permit);
    let analysis = tokio::task::spawn_blocking(move || {
        let _held = held;
        analyze_file(&first_path, &config, &MonotonicClock::start())
    })
    .await
    .map_err(|e| ApiError::internal("analysis task", &e))?
    .map_err(|err| capture_error(&err, &temp_name, &file_name))?;

    let meta = ImportMeta {
        file_name: file_name.clone(),
        sha256: received.sha256.clone(),
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

    let session = import.commit(&state.storage).await?;
    tracing::info!(
        session_id = session.session.id,
        packets = session.session.packets_processed,
        packets_stored = session.session.packets_stored,
        flows = session.session.flows_total,
        size_bytes = received.size_bytes,
        "capture imported"
    );
    let location = HeaderValue::try_from(format!("/api/v1/captures/{}", session.session.id))
        .map_err(|e| ApiError::internal("location header", &e))?;
    Ok((
        StatusCode::CREATED,
        [(header::LOCATION, location)],
        Json(session),
    )
        .into_response())
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
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn delete_capture(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<i64>,
) -> Result<StatusCode, ApiError> {
    let _slot = state.read_slot().await?;
    if state.storage.delete_session(id).await? {
        tracing::info!(session_id = id, "capture deleted");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("capture"))
    }
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
    let _slot = state.read_slot().await?;
    let page = page_of(params.page, params.per_page)?;
    let sort = packet_sort(params.sort.as_deref())?;
    require_session(&state, id).await?;
    let flow = params.flow_id.map(FlowIs);
    let condition = flow.as_ref().map(|c| c as &dyn SqlCondition);
    Ok(Json(
        state
            .storage
            .list_packets(id, page, sort, condition)
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
    let _slot = state.read_slot().await?;
    let page = page_of(params.page, params.per_page)?;
    let sort = flow_sort(params.sort.as_deref())?;
    require_session(&state, id).await?;
    Ok(Json(state.storage.list_flows(id, page, sort, None).await?))
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
        (status = 422, description = "Malformed body", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn put_retention(
    State(state): State<AppState>,
    ApiJson(settings): ApiJson<RetentionSettings>,
) -> Result<Json<RetentionSettings>, ApiError> {
    let _slot = state.read_slot().await?;
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
    tracing::info!(
        session_ttl_days = updated.session_ttl_days,
        max_packets_stored = updated.max_packets_stored,
        "retention settings updated"
    );
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
