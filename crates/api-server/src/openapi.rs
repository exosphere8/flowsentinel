//! OpenAPI 3.1 description, generated from the handler annotations and
//! served at `GET /api/v1/openapi.json`.

use utoipa::OpenApi;

use crate::error::{ErrorBody, ErrorResponse};
use crate::routes;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "FlowSentinel API",
        description = "Metadata-only analysis of authorized packet captures. \
                       No endpoint returns packet payloads, and TLS is never decrypted.",
        license(name = "MIT"),
    ),
    paths(
        routes::import_capture,
        routes::list_captures,
        routes::get_capture,
        routes::delete_capture,
        routes::list_packets,
        routes::get_packet,
        routes::list_flows,
        routes::get_flow,
        routes::list_dns,
        routes::list_http,
        routes::list_tls,
        routes::get_retention,
        routes::put_retention,
    ),
    components(schemas(
        ErrorBody,
        ErrorResponse,
        storage::Session,
        storage::SessionDetail,
        storage::PacketSummary,
        storage::PacketDetail,
        storage::FlowSummaryRow,
        storage::FlowDetail,
        storage::DnsEvent,
        storage::HttpEvent,
        storage::TlsEvent,
        storage::RetentionSettings,
    )),
    tags(
        (name = "captures", description = "Import, list and delete captures"),
        (name = "packets", description = "Per-packet metadata"),
        (name = "flows", description = "Bidirectional flows"),
        (name = "application", description = "DNS, HTTP and TLS handshake metadata"),
        (name = "settings", description = "Retention settings"),
    )
)]
pub struct ApiDoc;
