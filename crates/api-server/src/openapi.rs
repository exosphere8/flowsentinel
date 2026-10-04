//! OpenAPI 3.1 description, generated from the handler annotations and
//! served at `GET /api/v1/openapi.json`.

use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::auth::COOKIE_NAME;
use crate::error::{ErrorBody, ErrorResponse};
use crate::{accounts, routes};

/// Declares the session cookie as the API's authentication.
struct SessionCookie;

impl Modify for SessionCookie {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        let mut cookie = ApiKeyValue::new(COOKIE_NAME);
        cookie.description = Some(
            "Session cookie set by POST /auth/login (named __Host-flowsentinel_session when \
             FLOWSENTINEL_SECURE_COOKIES=true). State-changing requests must also send the \
             session's CSRF token in the X-CSRF-Token header."
                .to_owned(),
        );
        components.add_security_scheme("session", SecurityScheme::ApiKey(ApiKey::Cookie(cookie)));
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "FlowSentinel API",
        description = "Metadata-only analysis of authorized packet captures. \
                       No endpoint returns packet payloads, and TLS is never decrypted. \
                       Every endpoint except POST /auth/login needs a signed-in session; \
                       viewers read, analysts also import and triage, admins also delete, \
                       change settings, manage accounts and read the audit log.",
        license(name = "MIT"),
    ),
    modifiers(&SessionCookie),
    security(("session" = [])),
    paths(
        accounts::login,
        accounts::session,
        accounts::logout,
        accounts::change_password,
        accounts::list_users,
        accounts::create_user,
        accounts::update_user,
        accounts::delete_user,
        accounts::list_audit,
        routes::overview,
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
        routes::list_alerts,
        routes::get_alert,
        routes::update_alert,
        routes::list_rules,
        routes::validate_filter,
        routes::filter_fields,
        routes::get_retention,
        routes::put_retention,
    ),
    components(schemas(
        ErrorBody,
        ErrorResponse,
        crate::error::Position,
        routes::FilterCheck,
        routes::FilterField,
        routes::AlertUpdate,
        routes::RuleInfo,
        storage::AlertRow,
        storage::Overview,
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
        storage::Role,
        storage::User,
        storage::AuditEvent,
        storage::AuditOutcome,
        accounts::SessionInfo,
        accounts::SessionAccount,
        accounts::LoginRequest,
        accounts::PasswordChange,
        accounts::NewUser,
        accounts::UserPatch,
    )),
    tags(
        (name = "captures", description = "Import, list and delete captures"),
        (name = "packets", description = "Per-packet metadata"),
        (name = "flows", description = "Bidirectional flows"),
        (name = "application", description = "DNS, HTTP and TLS handshake metadata"),
        (name = "alerts", description = "Heuristic detections: indicators to review, not proof of compromise"),
        (name = "filters", description = "Display-filter validation and field catalog"),
        (name = "settings", description = "Retention settings"),
        (name = "auth", description = "Sign-in sessions and passwords"),
        (name = "users", description = "Account management (admin)"),
        (name = "audit", description = "Security audit log (admin)"),
    )
)]
pub struct ApiDoc;
