//! The security audit log: who did what, when, from where, and whether it
//! was allowed. Events go to the `audit_events` table and, as JSON log lines
//! with target `audit`, to the server log. They never hold passwords,
//! tokens or packet data.

use axum::extract::OriginalUri;
use axum::http::request::Parts;
use storage::NewAuditEvent;

use crate::auth::CurrentUser;
use crate::state::AppState;

/// Longest request path kept in an event.
const MAX_PATH_CHARS: usize = 200;

/// The full request path (also inside nested routers), cut to 200
/// characters. Query strings are left out.
pub fn path_of(parts: &Parts) -> String {
    let path = parts
        .extensions
        .get::<OriginalUri>()
        .map_or_else(|| parts.uri.path(), |OriginalUri(uri)| uri.path());
    path.chars().take(MAX_PATH_CHARS).collect()
}

/// Stores an event and logs it. A storage failure is logged with the event
/// and does not fail the request, which has already happened.
pub async fn record(state: &AppState, event: NewAuditEvent) {
    tracing::info!(
        target: "audit",
        action = event.action,
        outcome = event.outcome.as_str(),
        actor = event.actor.as_deref().unwrap_or("-"),
        target_type = event.target_type.unwrap_or("-"),
        target_id = event.target_id.as_deref().unwrap_or("-"),
        client_ip = ?event.client_ip,
        details = %event.details,
        "audit event"
    );
    if let Err(err) = state.storage.record_audit(&event).await {
        tracing::error!(
            target: "audit",
            action = event.action,
            error = %err,
            "could not store an audit event"
        );
    }
}

/// An event performed by a signed-in account.
pub fn by(user: &CurrentUser, action: &'static str) -> NewAuditEvent {
    NewAuditEvent {
        actor_id: Some(user.user_id),
        actor: Some(user.username.clone()),
        action,
        outcome: storage::AuditOutcome::Success,
        target_type: None,
        target_id: None,
        client_ip: None,
        details: serde_json::Value::Object(serde_json::Map::new()),
    }
}
