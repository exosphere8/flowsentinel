//! Structured API errors: `{"error": {"code": "...", "message": "..."}}`.
//!
//! Messages are written for clients and never include SQL, file paths,
//! stack traces or packet data. Internal causes are logged instead.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ErrorBody {
    /// Stable machine-readable code, for example `not_found`.
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
    /// For filter errors: the byte range `[start, end)` of the problem in
    /// the filter text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<Position>,
}

/// A byte range in a request value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct Position {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

/// Longest client-supplied detail echoed in an error message.
const MAX_DETAIL_CHARS: usize = 200;

/// An error returned to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub position: Option<Position>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        let mut message: String = message.into();
        if let Some((cut, _)) = message.char_indices().nth(MAX_DETAIL_CHARS) {
            message.truncate(cut);
            message.push_str("...");
        }
        Self {
            status,
            code,
            message,
            position: None,
        }
    }

    /// An invalid display filter, pointing at the problem when possible.
    pub fn filter(err: &filter_language::FilterError) -> Self {
        let mut api = Self::bad_request(err.code(), format!("invalid filter: {err}"));
        api.position = err.span().map(|span| Position {
            start: span.start,
            end: span.end,
        });
        api
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn not_found(what: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("{what} not found"),
        )
    }

    /// A server-side failure. The cause is logged, not returned.
    pub fn internal(context: &'static str, cause: &dyn std::fmt::Display) -> Self {
        tracing::error!(context, error = %cause, "request failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the server could not complete the request",
        )
    }

    pub fn unavailable(cause: &dyn std::fmt::Display) -> Self {
        tracing::error!(error = %cause, "database unavailable");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            "the database is unavailable; try again later",
        )
    }
}

impl From<storage::StorageError> for ApiError {
    fn from(err: storage::StorageError) -> Self {
        match &err {
            storage::StorageError::Connection(_) => Self::unavailable(&err),
            storage::StorageError::QueryTimeout => {
                tracing::warn!("list query cancelled at the time limit");
                Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "query_timeout",
                    "the query took longer than the time limit; narrow the filter and try again",
                )
            }
            _ => Self::internal("storage", &err),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorResponse {
            error: ErrorBody {
                code: self.code.to_owned(),
                message: self.message,
                position: self.position,
            },
        };
        (self.status, Json(body)).into_response()
    }
}

/// Fallback for unknown routes.
pub async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such endpoint")
}

/// Fallback for known routes called with the wrong method.
pub async fn method_not_allowed() -> ApiError {
    ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "this endpoint does not support the request method",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_timeouts_are_reported_as_such() {
        let err = ApiError::from(storage::StorageError::QueryTimeout);
        assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.code, "query_timeout");
    }

    #[test]
    fn long_messages_are_cut() {
        let err = ApiError::bad_request("x", "a".repeat(1000));
        assert_eq!(err.message.chars().count(), MAX_DETAIL_CHARS + 3);
    }
}
