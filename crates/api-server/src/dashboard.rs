//! Serves the built dashboard and sets security headers on every response.

use std::path::Path;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::error;

/// Content Security Policy for the dashboard: only same-origin scripts,
/// styles, images and API calls; no framing, plugins or inline scripts.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
     object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The built dashboard in `dir`, for every path the API does not claim:
///
/// - `/assets/...` (file names that change with their content): cached for
///   a year; a missing asset is `404`, not the page, so a stale page fails
///   visibly instead of loading HTML as a script.
/// - Paths under `/api/`: the JSON `404`, never the page.
/// - Other files in `dir` (`favicon.svg`), and `index.html` for every other
///   path, so the dashboard's client-side routes load directly. These are
///   revalidated on every load (`no-cache`), so an upgrade takes effect at
///   once.
///
/// Only GET and HEAD are served.
pub fn router(dir: &Path) -> Router {
    let pages = Router::new()
        .fallback_service(
            ServeDir::new(dir)
                .append_index_html_on_directories(true)
                .fallback(ServeFile::new(dir.join("index.html"))),
        )
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
        .layer(middleware::from_fn(not_under_api));
    Router::new()
        .nest_service("/assets", ServeDir::new(dir.join("assets")))
        .layer(middleware::from_fn(cache_assets))
        .fallback_service(pages)
}

async fn not_under_api(request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if path == "/api" || path.starts_with("/api/") {
        return error::not_found().await.into_response();
    }
    next.run(request).await
}

async fn cache_assets(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let cache = if matches!(response.status(), StatusCode::OK | StatusCode::NOT_MODIFIED) {
        "public, max-age=31536000, immutable"
    } else {
        "no-store"
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    response
}

/// Adds the security headers to every response that does not set them.
pub fn with_security_headers(router: Router) -> Router {
    let headers: [(HeaderName, &'static str); 5] = [
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
    ];
    headers.into_iter().fold(router, |router, (name, value)| {
        router.layer(SetResponseHeaderLayer::if_not_present(
            name,
            HeaderValue::from_static(value),
        ))
    })
}
