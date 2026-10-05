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

/// `Cache-Control: no-store` on API and probe responses, errors included
/// (also those refused before routing): they hold capture metadata or live
/// state, so browsers and proxies must not keep them.
async fn no_store(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path();
    let api = path == "/api" || path.starts_with("/api/") || matches!(path, "/health" | "/ready");
    let mut response = next.run(request).await;
    if api {
        response
            .headers_mut()
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-store"));
    }
    response
}

/// HSTS when the server is reached through HTTPS: one year, subdomains
/// excluded (the server cannot know whether they all use HTTPS).
pub const STRICT_TRANSPORT_SECURITY: &str = "max-age=31536000";

/// Adds the security headers to every response that does not set them;
/// with `https` (secure cookies, so HTTPS in front), also HSTS.
pub fn with_security_headers(router: Router, https: bool) -> Router {
    let router = router.layer(axum::middleware::from_fn(no_store));
    let router = if https {
        router.layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(STRICT_TRANSPORT_SECURITY),
        ))
    } else {
        router
    };
    let headers: [(HeaderName, &'static str); 7] = [
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("permissions-policy"),
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        ),
    ];
    headers.into_iter().fold(router, |router, (name, value)| {
        router.layer(SetResponseHeaderLayer::if_not_present(
            name,
            HeaderValue::from_static(value),
        ))
    })
}
