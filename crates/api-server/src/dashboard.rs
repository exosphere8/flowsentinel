//! Serves the built dashboard and sets security headers on every response.

use std::path::Path;

use axum::Router;
use axum::http::{HeaderName, HeaderValue, header};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

/// Content Security Policy for the dashboard: only same-origin scripts,
/// styles, images and API calls; no framing, plugins or inline scripts.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
     object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// Static files from `dir`. Paths without a file get `index.html`, so the
/// dashboard's client-side routes load directly. Only GET and HEAD are
/// served.
pub fn service(dir: &Path) -> ServeDir<ServeFile> {
    ServeDir::new(dir)
        .append_index_html_on_directories(true)
        .fallback(ServeFile::new(dir.join("index.html")))
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
