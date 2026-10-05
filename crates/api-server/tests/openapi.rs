//! The committed OpenAPI document (`docs/openapi.json`) matches the server.
//! The dashboard generates its API types from that file.
//!
//! Regenerate it with `FLOWSENTINEL_UPDATE_OPENAPI=1 cargo test -p api-server --test openapi`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;

use api_server::openapi::ApiDoc;
use utoipa::OpenApi;

#[test]
fn committed_openapi_document_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/openapi.json");
    let mut current = serde_json::to_string_pretty(&ApiDoc::openapi()).unwrap();
    current.push('\n');
    if std::env::var_os("FLOWSENTINEL_UPDATE_OPENAPI").is_some() {
        std::fs::write(&path, &current).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == current,
        "docs/openapi.json is out of date; run \
         FLOWSENTINEL_UPDATE_OPENAPI=1 cargo test -p api-server --test openapi"
    );
}
