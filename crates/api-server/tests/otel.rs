//! OpenTelemetry export to a local fake OTLP/HTTP collector (feature `otel`).
#![cfg(feature = "otel")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::routing::post;
use tracing_subscriber::layer::SubscriberExt;

#[tokio::test(flavor = "multi_thread")]
async fn only_request_spans_and_access_events_reach_an_otlp_collector() {
    let received = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let kinds = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let collector = Router::new().route(
        "/v1/traces",
        post({
            let received = Arc::clone(&received);
            let kinds = Arc::clone(&kinds);
            move |headers: HeaderMap, body: Bytes| async move {
                received.lock().unwrap().extend_from_slice(&body);
                if let Some(kind) = headers.get("content-type") {
                    kinds
                        .lock()
                        .unwrap()
                        .push(kind.to_str().unwrap().to_owned());
                }
                ""
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, collector).await });

    let endpoint = format!("http://{addr}/v1/traces");
    // The exporter's HTTP client blocks; build, use and flush it off the
    // async runtime.
    tokio::task::spawn_blocking(move || {
        let (layer, provider) = api_server::telemetry::otel::layer(Some(&endpoint)).unwrap();
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::error_span!("request", request_id = "req-marker-1", method = "GET");
            span.in_scope(|| {
                tracing::info!(target: "access", route = "/api/v1/captures/{id}", status = 200, "request");
                // Audit details and warnings stay in the logs.
                tracing::info!(actor = "audit-actor-marker", "audit event");
                tracing::warn!(path = "/secret/path/marker", "a warning");
                tracing::info_span!("db_query", sql = "sql-marker").in_scope(|| {});
            });
        });
        provider.shutdown().unwrap();
    })
    .await
    .unwrap();

    let body = String::from_utf8_lossy(&received.lock().unwrap()).into_owned();
    assert!(!body.is_empty(), "no spans exported");
    // Protobuf keeps strings as plain UTF-8, so markers can be searched for.
    assert!(body.contains("req-marker-1"));
    assert!(body.contains("/api/v1/captures/{id}"));
    for absent in [
        "audit-actor-marker",
        "/secret/path/marker",
        "sql-marker",
        "db_query",
    ] {
        assert!(!body.contains(absent), "{absent} was exported");
    }
    assert_eq!(
        kinds.lock().unwrap().first().map(String::as_str),
        Some("application/x-protobuf")
    );
}
