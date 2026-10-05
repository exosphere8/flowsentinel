//! OpenTelemetry export to a local fake OTLP/HTTP collector (feature `otel`).
#![cfg(feature = "otel")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::routing::post;
use tracing_subscriber::layer::SubscriberExt;

#[tokio::test(flavor = "multi_thread")]
async fn spans_reach_an_otlp_collector() {
    let received = Arc::new(AtomicUsize::new(0));
    let kinds = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let collector = Router::new().route(
        "/v1/traces",
        post({
            let received = Arc::clone(&received);
            let kinds = Arc::clone(&kinds);
            move |headers: HeaderMap, body: Bytes| async move {
                received.fetch_add(body.len(), Ordering::Relaxed);
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
            let span = tracing::info_span!("request", request_id = "abc", method = "GET");
            span.in_scope(|| tracing::info!("inside"));
        });
        provider.shutdown().unwrap();
    })
    .await
    .unwrap();

    assert!(received.load(Ordering::Relaxed) > 0, "no spans exported");
    assert_eq!(
        kinds.lock().unwrap().first().map(String::as_str),
        Some("application/x-protobuf")
    );
}
