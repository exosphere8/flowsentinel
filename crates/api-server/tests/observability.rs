//! Request IDs, access metrics, readiness and the hardened response headers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::time::Duration;

use api_server::auth::{AuthConfig, COOKIE_NAME, CSRF_HEADER, SessionToken};
use api_server::host::HostPolicy;
use api_server::observability::{GaugeSource, metrics_router};
use api_server::{ApiConfig, AppState, app_with_state};
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use capture::CaptureLimits;
use detection_engine::DetectionConfig;
use flow_engine::FlowConfig;
use storage::testing::TestDatabase;
use tower::ServiceExt;

const UNUSED_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$dW51c2VkLXNhbHQ$dW51c2VkLWhhc2g";

fn config(upload_dir: &std::path::Path, secure_cookies: bool) -> ApiConfig {
    ApiConfig {
        max_upload_bytes: 1024 * 1024,
        upload_dir: upload_dir.to_owned(),
        capture_limits: CaptureLimits::default(),
        flow_config: FlowConfig::default(),
        host_policy: HostPolicy::default_for("127.0.0.1:8080".parse().unwrap()),
        detection: DetectionConfig::default(),
        dashboard_dir: None,
        auth: AuthConfig {
            secure_cookies,
            ..AuthConfig::default()
        },
        live: api_server::Config::default().live(),
    }
}

async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = app_with_state(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn every_response_has_a_request_id_and_hardened_headers() {
    let Some(db) = TestDatabase::create("obs_headers").await else {
        return;
    };
    let uploads = tempfile::tempdir().unwrap();
    let state = AppState::new(db.storage.clone(), config(uploads.path(), false), 1);
    let user = db
        .storage
        .create_user("root", UNUSED_HASH, storage::Role::Admin)
        .await
        .unwrap()
        .unwrap();
    let token = SessionToken::generate().unwrap();
    db.storage
        .create_auth_session(
            user.id,
            &token.digest(),
            Duration::from_secs(600),
            10,
            UNUSED_HASH,
        )
        .await
        .unwrap()
        .unwrap();
    let signed = |uri: &str| {
        Request::get(uri)
            .header(header::COOKIE, format!("{COOKIE_NAME}={}", token.to_hex()))
            .header(CSRF_HEADER, token.csrf_token())
            .body(Body::empty())
            .unwrap()
    };

    let mut ids = Vec::new();
    for request in [
        get("/health"),
        get("/api/v1/captures"),
        signed("/api/v1/captures/7"),
        signed("/api/v1/captures"),
        Request::get("/api/v1/captures")
            .header(header::HOST, "evil.example")
            .body(Body::empty())
            .unwrap(),
    ] {
        let uri = request.uri().clone();
        let (status, headers, _) = send(&state, request).await;
        let id = headers["x-request-id"].to_str().unwrap().to_owned();
        assert_eq!(id.len(), 32, "{uri} {status}");
        ids.push(id);
        assert_eq!(
            headers["cross-origin-resource-policy"], "same-origin",
            "{uri}"
        );
        assert!(
            headers["permissions-policy"]
                .to_str()
                .unwrap()
                .contains("camera=()")
        );
        assert!(headers.get(header::STRICT_TRANSPORT_SECURITY).is_none());
        // No CORS: nothing is shared with other origins.
        assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 5, "request IDs are unique");

    // API responses are never cached.
    let (_, headers, _) = send(&state, signed("/api/v1/captures")).await;
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    // A plain client request ID is kept; anything else is replaced.
    let (_, headers, _) = send(
        &state,
        Request::get("/health")
            .header("x-request-id", "trace-42.abc")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(headers["x-request-id"], "trace-42.abc");
    let (_, headers, _) = send(
        &state,
        Request::get("/health")
            .header("x-request-id", "x".repeat(65))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(headers["x-request-id"].len(), 32);
    // A CORS preflight gets no permission.
    let (status, headers, _) = send(
        &state,
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/api/v1/captures")
            .header(header::ORIGIN, "https://other.example")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(status.is_client_error(), "{status}");
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

    // Responses made outside a route keep a precise label, and API paths
    // are never cached even when refused before routing.
    let signed_with = |method: Method, uri: &str, origin: Option<&str>| {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::COOKIE, format!("{COOKIE_NAME}={}", token.to_hex()))
            .header(CSRF_HEADER, token.csrf_token());
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        request.body(Body::empty()).unwrap()
    };
    let (status, _, _) = send(
        &state,
        signed_with(Method::DELETE, "/api/v1/overview", None),
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, _, _) = send(
        &state,
        signed_with(
            Method::POST,
            "/api/v1/auth/logout",
            Some("https://evil.example"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for uri in ["/api/v1/captures", "/ready"] {
        let (status, headers, _) = send(
            &state,
            Request::get(uri)
                .header(header::HOST, "evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        if uri.starts_with("/api") {
            assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
        }
        assert_eq!(headers[header::CACHE_CONTROL], "no-store", "{uri}");
    }
    // A request the client abandons is still logged and counted, as 499.
    let all = u32::try_from(state.filter_slots.available_permits()).unwrap();
    let held = Arc::clone(&state.filter_slots)
        .acquire_many_owned(all)
        .await
        .unwrap();
    let abandoned = app_with_state(state.clone()).oneshot(signed_with(
        Method::GET,
        "/api/v1/captures/9/flows?filter=udp",
        None,
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), abandoned)
            .await
            .is_err()
    );
    drop(held);

    // Metrics count route templates, never raw paths.
    let gauges: GaugeSource = Arc::new(|| vec![("flowsentinel_test", "Test.", 1.0)]);
    let metrics = metrics_router(Arc::clone(&state.metrics), gauges);
    let response = metrics.oneshot(get("/metrics")).await.unwrap();
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let text = String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(text.contains(
        "flowsentinel_http_requests_total{method=\"GET\",route=\"/api/v1/captures/{id}\",status=\"404\"} 1"
    ));
    assert!(text.contains(
        "flowsentinel_http_requests_total{method=\"GET\",route=\"/api/v1/captures\",status=\"401\"} 1"
    ));
    assert!(text.contains("route=\"/health\""));
    for line in [
        "{method=\"DELETE\",route=\"method_not_allowed\",status=\"405\"} 1",
        "{method=\"POST\",route=\"/api/v1/auth/logout\",status=\"403\"} 1",
        "{method=\"GET\",route=\"misdirected\",status=\"421\"} 2",
        "{method=\"GET\",route=\"/api/v1/captures/{id}/flows\",status=\"499\"} 1",
    ] {
        assert!(
            text.contains(&format!("flowsentinel_http_requests_total{line}")),
            "{line}\n{text}"
        );
    }
    assert!(!text.contains("/api/v1/captures/7"));
    assert!(text.contains("flowsentinel_test 1"));
    db.drop_database().await;
}

#[tokio::test]
async fn https_deployments_get_hsts() {
    let Some(db) = TestDatabase::create("obs_hsts").await else {
        return;
    };
    let uploads = tempfile::tempdir().unwrap();
    let state = AppState::new(db.storage.clone(), config(uploads.path(), true), 1);
    let (_, headers, _) = send(&state, get("/health")).await;
    assert_eq!(
        headers[header::STRICT_TRANSPORT_SECURITY],
        "max-age=31536000"
    );
    db.drop_database().await;
}

#[tokio::test]
async fn readiness_follows_the_database() {
    let Some(db) = TestDatabase::create("obs_ready").await else {
        return;
    };
    let uploads = tempfile::tempdir().unwrap();
    let state = AppState::new(db.storage.clone(), config(uploads.path(), false), 1);
    let (status, _, body) = send(
        &state,
        Request::get("/ready")
            .header(header::HOST, "10.0.0.5:8080")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"status":"ready","database":"ok"}"#);
    db.drop_database().await;

    // A database nobody listens on.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(500))
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
        .unwrap();
    let down = AppState::new(
        storage::Storage::from_pool(pool),
        config(uploads.path(), false),
        1,
    );
    let (status, _, body) = send(&down, get("/ready")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, r#"{"status":"not_ready","database":"unavailable"}"#);
    // Liveness does not depend on the database.
    let (status, _, _) = send(&down, get("/health")).await;
    assert_eq!(status, StatusCode::OK);

    // One check answers for a second: with the database down, a check
    // waits out the connection timeout (0.5 s here), and the probes right
    // after it, concurrent or not, answer at once from that check.
    let app = app_with_state(down.clone());
    let started = std::time::Instant::now();
    let first = app.clone().oneshot(get("/ready")).await.unwrap().status();
    let checked = started.elapsed();
    assert_eq!(first, StatusCode::SERVICE_UNAVAILABLE);
    assert!(checked >= Duration::from_millis(400), "{checked:?}");
    let started = std::time::Instant::now();
    let probes = (0..20).map(|_| {
        let app = app.clone();
        async move { app.oneshot(get("/ready")).await.unwrap().status() }
    });
    let statuses = futures_util::future::join_all(probes).await;
    assert!(
        statuses
            .iter()
            .all(|s| *s == StatusCode::SERVICE_UNAVAILABLE)
    );
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "{:?}",
        started.elapsed()
    );
}
