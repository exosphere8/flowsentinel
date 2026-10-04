//! Live capture through the API with replay sources (no network access or
//! privileges needed), against a real PostgreSQL server.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use api_server::auth::{AuthConfig, COOKIE_NAME, CSRF_HEADER, SessionToken};
use api_server::host::HostPolicy;
use api_server::live::LiveConfig;
use api_server::{ApiConfig, AppState, app_with_state};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use capture::CaptureLimits;
use detection_engine::DetectionConfig;
use flow_engine::FlowConfig;
use live_capture::{LiveLimits, ReplayFactory, SourceFactory, Unavailable};
use serde_json::{Value, json};
use storage::Role;
use storage::testing::TestDatabase;
use tower::ServiceExt;

const UNUSED_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$dW51c2VkLXNhbHQ$dW51c2VkLWhhc2g";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pcap")
        .join(name)
}

struct Harness {
    db: TestDatabase,
    state: AppState,
    uploads: tempfile::TempDir,
    admin: SessionToken,
    viewer: SessionToken,
}

struct Reply {
    status: StatusCode,
    body: Value,
}

impl Reply {
    fn code(&self) -> &str {
        self.body["error"]["code"].as_str().unwrap_or("")
    }
}

fn live_config(enabled: bool) -> LiveConfig {
    LiveConfig {
        enabled,
        interfaces: None,
        max: LiveLimits {
            max_packets: 1_000_000,
            max_bytes: 64 * 1024 * 1024,
            max_duration: Duration::from_secs(600),
            snaplen: 262_144,
        },
    }
}

impl Harness {
    async fn new(test: &str, live: LiveConfig, factory: Arc<dyn SourceFactory>) -> Option<Self> {
        let db = TestDatabase::create(test).await?;
        let uploads = tempfile::tempdir().unwrap();
        let state = AppState::new(
            db.storage.clone(),
            ApiConfig {
                max_upload_bytes: 64 * 1024 * 1024,
                upload_dir: uploads.path().to_owned(),
                capture_limits: CaptureLimits::default(),
                flow_config: FlowConfig::default(),
                host_policy: HostPolicy::default_for("127.0.0.1:8080".parse().unwrap()),
                detection: DetectionConfig::default(),
                dashboard_dir: None,
                auth: AuthConfig::default(),
                live,
            },
            1,
        )
        .with_live_factory(factory);
        let mut tokens = Vec::new();
        for (name, role) in [("root", Role::Admin), ("vic", Role::Viewer)] {
            let user = db
                .storage
                .create_user(name, UNUSED_HASH, role)
                .await
                .unwrap()
                .unwrap();
            let token = SessionToken::generate().unwrap();
            db.storage
                .create_auth_session(
                    user.id,
                    &token.digest(),
                    Duration::from_secs(3600),
                    10,
                    UNUSED_HASH,
                )
                .await
                .unwrap()
                .unwrap();
            tokens.push(token);
        }
        let viewer = tokens.pop().unwrap();
        let admin = tokens.pop().unwrap();
        Some(Self {
            db,
            state,
            uploads,
            admin,
            viewer,
        })
    }

    fn app(&self) -> Router {
        app_with_state(self.state.clone())
    }

    async fn call(
        &self,
        as_: &SessionToken,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::COOKIE, format!("{COOKIE_NAME}={}", as_.to_hex()))
            .header(CSRF_HEADER, as_.csrf_token());
        let body = match body {
            Some(value) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .app()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        Reply { status, body }
    }

    async fn status(&self) -> Value {
        self.call(
            &self.admin,
            Method::GET,
            "/api/v1/live/captures/current",
            None,
        )
        .await
        .body
    }

    /// Polls until the capture is no longer capturing or importing.
    async fn settled(&self) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let status = self.status().await;
            let state = status["state"].as_str().unwrap().to_owned();
            if state != "capturing" && state != "importing" {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "capture did not finish: {status}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn uploads_empty(&self) -> bool {
        std::fs::read_dir(self.uploads.path())
            .unwrap()
            .next()
            .is_none()
    }

    async fn audit(&self, action: &str) -> Vec<Value> {
        self.db
            .storage
            .list_audit(
                storage::Page::new(1, 100),
                &storage::AuditFilter {
                    action: Some(action.to_owned()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .collect()
    }
}

fn replay(repeats: u32, pace: Option<Duration>) -> Arc<dyn SourceFactory> {
    Arc::new(ReplayFactory {
        interface: "replay0".to_owned(),
        path: fixture("detect-mixed.pcap"),
        repeats,
        pace,
    })
}

fn start_body() -> Value {
    json!({ "interface": "replay0", "authorized": true })
}

#[tokio::test]
async fn a_live_capture_is_imported_as_metadata() {
    let Some(h) = Harness::new("live_import", live_config(true), replay(0, None)).await else {
        return;
    };
    let interfaces = h
        .call(&h.admin, Method::GET, "/api/v1/live/interfaces", None)
        .await;
    assert_eq!(interfaces.status, StatusCode::OK);
    assert_eq!(interfaces.body[0]["name"], "replay0");
    assert_eq!(h.status().await["state"], "idle");

    let started = h
        .call(
            &h.admin,
            Method::POST,
            "/api/v1/live/captures",
            Some(start_body()),
        )
        .await;
    assert_eq!(started.status, StatusCode::ACCEPTED, "{}", started.body);
    assert_eq!(started.body["promiscuous"], false);
    assert_eq!(started.body["limits"]["max_seconds"], 60);
    assert_eq!(started.body["started_by"], "root");

    let done = h.settled().await;
    assert_eq!(done["state"], "finished", "{done}");
    assert_eq!(done["stop_reason"], "source_ended");
    assert_eq!(done["packets_written"], 138);
    assert_eq!(done["dropped_backpressure"], 0);
    let id = done["capture_id"].as_i64().unwrap();
    let capture = h
        .call(
            &h.admin,
            Method::GET,
            &format!("/api/v1/captures/{id}"),
            None,
        )
        .await;
    assert_eq!(capture.body["source"], "live");
    assert_eq!(capture.body["packets_processed"], 138);
    assert_eq!(capture.body["alerts_total"], 5);
    assert!(
        capture.body["file_name"]
            .as_str()
            .unwrap()
            .starts_with("live-replay0-")
    );
    // The temporary capture file is gone.
    assert!(h.uploads_empty());

    let start = &h.audit("live.start").await[0];
    assert_eq!(start["actor"], "root");
    assert_eq!(start["target_id"], "replay0");
    assert_eq!(start["details"]["promiscuous"], false);
    let finish = &h.audit("live.finish").await[0];
    assert_eq!(finish["outcome"], "success");
    assert_eq!(finish["target_id"], id.to_string());
    h.db.drop_database().await;
}

#[tokio::test]
async fn one_capture_at_a_time_and_stopping_imports_it() {
    let Some(h) = Harness::new(
        "live_stop",
        live_config(true),
        replay(10_000, Some(Duration::from_millis(2))),
    )
    .await
    else {
        return;
    };
    let first = h
        .call(
            &h.admin,
            Method::POST,
            "/api/v1/live/captures",
            Some(start_body()),
        )
        .await;
    assert_eq!(first.status, StatusCode::ACCEPTED);
    let second = h
        .call(
            &h.admin,
            Method::POST,
            "/api/v1/live/captures",
            Some(start_body()),
        )
        .await;
    assert_eq!(
        (second.status, second.code()),
        (StatusCode::CONFLICT, "live_capture_running")
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let running = h.status().await;
    assert_eq!(running["state"], "capturing");
    assert!(
        running["packets_written"].as_u64().unwrap() > 0,
        "{running}"
    );

    let stopped = h
        .call(
            &h.admin,
            Method::POST,
            "/api/v1/live/captures/current/stop",
            None,
        )
        .await;
    assert_eq!(stopped.status, StatusCode::ACCEPTED);
    let done = h.settled().await;
    assert_eq!(done["state"], "finished", "{done}");
    assert_eq!(done["stop_reason"], "requested");
    assert!(done["capture_id"].is_i64());
    let again = h
        .call(
            &h.admin,
            Method::POST,
            "/api/v1/live/captures/current/stop",
            None,
        )
        .await;
    assert_eq!(again.code(), "no_live_capture");
    assert_eq!(h.audit("live.stop").await.len(), 1);
    assert!(h.uploads_empty());
    h.db.drop_database().await;
}

#[tokio::test]
async fn requests_are_checked_before_capturing() {
    let Some(h) = Harness::new("live_checks", live_config(true), replay(0, None)).await else {
        return;
    };
    let cases = [
        (
            json!({ "interface": "replay0", "authorized": false }),
            StatusCode::BAD_REQUEST,
            "authorization_required",
        ),
        (
            json!({ "interface": "eth9", "authorized": true }),
            StatusCode::BAD_REQUEST,
            "unknown_interface",
        ),
        (
            json!({ "interface": "replay0", "authorized": true, "max_seconds": 601 }),
            StatusCode::BAD_REQUEST,
            "invalid_limit",
        ),
        (
            json!({ "interface": "replay0", "authorized": true, "max_packets": 0 }),
            StatusCode::BAD_REQUEST,
            "invalid_limit",
        ),
        (
            json!({ "interface": "replay0", "authorized": true, "snaplen": 10 }),
            StatusCode::BAD_REQUEST,
            "invalid_limit",
        ),
        (
            json!({ "interface": "replay0", "authorized": true, "filter": "tcp\nport 80" }),
            StatusCode::BAD_REQUEST,
            "invalid_capture_filter",
        ),
        (
            json!({ "interface": "replay0" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body",
        ),
        (
            json!({ "interface": "replay0", "authorized": true, "inject": true }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body",
        ),
    ];
    for (body, status, code) in cases {
        let reply = h
            .call(
                &h.admin,
                Method::POST,
                "/api/v1/live/captures",
                Some(body.clone()),
            )
            .await;
        assert_eq!((reply.status, reply.code()), (status, code), "{body}");
    }
    assert_eq!(h.status().await["state"], "idle");

    // Admins only.
    for (method, uri) in [
        (Method::GET, "/api/v1/live/interfaces"),
        (Method::GET, "/api/v1/live/captures/current"),
        (Method::POST, "/api/v1/live/captures"),
        (Method::POST, "/api/v1/live/captures/current/stop"),
    ] {
        let reply = h.call(&h.viewer, method, uri, Some(start_body())).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{uri}");
    }
    h.db.drop_database().await;
}

#[tokio::test]
async fn live_capture_is_off_unless_enabled_and_built() {
    let Some(h) = Harness::new("live_off", live_config(false), replay(0, None)).await else {
        return;
    };
    for (method, uri) in [
        (Method::GET, "/api/v1/live/interfaces"),
        (Method::POST, "/api/v1/live/captures"),
    ] {
        let reply = h.call(&h.admin, method, uri, Some(start_body())).await;
        assert_eq!(
            (reply.status, reply.code()),
            (StatusCode::SERVICE_UNAVAILABLE, "live_capture_disabled")
        );
    }
    h.db.drop_database().await;

    let Some(h) = Harness::new("live_unbuilt", live_config(true), Arc::new(Unavailable)).await
    else {
        return;
    };
    let reply = h
        .call(&h.admin, Method::GET, "/api/v1/live/interfaces", None)
        .await;
    assert_eq!(
        (reply.status, reply.code()),
        (StatusCode::NOT_IMPLEMENTED, "live_capture_unavailable")
    );
    h.db.drop_database().await;

    // Only listed interfaces may be used.
    let mut only = live_config(true);
    only.interfaces = Some(vec!["eth0".to_owned()]);
    let Some(h) = Harness::new("live_listed", only, replay(0, None)).await else {
        return;
    };
    let listed = h
        .call(&h.admin, Method::GET, "/api/v1/live/interfaces", None)
        .await;
    assert_eq!(listed.body, json!([]));
    let reply = h
        .call(
            &h.admin,
            Method::POST,
            "/api/v1/live/captures",
            Some(start_body()),
        )
        .await;
    assert_eq!(
        (reply.status, reply.code()),
        (StatusCode::FORBIDDEN, "interface_not_allowed")
    );
    h.db.drop_database().await;
}
