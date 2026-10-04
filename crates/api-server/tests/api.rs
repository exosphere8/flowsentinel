//! `/api/v1` end to end against a real PostgreSQL server (see
//! `storage::testing` for how to enable these tests).

use std::path::{Path, PathBuf};

use std::time::Duration;

use api_server::auth::{AuthConfig, COOKIE_NAME, CSRF_HEADER, SessionToken};
use api_server::host::HostPolicy;
use api_server::{ApiConfig, AppState, app_with_state};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use capture::CaptureLimits;
use detection_engine::DetectionConfig;
use flow_engine::FlowConfig;
use serde_json::{Value, json};
use storage::testing::TestDatabase;
use tower::ServiceExt;

struct Harness {
    db: TestDatabase,
    state: AppState,
    upload_dir: tempfile::TempDir,
    /// The admin session every request sends unless it has its own cookie.
    admin: SessionToken,
}

/// A PHC string for accounts whose password is never checked in a test.
/// Tests that sign in create accounts with real hashes.
const UNUSED_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$dW51c2VkLXNhbHQ$dW51c2VkLWhhc2g";

/// Starts a session for an account directly in the database.
async fn session_for(storage: &storage::Storage, user_id: i64) -> SessionToken {
    let token = SessionToken::generate().unwrap();
    storage
        .create_auth_session(
            user_id,
            &token.digest(),
            Duration::from_secs(3600),
            10,
            UNUSED_HASH,
        )
        .await
        .unwrap()
        .unwrap();
    token
}

/// Adds a session cookie and its CSRF token to a request that has no cookie.
fn signed(mut request: Request<Body>, token: &SessionToken) -> Request<Body> {
    let headers = request.headers_mut();
    if !headers.contains_key(header::COOKIE) {
        headers.insert(
            header::COOKIE,
            format!("{COOKIE_NAME}={}", token.to_hex()).parse().unwrap(),
        );
        headers.insert(CSRF_HEADER, token.csrf_token().parse().unwrap());
    }
    request
}

impl Harness {
    async fn new(test: &str, max_upload_bytes: u64) -> Option<Self> {
        Self::build(test, max_upload_bytes, CaptureLimits::default(), None).await
    }

    async fn with_limits(
        test: &str,
        max_upload_bytes: u64,
        capture_limits: CaptureLimits,
    ) -> Option<Self> {
        Self::build(test, max_upload_bytes, capture_limits, None).await
    }

    async fn build(
        test: &str,
        max_upload_bytes: u64,
        capture_limits: CaptureLimits,
        dashboard_dir: Option<PathBuf>,
    ) -> Option<Self> {
        let db = TestDatabase::create(test).await?;
        let upload_dir = tempfile::tempdir().unwrap();
        let state = AppState::new(
            db.storage.clone(),
            ApiConfig {
                max_upload_bytes,
                upload_dir: upload_dir.path().to_owned(),
                capture_limits,
                flow_config: FlowConfig::default(),
                host_policy: HostPolicy::default_for("127.0.0.1:8080".parse().unwrap()),
                detection: DetectionConfig::default(),
                dashboard_dir,
                auth: AuthConfig::default(),
                live: api_server::Config::default().live(),
            },
            1,
        );
        let admin = db
            .storage
            .create_user("admin", UNUSED_HASH, storage::Role::Admin)
            .await
            .unwrap()
            .unwrap();
        let admin = session_for(&db.storage, admin.id).await;
        Some(Self {
            db,
            state,
            upload_dir,
            admin,
        })
    }

    fn app(&self) -> Router {
        app_with_state(self.state.clone())
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value, axum::http::HeaderMap) {
        let response = self
            .app()
            .oneshot(signed(request, &self.admin))
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| panic!("non-JSON body: {}", String::from_utf8_lossy(&bytes)))
        };
        (status, body, headers)
    }

    async fn get(&self, uri: &str) -> (StatusCode, Value) {
        let (status, body, _) = self
            .send(Request::get(uri).body(Body::empty()).unwrap())
            .await;
        (status, body)
    }

    async fn upload(
        &self,
        name: &str,
        bytes: Vec<u8>,
    ) -> (StatusCode, Value, axum::http::HeaderMap) {
        let request = Request::post(format!("/api/v1/captures?file_name={name}"))
            .header(header::CONTENT_TYPE, "application/vnd.tcpdump.pcap")
            .body(Body::from(bytes))
            .unwrap();
        self.send(request).await
    }

    async fn upload_fixture(&self, name: &str) -> i64 {
        let (status, body, _) = self.upload(name, fixture(name)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["id"].as_i64().unwrap()
    }

    fn upload_dir_is_empty(&self) -> bool {
        std::fs::read_dir(self.upload_dir.path())
            .unwrap()
            .next()
            .is_none()
    }

    async fn finish(self) {
        self.db.drop_database().await;
    }
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pcap")
        .join(name)
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap()
}

fn error_code(body: &Value) -> &str {
    body["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("not an error body: {body}"))
}

#[tokio::test]
async fn import_then_browse_a_capture() {
    let Some(h) = Harness::new("api_import", 64 * 1024 * 1024).await else {
        return;
    };
    let (status, body, headers) = h
        .upload("flows-mixed.pcap", fixture("flows-mixed.pcap"))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["id"].as_i64().unwrap();
    assert_eq!(
        headers[header::LOCATION],
        format!("/api/v1/captures/{id}").as_str()
    );
    assert_eq!(body["file_name"], "flows-mixed.pcap");
    assert_eq!(body["packets_processed"], 19);
    assert_eq!(body["packets_stored"], 19);
    assert_eq!(body["flows_total"], 6);
    assert_eq!(body["sha256"].as_str().unwrap().len(), 64);
    assert!(h.upload_dir_is_empty(), "temporary upload file is deleted");

    let (status, list) = h.get("/api/v1/captures").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["total"], 1);
    assert_eq!(list["items"][0]["id"], id);

    let (_, detail) = h.get(&format!("/api/v1/captures/{id}")).await;
    assert_eq!(detail["flow_summary"]["flows_total"], 6);

    let (_, page) = h
        .get(&format!("/api/v1/captures/{id}/packets?page=2&per_page=5"))
        .await;
    assert_eq!(page["total"], 19);
    assert_eq!(page["page"], 2);
    assert_eq!(page["items"][0]["packet_index"], 6);

    let (_, packet) = h.get(&format!("/api/v1/captures/{id}/packets/1")).await;
    assert_eq!(packet["top_protocol"], "DNS");
    assert_eq!(packet["layers"][3]["layer"], "dns");

    let (_, flows) = h
        .get(&format!("/api/v1/captures/{id}/flows?sort=-bytes"))
        .await;
    assert_eq!(flows["total"], 6);
    assert_eq!(flows["items"][0]["flow_id"], 2);
    let (_, flow) = h.get(&format!("/api/v1/captures/{id}/flows/2")).await;
    assert_eq!(flow["record"]["tcp"]["state"], "closed");
    let (_, flow_packets) = h
        .get(&format!(
            "/api/v1/captures/{id}/packets?flow_id=2&per_page=500"
        ))
        .await;
    assert_eq!(flow_packets["total"], 9);

    let (_, dns) = h.get(&format!("/api/v1/captures/{id}/dns")).await;
    assert_eq!(dns["total"], 2);
    let (_, tls) = h.get(&format!("/api/v1/captures/{id}/tls")).await;
    assert_eq!(tls["items"][0]["server_name"], "www.example.com");
    let (_, http) = h.get(&format!("/api/v1/captures/{id}/http")).await;
    assert_eq!(http["total"], 0);

    let (status, _, _) = h
        .send(
            Request::delete(format!("/api/v1/captures/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = h.get(&format!("/api/v1/captures/{id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error_code(&body), "not_found");
    h.finish().await;
}

#[tokio::test]
async fn malformed_requests_get_structured_errors() {
    let Some(h) = Harness::new("api_errors", 1024 * 1024).await else {
        return;
    };
    let id = h.upload_fixture("flows-mixed.pcap").await;
    for (uri, status, code) in [
        (
            "/api/v1/captures?page=0",
            StatusCode::BAD_REQUEST,
            "invalid_page",
        ),
        (
            "/api/v1/captures?per_page=501",
            StatusCode::BAD_REQUEST,
            "invalid_per_page",
        ),
        (
            "/api/v1/captures?page=abc",
            StatusCode::BAD_REQUEST,
            "invalid_query",
        ),
        (
            "/api/v1/captures?unknown=1",
            StatusCode::BAD_REQUEST,
            "invalid_query",
        ),
        (
            "/api/v1/captures?sort=id;DROP",
            StatusCode::BAD_REQUEST,
            "invalid_sort",
        ),
        (
            "/api/v1/captures/abc",
            StatusCode::BAD_REQUEST,
            "invalid_path",
        ),
        ("/api/v1/captures/99999", StatusCode::NOT_FOUND, "not_found"),
        (
            "/api/v1/captures/99999/packets",
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        (
            "/api/v1/captures/99999/flows",
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        ("/api/v1/nothing-here", StatusCode::NOT_FOUND, "not_found"),
    ] {
        let (actual, body) = h.get(uri).await;
        assert_eq!(actual, status, "{uri}: {body}");
        assert_eq!(error_code(&body), code, "{uri}");
    }
    let (status, body) = h.get(&format!("/api/v1/captures/{id}/packets/0")).await;
    assert_eq!(
        (status, error_code(&body)),
        (StatusCode::NOT_FOUND, "not_found")
    );
    let (status, body) = h
        .get(&format!("/api/v1/captures/{id}/flows?sort=bytes"))
        .await;
    assert_eq!(
        (status, error_code(&body)),
        (StatusCode::BAD_REQUEST, "invalid_sort")
    );
    let (status, body, _) = h
        .send(
            Request::patch(format!("/api/v1/captures/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(error_code(&body), "method_not_allowed");
    h.finish().await;
}

#[tokio::test]
async fn uploads_are_validated_and_never_left_on_disk() {
    let Some(h) = Harness::new("api_uploads", 4096).await else {
        return;
    };
    // Wrong or missing content type.
    for content_type in [
        None,
        Some("multipart/form-data; boundary=x"),
        Some("text/plain"),
    ] {
        let mut request = Request::post("/api/v1/captures?file_name=a.pcap");
        if let Some(value) = content_type {
            request = request.header(header::CONTENT_TYPE, value);
        }
        let (status, body, _) = h
            .send(request.body(Body::from(vec![0u8; 10])).unwrap())
            .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(error_code(&body), "unsupported_media_type");
    }
    // File names.
    for (query, code) in [
        ("", "invalid_query"),
        ("?file_name=a.pcapng", "unsupported_extension"),
        ("?file_name=notes.txt", "unsupported_extension"),
        ("?file_name=.pcap", "unsupported_extension"),
    ] {
        let request = Request::post(format!("/api/v1/captures{query}"))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(fixture("le-usec.pcap")))
            .unwrap();
        let (status, body, _) = h.send(request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(error_code(&body), code, "{query}");
    }
    // Directory components are dropped from the stored name.
    let (status, body, _) = h
        .upload("..%2F..%2Fetc%2Fevil.pcap", fixture("le-usec.pcap"))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["file_name"], "evil.pcap");

    // Size: declared and streamed.
    let request = Request::post("/api/v1/captures?file_name=big.pcap")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, "4097")
        .body(Body::from(vec![0u8; 4097]))
        .unwrap();
    let (status, body, _) = h.send(request).await;
    assert_eq!(
        (status, error_code(&body)),
        (StatusCode::PAYLOAD_TOO_LARGE, "upload_too_large")
    );
    let (status, body, _) = h.upload("big.pcap", vec![0u8; 5000]).await;
    assert_eq!(
        (status, error_code(&body)),
        (StatusCode::PAYLOAD_TOO_LARGE, "upload_too_large")
    );

    // Content.
    let (status, body, _) = h.upload("empty.pcap", Vec::new()).await;
    assert_eq!(
        (status, error_code(&body)),
        (StatusCode::BAD_REQUEST, "empty_upload")
    );
    for (name, code) in [
        ("invalid-magic.pcap", "invalid_magic"),
        ("pcapng-content.pcap", "unsupported_format"),
        ("truncated-record-data.pcap", "truncated_record_data"),
    ] {
        let (status, body, _) = h.upload("x.pcap", fixture(name)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {body}");
        assert_eq!(error_code(&body), code, "{name}");
        let message = body["error"]["message"].as_str().unwrap();
        assert!(!message.contains("flowsentinel-upload-"), "{message}");
    }
    assert!(h.upload_dir_is_empty(), "rejected uploads are deleted");

    // A second import while one is running is refused.
    let permit = h.state.import_slots.clone().try_acquire_owned().unwrap();
    let (status, body, _) = h.upload("busy.pcap", fixture("le-usec.pcap")).await;
    assert_eq!(
        (status, error_code(&body)),
        (StatusCode::TOO_MANY_REQUESTS, "import_busy")
    );
    drop(permit);
    h.finish().await;
}

#[tokio::test]
async fn retention_settings_apply_to_new_imports() {
    let Some(h) = Harness::new("api_retention", 1024 * 1024).await else {
        return;
    };
    let (status, body) = h.get("/api/v1/settings/retention").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"session_ttl_days": 30, "max_packets_stored": 100000})
    );

    let put = |value: String| {
        Request::put("/api/v1/settings/retention")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value))
            .unwrap()
    };
    let (status, body, _) = h
        .send(put(
            json!({"session_ttl_days": 2, "max_packets_stored": 3}).to_string()
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for (value, status, code) in [
        (
            json!({"session_ttl_days": 0, "max_packets_stored": 3}).to_string(),
            StatusCode::BAD_REQUEST,
            "invalid_ttl",
        ),
        (
            json!({"session_ttl_days": 2, "max_packets_stored": -1}).to_string(),
            StatusCode::BAD_REQUEST,
            "invalid_max_packets",
        ),
        (
            json!({"session_ttl_days": 2}).to_string(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body",
        ),
        (
            json!({"session_ttl_days": 2, "max_packets_stored": 3, "x": 1}).to_string(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body",
        ),
        (
            "{not json".to_owned(),
            StatusCode::BAD_REQUEST,
            "invalid_body",
        ),
        (
            "x".repeat(20_000),
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_body",
        ),
    ] {
        let (actual, body, _) = h.send(put(value)).await;
        assert_eq!(actual, status, "{body}");
        assert_eq!(error_code(&body), code);
    }

    let id = h.upload_fixture("flows-mixed.pcap").await;
    let (_, detail) = h.get(&format!("/api/v1/captures/{id}")).await;
    assert_eq!(detail["packets_stored"], 3);
    assert_eq!(detail["packets_processed"], 19);
    assert_eq!(detail["flows_stored"], 6);
    h.finish().await;
}

#[tokio::test]
async fn responses_never_contain_payloads_or_secrets() {
    let Some(h) = Harness::new("api_privacy", 1024 * 1024).await else {
        return;
    };
    let mut text = String::new();
    for name in [
        "app-dns.pcap",
        "app-dhcp.pcap",
        "app-http.pcap",
        "app-tls.pcap",
        "flows-mixed.pcap",
        "detect-mixed.pcap",
    ] {
        let id = h.upload_fixture(name).await;
        for path in [
            "",
            "/packets?per_page=500",
            "/flows?per_page=500",
            "/dns",
            "/http",
            "/tls",
            "/alerts?per_page=500",
        ] {
            let (status, body) = h.get(&format!("/api/v1/captures/{id}{path}")).await;
            assert_eq!(status, StatusCode::OK);
            text.push_str(&body.to_string());
        }
        let (_, packets) = h
            .get(&format!("/api/v1/captures/{id}/packets?per_page=500"))
            .await;
        for packet in packets["items"].as_array().unwrap() {
            let index = &packet["packet_index"];
            let (_, detail) = h
                .get(&format!("/api/v1/captures/{id}/packets/{index}"))
                .await;
            text.push_str(&detail.to_string());
        }
        let (_, flows) = h
            .get(&format!("/api/v1/captures/{id}/flows?per_page=500"))
            .await;
        for flow in flows["items"].as_array().unwrap() {
            let flow_id = &flow["flow_id"];
            let (_, detail) = h
                .get(&format!("/api/v1/captures/{id}/flows/{flow_id}"))
                .await;
            text.push_str(&detail.to_string());
        }
        let (_, alerts) = h
            .get(&format!("/api/v1/captures/{id}/alerts?per_page=500"))
            .await;
        for alert in alerts["items"].as_array().unwrap() {
            let alert_id = &alert["alert_id"];
            let (_, detail) = h
                .get(&format!("/api/v1/captures/{id}/alerts/{alert_id}"))
                .await;
            text.push_str(&detail.to_string());
        }
    }
    let lower = text.to_ascii_lowercase();
    assert!(lower.contains("fs-dns-tunnel"), "alerts were fetched");
    assert!(lower.contains("www.example.com"));
    assert!(!lower.contains("flowsentinel-secret"));
    assert!(!lower.contains("flowsentinel-synthetic-payload-marker"));
    h.finish().await;
}

#[tokio::test]
async fn openapi_document_lists_every_endpoint() {
    let Some(h) = Harness::new("api_openapi", 1024).await else {
        return;
    };
    let (status, doc) = h.get("/api/v1/openapi.json").await;
    assert_eq!(status, StatusCode::OK);
    assert!(doc["openapi"].as_str().unwrap().starts_with("3."));
    let paths = doc["paths"].as_object().unwrap();
    for path in [
        "/api/v1/captures",
        "/api/v1/captures/{id}",
        "/api/v1/captures/{id}/packets",
        "/api/v1/captures/{id}/packets/{index}",
        "/api/v1/captures/{id}/flows",
        "/api/v1/captures/{id}/flows/{flow_id}",
        "/api/v1/captures/{id}/dns",
        "/api/v1/captures/{id}/http",
        "/api/v1/captures/{id}/tls",
        "/api/v1/settings/retention",
        "/api/v1/captures/{id}/alerts",
        "/api/v1/captures/{id}/alerts/{alert_id}",
        "/api/v1/rules",
    ] {
        assert!(paths.contains_key(path), "{path}");
    }
    assert!(paths["/api/v1/captures"]["post"].is_object());
    assert!(paths["/api/v1/captures/{id}/alerts/{alert_id}"]["patch"].is_object());
    assert!(doc["components"]["schemas"]["ErrorResponse"].is_object());
    let (status, _, _) = h
        .send(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    h.finish().await;
}

/// A valid capture of `count` copies of the first record of `name`.
fn repeated_capture(name: &str, count: usize) -> Vec<u8> {
    let bytes = fixture(name);
    let (header, rest) = bytes.split_at(24);
    let captured = u32::from_le_bytes(rest[8..12].try_into().unwrap()) as usize;
    let record = &rest[..16 + captured];
    let mut out = header.to_vec();
    for _ in 0..count {
        out.extend_from_slice(record);
    }
    out
}

#[tokio::test]
async fn unexpected_host_names_are_refused() {
    let Some(h) = Harness::new("api_hosts", 1024).await else {
        return;
    };
    let get = |host: &'static str| {
        Request::get("/api/v1/captures")
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap()
    };
    // A page on another site that rebinds its DNS name to 127.0.0.1.
    let (status, body, _) = h.send(get("rebind.attacker.example:8080")).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(error_code(&body), "invalid_host");
    for host in ["localhost:8080", "127.0.0.1:8080", "[::1]:8080"] {
        let (status, _, _) = h.send(get(host)).await;
        assert_eq!(status, StatusCode::OK, "{host}");
    }
    // The health check answers any host.
    let (status, _, _) = h
        .send(
            Request::get("/health")
                .header(header::HOST, "10.1.2.3:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    h.finish().await;
}

#[tokio::test]
async fn upload_names_and_large_bodies() {
    let Some(h) = Harness::new("api_names", 4 * 1024 * 1024).await else {
        return;
    };
    // Well over the 16 KiB JSON body limit, which must not apply to uploads.
    let big = repeated_capture("le-usec.pcap", 2_000);
    assert!(big.len() > 64 * 1024);
    let long = format!("{}.pcap", "n".repeat(200));
    let (status, body, _) = h.upload(&long, big).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["packets_processed"], 2_000);
    let name = body["file_name"].as_str().unwrap();
    assert!(name.ends_with("...pcap") && name.len() < 140, "{name}");
    // Windows paths keep only the file name on every platform.
    let (status, body, _) = h
        .upload("C:%5Ccaptures%5Clab.pcap", fixture("le-usec.pcap"))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["file_name"], "lab.pcap");
    h.finish().await;
}

#[tokio::test]
async fn partial_imports_report_a_stable_completion_state() {
    let limits = CaptureLimits {
        max_packets: 5,
        ..CaptureLimits::default()
    };
    let Some(h) = Harness::with_limits("api_partial", 1024 * 1024, limits).await else {
        return;
    };
    let id = h.upload_fixture("flows-mixed.pcap").await;
    let (_, capture) = h.get(&format!("/api/v1/captures/{id}")).await;
    assert_eq!(capture["completion_state"], "packet_limit_reached");
    assert_eq!(capture["packets_processed"], 5);
    h.finish().await;
}

fn encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[tokio::test]
async fn display_filters_select_matching_rows() {
    let Some(h) = Harness::new("api_filters", 1024 * 1024).await else {
        return;
    };
    let id = h.upload_fixture("flows-mixed.pcap").await;
    let total = |kind: &'static str, filter: &'static str| {
        let uri = format!(
            "/api/v1/captures/{id}/{kind}?per_page=500&filter={}",
            encode(filter)
        );
        let h = &h;
        async move {
            let (status, body) = h.get(&uri).await;
            assert_eq!(status, StatusCode::OK, "{filter}: {body}");
            body["total"].as_i64().unwrap()
        }
    };
    assert_eq!(total("packets", "tls.sni == \"www.example.com\"").await, 2);
    assert_eq!(total("packets", "TLS.SNI contains \"EXAMPLE\"").await, 2);
    assert_eq!(total("packets", "ip.addr == 192.0.2.53").await, 2);
    assert_eq!(total("packets", "ip.src == 192.0.2.0/24 and tcp").await, 7);
    assert_eq!(total("packets", "udp and not dns").await, 5);
    assert_eq!(total("packets", "tcp.flags.syn").await, 3);
    assert_eq!(total("packets", "arp or ipv6").await, 3);
    assert_eq!(total("packets", "not ip").await, 1);
    assert_eq!(
        total("packets", "dns.qry.name == \"www.example.com\"").await,
        2
    );
    assert_eq!(total("packets", "").await, 19);
    assert_eq!(total("flows", "flow.bytes > 1000").await, 1);
    assert_eq!(total("flows", "udp && flow.packets >= 2").await, 3);
    assert_eq!(total("flows", "flow.end_reason == idle_timeout").await, 3);
    assert_eq!(
        total("flows", "flow.state == reset or flow.state == closed").await,
        2
    );
    assert_eq!(total("flows", "tls.sni == \"www.example.com\"").await, 1);
    assert_eq!(total("flows", "flow.duration >= 1").await, 1);

    // Port fields never match flows without ports (ICMPv6, ESP, fragments),
    // just as they never match such packets.
    let ipv6 = h.upload_fixture("decode-ipv6.pcap").await;
    for filter in ["port == 0", "port != 9", "flow.initiator_port < 1024"] {
        let (_, flows) = h
            .get(&format!(
                "/api/v1/captures/{ipv6}/flows?per_page=500&filter={}",
                encode(filter)
            ))
            .await;
        for flow in flows["items"].as_array().unwrap() {
            assert!(
                flow["protocol"] == 6 || flow["protocol"] == 17,
                "{filter}: {flow}"
            );
        }
    }
    let (_, portless) = h
        .get(&format!(
            "/api/v1/captures/{ipv6}/flows?per_page=500&filter={}",
            encode("port == 0")
        ))
        .await;
    assert_eq!(portless["total"], 0);

    // The filter is not trimmed, so positions match /filters/validate.
    let (_, body) = h
        .get(&format!(
            "/api/v1/captures/{id}/packets?filter={}",
            encode("   nosuch == 1")
        ))
        .await;
    assert_eq!(body["error"]["position"], json!({"start": 3, "end": 9}));
    let (_, blank) = h
        .get(&format!("/api/v1/captures/{id}/packets?filter=%20%20"))
        .await;
    assert_eq!(blank["total"], 19);

    // A filter combines with flow_id.
    let (_, both) = h
        .get(&format!(
            "/api/v1/captures/{id}/packets?flow_id=2&filter={}",
            encode("tcp.flags.fin")
        ))
        .await;
    assert_eq!(both["total"], 2);

    // Errors say what and where.
    let (status, body) = h
        .get(&format!(
            "/api/v1/captures/{id}/packets?filter={}",
            encode("tcp.port == 443 and nosuch == 1")
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&body), "unknown_field");
    assert_eq!(body["error"]["position"], json!({"start": 20, "end": 26}));
    let (_, body) = h
        .get(&format!(
            "/api/v1/captures/{id}/flows?filter={}",
            encode("frame.len > 10")
        ))
        .await;
    assert_eq!(
        error_code(&body),
        "unknown_field",
        "packet fields are not flow fields"
    );

    // Quoted text is a parameter, never SQL.
    for attempt in [
        "http.host == \"x' OR '1'='1\"",
        "dns.qry.name contains \"'); DROP TABLE packets; --\"",
    ] {
        assert_eq!(total("packets", attempt).await, 0, "{attempt}");
    }
    assert_eq!(total("packets", "").await, 19);
    h.finish().await;
}

#[tokio::test]
async fn filters_can_be_validated_and_fields_listed() {
    let Some(h) = Harness::new("api_filter_meta", 1024).await else {
        return;
    };
    let (status, body) = h
        .get(&format!(
            "/api/v1/filters/validate?target=packets&filter={}",
            encode("TCP.Port==443 && !dns")
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["valid"], true);
    assert_eq!(body["normalized"], "tcp.port == 443 and not dns");
    assert_eq!(body["parameters"], 2);

    for (filter, code) in [
        ("tcp.port == 99999", "invalid_value"),
        ("(tcp", "syntax_error"),
        ("http.host == \"unterminated", "unterminated_string"),
        ("ip.src > 192.0.2.1", "invalid_operator"),
    ] {
        let (status, body) = h
            .get(&format!(
                "/api/v1/filters/validate?target=packets&filter={}",
                encode(filter)
            ))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{filter}");
        assert_eq!(error_code(&body), code, "{filter}");
        assert!(body["error"]["position"].is_object(), "{filter}: {body}");
    }
    let long = "a or ".repeat(300);
    let (_, body) = h
        .get(&format!(
            "/api/v1/filters/validate?target=packets&filter={}",
            encode(&long)
        ))
        .await;
    assert_eq!(error_code(&body), "filter_too_long");
    let (status, body) = h
        .get("/api/v1/filters/validate?target=alerts&filter=tcp")
        .await;
    assert_eq!(
        (status, error_code(&body)),
        (StatusCode::BAD_REQUEST, "invalid_target")
    );

    let (status, fields) = h.get("/api/v1/filters/fields?target=flows").await;
    assert_eq!(status, StatusCode::OK);
    let bytes = fields
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "flow.bytes")
        .unwrap();
    assert_eq!(bytes["type"], "unsigned integer");
    assert!(
        bytes["operators"]
            .as_array()
            .unwrap()
            .contains(&json!(">="))
    );
    let state = fields
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "flow.state")
        .unwrap();
    assert!(
        state["values"]
            .as_array()
            .unwrap()
            .contains(&json!("established"))
    );
    h.finish().await;
}

async fn patch_json(h: &Harness, uri: &str, body: &str) -> (StatusCode, Value) {
    let (status, body, _) = h
        .send(
            Request::patch(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await;
    (status, body)
}

#[tokio::test]
async fn alerts_are_explained_filterable_and_triaged() {
    let Some(h) = Harness::new("api_alerts", 1024 * 1024).await else {
        return;
    };
    let id = h.upload_fixture("detect-mixed.pcap").await;
    let (_, capture) = h.get(&format!("/api/v1/captures/{id}")).await;
    assert_eq!(capture["alerts_total"], 5, "{capture}");
    assert_eq!(capture["detection_summary"]["alerts_total"], 5);

    let base = format!("/api/v1/captures/{id}/alerts");
    let (status, page) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["total"], 5);
    let items = page["items"].as_array().unwrap();
    let mut rules: Vec<&str> = items
        .iter()
        .map(|a| a["rule_id"].as_str().unwrap())
        .collect();
    rules.sort_unstable();
    assert_eq!(
        rules,
        [
            "FS-ARP-CONFLICT",
            "FS-BEACON",
            "FS-CLEARTEXT",
            "FS-DNS-TUNNEL",
            "FS-SCAN-SYN"
        ]
    );
    // Default order: most severe first.
    let ranks: Vec<u8> = items
        .iter()
        .map(|a| match a["severity"].as_str().unwrap() {
            "high" => 3,
            "medium" => 2,
            _ => 1,
        })
        .collect();
    assert!(ranks.windows(2).all(|w| w[0] >= w[1]), "{ranks:?}");
    for alert in items {
        assert!(
            alert["nature"]
                .as_str()
                .unwrap()
                .contains("not proof of compromise")
        );
        assert!(!alert["evidence"].as_array().unwrap().is_empty(), "{alert}");
        assert!(!alert["explanation"].as_str().unwrap().is_empty());
        assert!(!alert["uncertainty"].as_str().unwrap().is_empty());
        assert_eq!(alert["status"], "open");
        assert!(alert["status_changed_at"].is_null());
    }

    // Restrictions.
    let (_, high) = h.get(&format!("{base}?severity=high")).await;
    assert!(
        high["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["severity"] == "high")
    );
    let (_, beacon) = h.get(&format!("{base}?rule=FS-BEACON&sort=time")).await;
    assert_eq!(beacon["total"], 1);
    let beacon = &beacon["items"][0];
    assert_eq!(beacon["destination"], "203.0.113.80");
    assert_eq!(beacon["destination_port"], 8443);
    for (query, code) in [
        ("severity=critical", "invalid_severity"),
        ("status=closed", "invalid_status"),
        ("rule=FS-NOPE", "invalid_rule"),
        ("sort=severity_rank", "invalid_sort"),
        ("severity=high&extra=1", "invalid_query"),
    ] {
        let (status, body) = h.get(&format!("{base}?{query}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
        assert_eq!(error_code(&body), code, "{query}");
    }

    // Every cited flow exists and links back to the alert.
    let alert_id = beacon["alert_id"].as_i64().unwrap();
    let flow_ids = beacon["related_flow_ids"].as_array().unwrap();
    assert_eq!(flow_ids.len(), 7);
    for flow_id in flow_ids {
        let (status, flow) = h
            .get(&format!("/api/v1/captures/{id}/flows/{flow_id}"))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(flow["alert_count"].as_i64().unwrap() >= 1);
        assert!(
            flow["record"]["alert_ids"]
                .as_array()
                .unwrap()
                .contains(&json!(alert_id))
        );
    }

    // Detail and triage.
    let (status, detail) = h.get(&format!("{base}/{alert_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["rule_id"], "FS-BEACON");
    let (status, body) = h.get(&format!("{base}/999")).await;
    assert_eq!(
        (status, error_code(&body)),
        (StatusCode::NOT_FOUND, "not_found")
    );
    let (status, updated) = patch_json(
        &h,
        &format!("{base}/{alert_id}"),
        r#"{"status":"false_positive"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["status"], "false_positive");
    assert!(updated["status_changed_at"].is_string());
    assert_eq!(updated["evidence"], detail["evidence"]);
    let (_, triaged) = h.get(&format!("{base}?status=false_positive")).await;
    assert_eq!(triaged["total"], 1);
    for (body, status, code) in [
        (
            r#"{"status":"closed"}"#,
            StatusCode::BAD_REQUEST,
            "invalid_status",
        ),
        (
            r#"{"status":"open","severity":"low"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body",
        ),
    ] {
        let (got, response) = patch_json(&h, &format!("{base}/{alert_id}"), body).await;
        assert_eq!((got, error_code(&response)), (status, code), "{body}");
    }
    let (status, _) = patch_json(&h, &format!("{base}/999"), r#"{"status":"open"}"#).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = patch_json(
        &h,
        &format!("/api/v1/captures/{}/alerts/{alert_id}", id + 1),
        r#"{"status":"open"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Flow filters over alert facts.
    let flows = format!("/api/v1/captures/{id}/flows");
    let (_, alerted) = h.get(&format!("{flows}?filter=alert")).await;
    let alerted_total = alerted["total"].as_i64().unwrap();
    assert!(alerted_total >= 7, "{alerted}");
    assert!(
        alerted["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["alert_count"].as_i64().unwrap() > 0)
    );
    let (_, quiet) = h.get(&format!("{flows}?filter=not%20alert")).await;
    assert_eq!(
        alerted_total + quiet["total"].as_i64().unwrap(),
        capture["flows_stored"].as_i64().unwrap()
    );
    let (_, medium) = h
        .get(&format!(
            "{flows}?filter={}",
            encode("alert.severity == medium")
        ))
        .await;
    assert!(
        medium["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["max_alert_severity"] == "medium")
    );
    // High-severity DNS alerts mark the flows of the queries they cite.
    let (_, high) = h
        .get(&format!(
            "{flows}?filter={}",
            encode("alert.severity == high")
        ))
        .await;
    assert!(high["total"].as_i64().unwrap() >= 12, "{high}");
    assert!(
        high["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["max_alert_severity"] == "high" && f["protocol"] == 17)
    );
    let (status, body) = h
        .get(&format!(
            "{flows}?filter={}",
            encode("alert.severity == critical")
        ))
        .await;
    assert_eq!(
        (status, error_code(&body)),
        (StatusCode::BAD_REQUEST, "invalid_value")
    );

    // Rule catalog.
    let (status, catalog) = h.get("/api/v1/rules").await;
    assert_eq!(status, StatusCode::OK);
    let catalog = catalog.as_array().unwrap();
    assert_eq!(catalog.len(), 12);
    for rule in catalog {
        assert!(rule["id"].as_str().unwrap().starts_with("FS-"));
        assert!(
            !rule["likely_false_positives"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(rule["nature"].as_str().unwrap().contains("heuristic"));
    }

    // Alerts carry metadata only.
    for uri in [base.clone(), format!("{base}/{alert_id}"), flows.clone()] {
        let (_, body) = h.get(&uri).await;
        let text = body.to_string().to_ascii_lowercase();
        assert!(!text.contains("payload-marker"), "{uri}");
        assert!(!text.contains("flowsentinel-secret"), "{uri}");
    }
    h.finish().await;
}

#[tokio::test]
async fn overview_totals_every_capture() {
    let Some(h) = Harness::new("api_overview", 1024 * 1024).await else {
        return;
    };
    let (status, empty) = h.get("/api/v1/overview").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(empty["captures"], 0);
    assert_eq!(empty["recent_captures"], json!([]));
    let first = h.upload_fixture("detect-mixed.pcap").await;
    h.upload_fixture("flows-mixed.pcap").await;
    let (_, overview) = h.get("/api/v1/overview").await;
    assert_eq!(overview["captures"], 2);
    assert_eq!(overview["packets_processed"], 138 + 19);
    assert_eq!(overview["alerts_total"], 5);
    assert_eq!(
        overview["alerts_by_severity"],
        json!({"high": 2, "medium": 2, "low": 1})
    );
    assert_eq!(overview["alerts_by_status"], json!({"open": 5}));
    let recent = overview["recent_captures"].as_array().unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[1]["id"], first, "newest first");
    // Triage moves counts between statuses.
    let (status, _) = patch_json(
        &h,
        &format!("/api/v1/captures/{first}/alerts/1"),
        r#"{"status":"resolved"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, overview) = h.get("/api/v1/overview").await;
    assert_eq!(
        overview["alerts_by_status"],
        json!({"open": 4, "resolved": 1})
    );
    assert_eq!(
        overview["open_alerts_by_severity"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_i64().unwrap())
            .sum::<i64>(),
        4
    );
    h.finish().await;
}

async fn get_raw(
    h: &Harness,
    method: Method,
    uri: &str,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let response = h
        .app()
        .oneshot(signed(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
            &h.admin,
        ))
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        String::from_utf8_lossy(&bytes).into_owned(),
        headers,
    )
}

#[tokio::test]
async fn the_dashboard_is_served_with_security_headers() {
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(
        dist.path().join("index.html"),
        "<!doctype html><title>FlowSentinel</title><script type=\"module\" src=\"/assets/app.js\"></script>",
    )
    .unwrap();
    std::fs::create_dir(dist.path().join("assets")).unwrap();
    std::fs::write(dist.path().join("assets/app.js"), "console.log(1);").unwrap();
    let Some(h) = Harness::build(
        "api_dashboard",
        1024,
        CaptureLimits::default(),
        Some(dist.path().to_owned()),
    )
    .await
    else {
        return;
    };
    // The index and client-side routes get the page.
    for path in ["/", "/captures/7/packets?filter=tcp", "/settings"] {
        let (status, body, headers) = get_raw(&h, Method::GET, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(body.contains("<title>FlowSentinel</title>"), "{path}");
        assert!(
            headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
        // Revalidated on every load, so an upgrade takes effect at once.
        assert_eq!(headers[header::CACHE_CONTROL], "no-cache", "{path}");
    }
    let (status, body, headers) = get_raw(&h, Method::GET, "/assets/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "console.log(1);");
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .contains("javascript")
    );
    assert_eq!(
        headers[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );
    // A missing asset is not answered with the page (which a browser would
    // try to run as a script), and the 404 is not cached.
    let (status, body, headers) = get_raw(&h, Method::GET, "/assets/old-build.js").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.contains("<title>"));
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    // No path under /api/ is ever answered with the page.
    for path in ["/api", "/api/", "/api/v1/", "/api/v2/captures"] {
        let (status, body, headers) = get_raw(&h, Method::GET, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(body.contains("\"not_found\""), "{path}: {body}");
        assert!(
            headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("application/json"),
            "{path}"
        );
    }
    // The API keeps its JSON errors and headers.
    let (status, body) = h.get("/api/v1/no-such-endpoint").await;
    assert_eq!(
        (status, error_code(&body)),
        (StatusCode::NOT_FOUND, "not_found")
    );
    let (status, _, headers) = get_raw(&h, Method::GET, "/api/v1/rules").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    // Static files are read-only, and nothing outside the directory is served.
    let (status, _, _) = get_raw(&h, Method::POST, "/").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, body, _) = get_raw(&h, Method::GET, "/assets/../../../../etc/passwd").await;
    assert!(!body.contains("root:"), "{status}");
    h.finish().await;
}
