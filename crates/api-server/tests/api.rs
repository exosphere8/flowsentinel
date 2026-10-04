//! `/api/v1` end to end against a real PostgreSQL server (see
//! `storage::testing` for how to enable these tests).

use std::path::{Path, PathBuf};

use api_server::host::HostPolicy;
use api_server::{ApiConfig, AppState, app_with_state};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use capture::CaptureLimits;
use flow_engine::FlowConfig;
use serde_json::{Value, json};
use storage::testing::TestDatabase;
use tower::ServiceExt;

struct Harness {
    db: TestDatabase,
    state: AppState,
    upload_dir: tempfile::TempDir,
}

impl Harness {
    async fn new(test: &str, max_upload_bytes: u64) -> Option<Self> {
        Self::with_limits(test, max_upload_bytes, CaptureLimits::default()).await
    }

    async fn with_limits(
        test: &str,
        max_upload_bytes: u64,
        capture_limits: CaptureLimits,
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
            },
            1,
        );
        Some(Self {
            db,
            state,
            upload_dir,
        })
    }

    fn app(&self) -> Router {
        app_with_state(self.state.clone())
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value, axum::http::HeaderMap) {
        let response = self.app().oneshot(request).await.unwrap();
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
    ] {
        let id = h.upload_fixture(name).await;
        for path in [
            "",
            "/packets?per_page=500",
            "/flows?per_page=500",
            "/dns",
            "/http",
            "/tls",
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
    }
    let lower = text.to_ascii_lowercase();
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
    ] {
        assert!(paths.contains_key(path), "{path}");
    }
    assert!(paths["/api/v1/captures"]["post"].is_object());
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
