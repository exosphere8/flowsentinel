//! Accounts, sessions, CSRF, roles, sign-in limits and the audit log,
//! end to end against a real PostgreSQL server (see `storage::testing`).

use std::path::Path;

use api_server::auth::{AuthConfig, COOKIE_NAME, CSRF_HEADER};
use api_server::host::HostPolicy;
use api_server::{ApiConfig, AppState, app_with_state, bootstrap};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use capture::CaptureLimits;
use detection_engine::DetectionConfig;
use flow_engine::FlowConfig;
use serde_json::{Value, json};
use storage::Role;
use storage::testing::TestDatabase;
use tower::ServiceExt;

const PASSWORD: &str = "correct horse battery staple";

struct Harness {
    db: TestDatabase,
    state: AppState,
    _uploads: tempfile::TempDir,
}

/// A signed-in client: its cookie and CSRF token.
#[derive(Clone, Debug)]
struct Client {
    cookie: String,
    csrf: String,
}

struct Reply {
    status: StatusCode,
    body: Value,
    headers: HeaderMap,
}

impl Reply {
    fn code(&self) -> &str {
        self.body["error"]["code"].as_str().unwrap_or("")
    }
}

impl Harness {
    async fn new(test: &str) -> Option<Self> {
        let db = TestDatabase::create(test).await?;
        let uploads = tempfile::tempdir().unwrap();
        let state = AppState::new(
            db.storage.clone(),
            ApiConfig {
                max_upload_bytes: 4 * 1024 * 1024,
                upload_dir: uploads.path().to_owned(),
                capture_limits: CaptureLimits::default(),
                flow_config: FlowConfig::default(),
                host_policy: HostPolicy::default_for("127.0.0.1:8080".parse().unwrap()),
                detection: DetectionConfig::default(),
                dashboard_dir: None,
                auth: AuthConfig::default(),
                live: api_server::Config::default().live(),
            },
            1,
        );
        Some(Self {
            db,
            state,
            _uploads: uploads,
        })
    }

    fn app(&self) -> Router {
        app_with_state(self.state.clone())
    }

    async fn add_user(&self, name: &str, role: Role) -> i64 {
        bootstrap::create_user(&self.db.storage, name, role, PASSWORD.to_owned())
            .await
            .unwrap()
            .id
    }

    async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.app().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        Reply {
            status,
            body,
            headers,
        }
    }

    async fn login(&self, name: &str, password: &str) -> Reply {
        self.send(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": name, "password": password }).to_string(),
                ))
                .unwrap(),
        )
        .await
    }

    async fn sign_in(&self, name: &str) -> Client {
        let reply = self.login(name, PASSWORD).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        client_from(&reply)
    }

    /// A request as `client` (with its CSRF token), or anonymous.
    async fn call(
        &self,
        client: Option<&Client>,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> Reply {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(client) = client {
            request = request
                .header(header::COOKIE, &client.cookie)
                .header(CSRF_HEADER, &client.csrf);
        }
        let body = match body {
            Some(value) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        self.send(request.body(body).unwrap()).await
    }

    async fn upload(&self, client: &Client) -> Reply {
        let bytes = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pcap/detect-mixed.pcap"),
        )
        .unwrap();
        self.send(
            Request::post("/api/v1/captures?file_name=detect-mixed.pcap")
                .header(header::CONTENT_TYPE, "application/vnd.tcpdump.pcap")
                .header(header::COOKIE, &client.cookie)
                .header(CSRF_HEADER, &client.csrf)
                .body(Body::from(bytes))
                .unwrap(),
        )
        .await
    }

    async fn audit(&self, action: &str) -> Vec<Value> {
        let events = self
            .db
            .storage
            .list_audit(
                storage::Page::new(1, 500),
                &storage::AuditFilter {
                    action: Some(action.to_owned()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        events
            .items
            .into_iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .collect()
    }

    async fn sql(&self, statement: &str) {
        sqlx::query(statement)
            .execute(self.db.storage.pool())
            .await
            .unwrap();
    }
}

fn client_from(reply: &Reply) -> Client {
    let set_cookie = reply.headers[header::SET_COOKIE].to_str().unwrap();
    let cookie = set_cookie.split(';').next().unwrap().to_owned();
    Client {
        cookie,
        csrf: reply.body["csrf_token"].as_str().unwrap().to_owned(),
    }
}

#[tokio::test]
async fn sign_in_session_and_sign_out() {
    let Some(h) = Harness::new("auth_flow").await else {
        return;
    };
    h.add_user("Ana", Role::Analyst).await;

    // Everything but sign-in needs a session.
    for uri in [
        "/api/v1/captures",
        "/api/v1/overview",
        "/api/v1/rules",
        "/api/v1/openapi.json",
        "/api/v1/auth/session",
    ] {
        let reply = h.call(None, Method::GET, uri, None).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(reply.code(), "unauthenticated");
    }
    let health = h.call(None, Method::GET, "/health", None).await;
    assert_eq!(health.status, StatusCode::OK);

    // Usernames are case-insensitive; the cookie is HttpOnly and strict.
    let reply = h.login("ANA", PASSWORD).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.body["user"]["username"], "ana");
    assert_eq!(reply.body["user"]["role"], "analyst");
    assert_eq!(reply.body["idle_timeout_seconds"], 1800);
    let set_cookie = reply.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.starts_with(&format!("{COOKIE_NAME}=")));
    for attribute in ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=43200"] {
        assert!(set_cookie.contains(attribute), "{set_cookie}");
    }
    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
    let ana = client_from(&reply);
    // The cookie is not the CSRF token, and neither is stored.
    assert!(!ana.cookie.ends_with(&ana.csrf));
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_sha256 FROM auth_sessions")
        .fetch_all(h.db.storage.pool())
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    let token_hex = ana.cookie.split('=').nth(1).unwrap();
    assert!(
        !stored
            .iter()
            .any(|s| format!("{s:02x?}").contains(token_hex))
    );

    let session = h
        .call(Some(&ana), Method::GET, "/api/v1/auth/session", None)
        .await;
    assert_eq!(session.status, StatusCode::OK);
    assert_eq!(session.body["csrf_token"], ana.csrf.as_str());
    let captures = h
        .call(Some(&ana), Method::GET, "/api/v1/captures", None)
        .await;
    assert_eq!(captures.status, StatusCode::OK);

    let out = h
        .call(Some(&ana), Method::POST, "/api/v1/auth/logout", None)
        .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert!(
        out.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let after = h
        .call(Some(&ana), Method::GET, "/api/v1/captures", None)
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    // A dead cookie is cleared.
    assert!(
        after.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(h.audit("auth.logout").await.len(), 1);
    h.db.drop_database().await;
}

#[tokio::test]
async fn wrong_unknown_and_disabled_accounts_get_the_same_answer() {
    let Some(h) = Harness::new("auth_failures").await else {
        return;
    };
    let id = h.add_user("vic", Role::Viewer).await;
    let wrong = h.login("vic", "not the password at all").await;
    let unknown = h.login("nobody", PASSWORD).await;
    let invalid = h.login("bad name!", PASSWORD).await;
    let too_long = h.login("vic", &"x".repeat(2000)).await;
    h.sql(&format!("UPDATE users SET disabled = TRUE WHERE id = {id}"))
        .await;
    let disabled = h.login("vic", PASSWORD).await;
    for reply in [&wrong, &unknown, &invalid, &too_long, &disabled] {
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
        assert_eq!(reply.code(), "invalid_credentials");
        assert_eq!(reply.body, wrong.body);
        assert!(!reply.headers.contains_key(header::SET_COOKIE));
    }
    let events = h.audit("auth.login").await;
    let reasons: Vec<&str> = events
        .iter()
        .map(|e| e["details"]["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        [
            "account_disabled",
            "wrong_password",
            "unknown_user",
            "unknown_user",
            "wrong_password"
        ]
    );
    assert!(events.iter().all(|e| e["outcome"] == "failure"));
    // The attempted password never reaches the audit log.
    let all = serde_json::to_string(&events).unwrap();
    assert!(!all.contains("not the password"));
    assert!(!all.contains(PASSWORD));
    h.db.drop_database().await;
}

#[tokio::test]
async fn repeated_failures_lock_the_account_name() {
    let Some(h) = Harness::new("auth_limits").await else {
        return;
    };
    h.add_user("ana", Role::Analyst).await;
    for _ in 0..5 {
        let reply = h.login("ana", "wrong password guess").await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    // Even the right password is refused while locked.
    let locked = h.login("ana", PASSWORD).await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(locked.code(), "too_many_attempts");
    let retry: u64 = locked.headers[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=900).contains(&retry), "{retry}");
    // Other accounts are unaffected.
    h.add_user("bob", Role::Viewer).await;
    assert_eq!(h.login("bob", PASSWORD).await.status, StatusCode::OK);
    // Further refusals during the lock are not audited one by one.
    for _ in 0..10 {
        assert_eq!(
            h.login("ana", PASSWORD).await.status,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    let limited = h.audit("auth.login").await;
    let refusals = limited
        .iter()
        .filter(|e| e["details"]["reason"] == "rate_limited")
        .count();
    assert_eq!(refusals, 1);
    h.db.drop_database().await;
}

#[tokio::test]
async fn parallel_guesses_are_limited_too() {
    let Some(h) = Harness::new("auth_burst").await else {
        return;
    };
    h.add_user("admin", Role::Admin).await;
    let h = std::sync::Arc::new(h);
    let guesses = (0..40).map(|i| {
        let h = std::sync::Arc::clone(&h);
        tokio::spawn(async move {
            h.login("admin", &format!("wrong guess number {i}"))
                .await
                .status
        })
    });
    let statuses = futures_util::future::join_all(guesses).await;
    let checked = statuses
        .iter()
        .filter(|s| *s.as_ref().unwrap() == StatusCode::UNAUTHORIZED)
        .count();
    let refused = statuses
        .iter()
        .filter(|s| *s.as_ref().unwrap() == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert_eq!((checked, refused), (5, 35));
    let Ok(h) = std::sync::Arc::try_unwrap(h) else {
        panic!("harness still shared");
    };
    h.db.drop_database().await;
}

#[tokio::test]
async fn a_sign_in_checked_against_an_old_password_starts_no_session() {
    let Some(h) = Harness::new("auth_stale").await else {
        return;
    };
    let id = h.add_user("ana", Role::Analyst).await;
    let storage = &h.db.storage;
    let old = storage.password_hash(id).await.unwrap().unwrap();
    let token = api_server::auth::SessionToken::generate().unwrap();
    let hour = std::time::Duration::from_secs(3600);
    // The password changes while a sign-in with the old one is being checked.
    let new = api_server::auth::hash_password("a different passphrase").unwrap();
    assert!(storage.change_password(id, &new).await.unwrap());
    let stale = storage
        .create_auth_session(id, &token.digest(), hour, 10, &old)
        .await
        .unwrap();
    assert_eq!(stale, None);
    assert!(
        storage
            .create_auth_session(id, &token.digest(), hour, 10, &new)
            .await
            .unwrap()
            .is_some()
    );
    // Nor for a disabled account.
    h.sql(&format!("UPDATE users SET disabled = TRUE WHERE id = {id}"))
        .await;
    let other = api_server::auth::SessionToken::generate().unwrap();
    assert_eq!(
        storage
            .create_auth_session(id, &other.digest(), hour, 10, &new)
            .await
            .unwrap(),
        None
    );
    h.db.drop_database().await;
}

#[tokio::test]
async fn state_changes_need_the_csrf_token_and_the_same_origin() {
    let Some(h) = Harness::new("auth_csrf").await else {
        return;
    };
    h.add_user("root", Role::Admin).await;
    let admin = h.sign_in("root").await;
    let body = json!({ "session_ttl_days": 7, "max_packets_stored": 1000 }).to_string();
    let put = |csrf: Option<&str>, extra: Option<(&'static str, &'static str)>| {
        let mut request = Request::put("/api/v1/settings/retention")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &admin.cookie);
        if let Some(csrf) = csrf {
            request = request.header(CSRF_HEADER, csrf);
        }
        if let Some((name, value)) = extra {
            request = request.header(name, value);
        }
        request.body(Body::from(body.clone())).unwrap()
    };
    let missing = h.send(put(None, None)).await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);
    assert_eq!(missing.code(), "csrf_token_invalid");
    let wrong = h.send(put(Some(&"0".repeat(64)), None)).await;
    assert_eq!(wrong.code(), "csrf_token_invalid");
    let foreign = h
        .send(put(
            Some(&admin.csrf),
            Some(("origin", "https://attacker.example")),
        ))
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    assert_eq!(foreign.code(), "cross_site_request");
    let cross_site = h
        .send(put(
            Some(&admin.csrf),
            Some(("sec-fetch-site", "cross-site")),
        ))
        .await;
    assert_eq!(cross_site.code(), "cross_site_request");
    let null_origin = h
        .send(put(Some(&admin.csrf), Some(("origin", "null"))))
        .await;
    assert_eq!(null_origin.code(), "cross_site_request");
    // Nothing changed.
    assert_eq!(h.db.storage.retention().await.unwrap().session_ttl_days, 30);
    // The same origin with the token works.
    let mut ok = put(Some(&admin.csrf), Some(("sec-fetch-site", "same-origin")));
    ok.headers_mut()
        .insert(header::HOST, "127.0.0.1:8080".parse().unwrap());
    ok.headers_mut()
        .insert(header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
    let reply = h.send(ok).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    // Reads need no token.
    let read = h
        .send(
            Request::get("/api/v1/settings/retention")
                .header(header::COOKIE, &admin.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(read.status, StatusCode::OK);
    let denied = h.audit("access.denied").await;
    assert_eq!(denied.len(), 2);
    assert!(
        denied
            .iter()
            .all(|e| e["details"]["reason"] == "csrf_token_invalid")
    );
    h.db.drop_database().await;
}

#[tokio::test]
async fn roles_limit_what_each_account_may_do() {
    let Some(h) = Harness::new("auth_roles").await else {
        return;
    };
    h.add_user("root", Role::Admin).await;
    h.add_user("ana", Role::Analyst).await;
    h.add_user("vic", Role::Viewer).await;
    let admin = h.sign_in("root").await;
    let analyst = h.sign_in("ana").await;
    let viewer = h.sign_in("vic").await;

    // Viewers read but cannot import.
    let refused = h.upload(&viewer).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.code(), "forbidden");
    assert!(
        refused.body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("analyst")
    );
    // Analysts import and triage.
    let imported = h.upload(&analyst).await;
    assert_eq!(imported.status, StatusCode::CREATED, "{}", imported.body);
    let id = imported.body["id"].as_i64().unwrap();
    let alert = format!("/api/v1/captures/{id}/alerts/1");
    let triage = json!({ "status": "acknowledged" });
    assert_eq!(
        h.call(Some(&viewer), Method::PATCH, &alert, Some(triage.clone()))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.call(Some(&analyst), Method::PATCH, &alert, Some(triage))
            .await
            .status,
        StatusCode::OK
    );
    for client in [&viewer, &analyst] {
        let reads = [
            format!("/api/v1/captures/{id}"),
            format!("/api/v1/captures/{id}/packets"),
            format!("/api/v1/captures/{id}/flows"),
            format!("/api/v1/captures/{id}/alerts"),
            "/api/v1/settings/retention".to_owned(),
            "/api/v1/overview".to_owned(),
        ];
        for uri in reads {
            let reply = h.call(Some(client), Method::GET, &uri, None).await;
            assert_eq!(reply.status, StatusCode::OK, "{uri}");
        }
        // Admin-only actions.
        let retention = json!({ "session_ttl_days": 1, "max_packets_stored": 0 });
        let attempts = [
            (Method::DELETE, format!("/api/v1/captures/{id}"), None),
            (
                Method::PUT,
                "/api/v1/settings/retention".to_owned(),
                Some(retention),
            ),
            (Method::GET, "/api/v1/users".to_owned(), None),
            (
                Method::POST,
                "/api/v1/users".to_owned(),
                Some(json!({ "username": "x", "password": PASSWORD, "role": "admin" })),
            ),
            (Method::DELETE, "/api/v1/users/1".to_owned(), None),
            (Method::GET, "/api/v1/audit".to_owned(), None),
        ];
        for (method, uri, body) in attempts {
            let reply = h.call(Some(client), method.clone(), &uri, body).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method} {uri}");
            assert_eq!(reply.code(), "forbidden");
        }
    }
    // Admins may.
    let deleted = h
        .call(
            Some(&admin),
            Method::DELETE,
            &format!("/api/v1/captures/{id}"),
            None,
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    // Every refusal and change is audited with who did it.
    let denied = h.audit("access.denied").await;
    assert_eq!(denied.len(), 14);
    assert!(denied.iter().all(|e| e["outcome"] == "denied"));
    assert!(denied.iter().any(|e| e["actor"] == "vic"
        && e["details"]["required"] == "analyst"
        && e["details"]["path"] == "/api/v1/captures"));
    let import = &h.audit("capture.import").await[0];
    assert_eq!(import["actor"], "ana");
    assert_eq!(import["target_id"], id.to_string());
    assert_eq!(import["details"]["file_name"], "detect-mixed.pcap");
    let status = &h.audit("alert.status_change").await[0];
    assert_eq!(status["target_id"], format!("{id}/1"));
    assert_eq!(status["details"]["status"], "acknowledged");
    assert_eq!(h.audit("capture.delete").await[0]["actor"], "root");
    h.db.drop_database().await;
}

#[tokio::test]
async fn sessions_end_when_idle_expired_or_superseded() {
    let Some(h) = Harness::new("auth_expiry").await else {
        return;
    };
    let id = h.add_user("ana", Role::Analyst).await;
    let idle = h.sign_in("ana").await;
    h.sql("UPDATE auth_sessions SET last_seen_at = now() - interval '31 minutes'")
        .await;
    let reply = h
        .call(Some(&idle), Method::GET, "/api/v1/captures", None)
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    let expired = h.sign_in("ana").await;
    h.sql("UPDATE auth_sessions SET expires_at = now() - interval '1 second'")
        .await;
    let reply = h
        .call(Some(&expired), Method::GET, "/api/v1/captures", None)
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.db.storage
            .purge_auth_sessions(std::time::Duration::from_secs(1800))
            .await
            .unwrap(),
        2
    );

    // At most ten sessions per account: the oldest ends.
    let first = h.sign_in("ana").await;
    for _ in 0..10 {
        h.sign_in("ana").await;
    }
    let count: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM auth_sessions WHERE user_id = {id}"
    ))
    .fetch_one(h.db.storage.pool())
    .await
    .unwrap();
    assert_eq!(count, 10);
    let reply = h
        .call(Some(&first), Method::GET, "/api/v1/captures", None)
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    h.db.drop_database().await;
}

#[tokio::test]
async fn changing_a_password_ends_other_sessions() {
    let Some(h) = Harness::new("auth_password").await else {
        return;
    };
    h.add_user("ana", Role::Analyst).await;
    let laptop = h.sign_in("ana").await;
    let phone = h.sign_in("ana").await;
    let new_password = "a much better passphrase";

    let wrong = h
        .call(
            Some(&laptop),
            Method::PUT,
            "/api/v1/auth/password",
            Some(json!({ "current_password": "not it at all", "new_password": new_password })),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.code(), "wrong_password");
    let weak = h
        .call(
            Some(&laptop),
            Method::PUT,
            "/api/v1/auth/password",
            Some(json!({ "current_password": PASSWORD, "new_password": "short" })),
        )
        .await;
    assert_eq!(weak.code(), "weak_password");

    let changed = h
        .call(
            Some(&laptop),
            Method::PUT,
            "/api/v1/auth/password",
            Some(json!({ "current_password": PASSWORD, "new_password": new_password })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    let renewed = client_from(&changed);
    assert_ne!(renewed.cookie, laptop.cookie);
    for old in [&laptop, &phone] {
        let reply = h
            .call(Some(old), Method::GET, "/api/v1/captures", None)
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let reply = h
        .call(Some(&renewed), Method::GET, "/api/v1/captures", None)
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        h.login("ana", PASSWORD).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.login("ana", new_password).await.status, StatusCode::OK);
    let events = h.audit("auth.password_change").await;
    assert_eq!(
        events
            .iter()
            .map(|e| e["outcome"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["success", "failure"]
    );
    assert!(
        !serde_json::to_string(&events)
            .unwrap()
            .contains(new_password)
    );
    h.db.drop_database().await;
}

#[tokio::test]
async fn admins_manage_accounts_but_keep_one_admin() {
    let Some(h) = Harness::new("auth_users").await else {
        return;
    };
    let root_id = h.add_user("root", Role::Admin).await;
    let admin = h.sign_in("root").await;

    let created = h
        .call(
            Some(&admin),
            Method::POST,
            "/api/v1/users",
            Some(json!({ "username": "New.User", "password": PASSWORD, "role": "viewer" })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["username"], "new.user");
    assert!(created.body.get("password_hash").is_none());
    let user_id = created.body["id"].as_i64().unwrap();
    let cases = [
        (
            json!({ "username": "new.user", "password": PASSWORD, "role": "viewer" }),
            StatusCode::CONFLICT,
            "username_taken",
        ),
        (
            json!({ "username": "bad name", "password": PASSWORD, "role": "viewer" }),
            StatusCode::BAD_REQUEST,
            "invalid_username",
        ),
        (
            json!({ "username": "other", "password": "short", "role": "viewer" }),
            StatusCode::BAD_REQUEST,
            "weak_password",
        ),
        (
            json!({ "username": "other", "password": PASSWORD, "role": "root" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body",
        ),
    ];
    for (body, status, code) in cases {
        let reply = h
            .call(Some(&admin), Method::POST, "/api/v1/users", Some(body))
            .await;
        assert_eq!((reply.status, reply.code()), (status, code));
    }
    let list = h
        .call(Some(&admin), Method::GET, "/api/v1/users", None)
        .await;
    assert_eq!(list.body["total"], 2);
    assert!(!list.body.to_string().contains("argon2"));

    // A role change ends the account's sessions.
    let user = h.sign_in("new.user").await;
    let promoted = h
        .call(
            Some(&admin),
            Method::PATCH,
            &format!("/api/v1/users/{user_id}"),
            Some(json!({ "role": "analyst" })),
        )
        .await;
    assert_eq!(promoted.status, StatusCode::OK);
    assert_eq!(promoted.body["role"], "analyst");
    let reply = h
        .call(Some(&user), Method::GET, "/api/v1/captures", None)
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    // An admin password reset works and is checked.
    let reset = h
        .call(
            Some(&admin),
            Method::PATCH,
            &format!("/api/v1/users/{user_id}"),
            Some(json!({ "password": "reset by the admin today" })),
        )
        .await;
    assert_eq!(reset.status, StatusCode::OK);
    assert_eq!(
        h.login("new.user", "reset by the admin today").await.status,
        StatusCode::OK
    );
    let nothing = h
        .call(
            Some(&admin),
            Method::PATCH,
            &format!("/api/v1/users/{user_id}"),
            Some(json!({})),
        )
        .await;
    assert_eq!(nothing.code(), "nothing_to_change");

    // The only admin cannot be demoted, disabled or deleted.
    for change in [json!({ "role": "viewer" }), json!({ "disabled": true })] {
        let reply = h
            .call(
                Some(&admin),
                Method::PATCH,
                &format!("/api/v1/users/{root_id}"),
                Some(change),
            )
            .await;
        assert_eq!(
            (reply.status, reply.code()),
            (StatusCode::CONFLICT, "last_admin")
        );
    }
    let own = h
        .call(
            Some(&admin),
            Method::DELETE,
            &format!("/api/v1/users/{root_id}"),
            None,
        )
        .await;
    assert_eq!(own.code(), "cannot_delete_self");
    assert_eq!(
        h.db.storage.delete_user(root_id).await.unwrap(),
        storage::AccountChange::LastAdmin
    );
    let missing = h
        .call(Some(&admin), Method::DELETE, "/api/v1/users/9999", None)
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    let deleted = h
        .call(
            Some(&admin),
            Method::DELETE,
            &format!("/api/v1/users/{user_id}"),
            None,
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    // With a second admin, the first may step down.
    let second = h.add_user("second", Role::Admin).await;
    let demoted = h
        .call(
            Some(&admin),
            Method::PATCH,
            &format!("/api/v1/users/{root_id}"),
            Some(json!({ "role": "viewer" })),
        )
        .await;
    assert_eq!(demoted.status, StatusCode::OK);
    assert_eq!(
        h.db.storage.delete_user(second).await.unwrap(),
        storage::AccountChange::LastAdmin
    );

    // The audit log, filtered, newest first; it never holds passwords.
    let other_admin = h.sign_in("second").await;
    let audit = h
        .call(
            Some(&other_admin),
            Method::GET,
            "/api/v1/audit?action=user.update&per_page=10",
            None,
        )
        .await;
    assert_eq!(audit.status, StatusCode::OK);
    let items = audit.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["details"]["role"], "viewer");
    assert_eq!(items[1]["details"]["password_reset"], true);
    let everything = h
        .call(
            Some(&other_admin),
            Method::GET,
            "/api/v1/audit?per_page=500",
            None,
        )
        .await;
    let text = everything.body.to_string();
    assert!(!text.contains(PASSWORD) && !text.contains("reset by the admin today"));
    for bad in ["action=DROP%20TABLE", "outcome=maybe", "page=0"] {
        let reply = h
            .call(
                Some(&other_admin),
                Method::GET,
                &format!("/api/v1/audit?{bad}"),
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    h.db.drop_database().await;
}

#[tokio::test]
async fn the_first_admin_is_created_only_once() {
    let Some(h) = Harness::new("auth_bootstrap").await else {
        return;
    };
    let storage = &h.db.storage;
    assert!(
        bootstrap::first_admin(storage, "admin", "short".to_owned())
            .await
            .is_err()
    );
    let first = bootstrap::first_admin(storage, "Admin", PASSWORD.to_owned())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (first.username.as_str(), first.role),
        ("admin", Role::Admin)
    );
    let again = bootstrap::first_admin(storage, "other", PASSWORD.to_owned())
        .await
        .unwrap();
    assert_eq!(again, None);
    assert_eq!(storage.count_users().await.unwrap(), 1);
    assert_eq!(h.audit("user.bootstrap").await.len(), 1);
    let duplicate =
        bootstrap::create_user(storage, "admin", Role::Viewer, PASSWORD.to_owned()).await;
    assert!(duplicate.unwrap_err().contains("exists"));
    assert_eq!(h.login("admin", PASSWORD).await.status, StatusCode::OK);
    h.db.drop_database().await;
}
