//! Sign-in sessions, CSRF protection and role checks.
//!
//! A session is a random 256-bit token held in an `HttpOnly`,
//! `SameSite=Strict` cookie. The database stores only its SHA-256 digest.
//! State-changing requests must also send the session's CSRF token in the
//! `X-CSRF-Token` header; it is derived from the session token, so it needs
//! no storage and cannot be guessed without the cookie.
//!
//! Passwords are hashed with Argon2id (19 MiB, 2 passes, 1 lane: the OWASP
//! recommended minimum) on blocking threads, at most
//! [`MAX_CONCURRENT_HASHES`] at a time.

use std::fmt;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use sha2::{Digest, Sha256};
use storage::{AuditOutcome, NewAuditEvent, Role};

use crate::audit;
use crate::error::ApiError;
use crate::state::AppState;

/// Cookie name over plain HTTP.
pub const COOKIE_NAME: &str = "flowsentinel_session";
/// Cookie name with `FLOWSENTINEL_SECURE_COOKIES=true`. The `__Host-` prefix
/// makes browsers refuse it unless it is `Secure`, host-only and for `/`, so
/// a sibling subdomain cannot plant one.
pub const SECURE_COOKIE_NAME: &str = "__Host-flowsentinel_session";
/// Header that carries the CSRF token on state-changing requests.
pub const CSRF_HEADER: &str = "x-csrf-token";
/// Argon2id hashes computed at once (each uses 19 MiB).
pub const MAX_CONCURRENT_HASHES: usize = 4;
/// Sessions kept per account; signing in again ends the oldest.
pub const MAX_SESSIONS_PER_USER: u32 = 10;

pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_CHARS: usize = 256;
/// Longest password accepted at sign-in, in bytes (longer ones are refused
/// without hashing).
pub const MAX_PASSWORD_BYTES: usize = 1024;
pub const MAX_USERNAME_CHARS: usize = 64;

const CSRF_CONTEXT: &[u8] = b"flowsentinel-csrf-v1\0";

/// Session settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthConfig {
    /// A session ends after this long without a request.
    pub session_idle: Duration,
    /// A session ends this long after sign-in, however active.
    pub session_lifetime: Duration,
    /// Mark the cookie `Secure` (and use the `__Host-` name). Needs HTTPS.
    pub secure_cookies: bool,
    /// Audit events older than this are deleted.
    pub audit_retention_days: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_idle: Duration::from_secs(30 * 60),
            session_lifetime: Duration::from_secs(12 * 3600),
            secure_cookies: false,
            audit_retention_days: 365,
        }
    }
}

impl AuthConfig {
    pub fn cookie_name(&self) -> &'static str {
        if self.secure_cookies {
            SECURE_COOKIE_NAME
        } else {
            COOKIE_NAME
        }
    }

    fn cookie(&self, value: &str, max_age: u64) -> Result<HeaderValue, ApiError> {
        let secure = if self.secure_cookies { "; Secure" } else { "" };
        HeaderValue::try_from(format!(
            "{}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
            self.cookie_name()
        ))
        .map_err(|e| ApiError::internal("session cookie", &e))
    }

    /// `Set-Cookie` value that starts a session.
    pub fn session_cookie(&self, token: &SessionToken) -> Result<HeaderValue, ApiError> {
        self.cookie(&token.to_hex(), self.session_lifetime.as_secs())
    }

    /// `Set-Cookie` value that removes the session cookie.
    pub fn clear_cookie(&self) -> Result<HeaderValue, ApiError> {
        self.cookie("", 0)
    }
}

/// A session token. `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken([u8; 32]);

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken([redacted])")
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Compares in time independent of where the inputs differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl SessionToken {
    /// A new token from the operating system's random number generator.
    pub fn generate() -> Result<Self, ApiError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| ApiError::internal("random token", &e))?;
        Ok(Self(bytes))
    }

    /// Parses the cookie form: exactly 64 lowercase hex digits.
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.as_bytes();
        if digits.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
            let (&high, &low) = (pair.first()?, pair.get(1)?);
            *byte = (hex_value(high)? << 4) | hex_value(low)?;
        }
        Some(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// What the database stores.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }

    /// The CSRF token for this session.
    pub fn csrf_token(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(CSRF_CONTEXT);
        hasher.update(self.0);
        hex(&hasher.finalize())
    }

    /// The session token from a request's `Cookie` headers.
    pub fn from_headers(headers: &HeaderMap, cookie_name: &str) -> Option<Self> {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(name, _)| *name == cookie_name)
            .and_then(|(_, value)| Self::parse(value.trim()))
    }
}

/// The signed-in account, set by [`authenticate`] for every protected route.
#[derive(Clone, PartialEq, Eq)]
pub struct CurrentUser {
    pub session_id: i64,
    pub user_id: i64,
    pub username: String,
    pub role: Role,
    pub expires_at: String,
    pub csrf_token: String,
}

impl fmt::Debug for CurrentUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurrentUser")
            .field("session_id", &self.session_id)
            .field("user_id", &self.user_id)
            .field("username", &self.username)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// The client's address, when the server knows it (not in in-process tests).
/// Behind a reverse proxy this is the proxy's address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(client_ip(parts)))
    }
}

fn client_ip(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

fn is_state_changing(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

pub fn unauthenticated() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "sign in first; the session is missing, has expired or was ended",
    )
}

/// Middleware for protected routes: resolves the session cookie to an
/// account, checks the CSRF token on state-changing requests, and stores a
/// [`CurrentUser`] for the handlers.
pub async fn authenticate(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let auth = state.config.auth;
    let Some(token) = SessionToken::from_headers(request.headers(), auth.cookie_name()) else {
        return unauthenticated().into_response();
    };
    let found = async {
        let _slot = state.read_slot().await?;
        Ok::<_, ApiError>(
            state
                .storage
                .session_user(&token.digest(), auth.session_idle)
                .await?,
        )
    }
    .await;
    let user = match found {
        Ok(Some(user)) => user,
        Ok(None) => {
            // Tell the browser to drop the dead cookie.
            let mut response = unauthenticated().into_response();
            if let Ok(clear) = auth.clear_cookie() {
                response.headers_mut().insert(header::SET_COOKIE, clear);
            }
            return response;
        }
        Err(err) => return err.into_response(),
    };
    let csrf_token = token.csrf_token();
    let (mut parts, body) = request.into_parts();
    if is_state_changing(&parts.method) {
        let sent = parts
            .headers
            .get(CSRF_HEADER)
            .map(HeaderValue::as_bytes)
            .unwrap_or_default();
        if !constant_time_eq(sent, csrf_token.as_bytes()) {
            audit::record(
                &state,
                NewAuditEvent {
                    actor_id: Some(user.user_id),
                    actor: Some(user.username.clone()),
                    action: "access.denied",
                    outcome: AuditOutcome::Denied,
                    target_type: None,
                    target_id: None,
                    client_ip: client_ip(&parts),
                    details: json!({
                        "reason": "csrf_token_invalid",
                        "method": parts.method.as_str(),
                        "path": audit::path_of(&parts),
                    }),
                },
            )
            .await;
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "csrf_token_invalid",
                "missing or wrong X-CSRF-Token header; reload the page and try again",
            )
            .into_response();
        }
    }
    parts.extensions.insert(CurrentUser {
        session_id: user.session_id,
        user_id: user.user_id,
        username: user.username,
        role: user.role,
        expires_at: user.expires_at,
        csrf_token,
    });
    next.run(Request::from_parts(parts, body)).await
}

/// The host part of an `Origin` header value (`scheme://host[:port]`).
fn origin_authority(origin: &str) -> Option<&str> {
    let (_, rest) = origin.split_once("://")?;
    (!rest.is_empty() && !rest.contains('/')).then_some(rest)
}

/// Route layer for every `/api/v1` route: refuses state-changing requests
/// that a browser marks as coming from another site, in addition to the
/// CSRF token and `SameSite` cookies. Unknown paths get `404` either way.
pub async fn same_origin(request: Request, next: Next) -> Response {
    if is_state_changing(request.method()) {
        let headers = request.headers();
        let site = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok());
        let cross_site = site.is_some_and(|site| site != "same-origin" && site != "none");
        let origin = headers
            .get(header::ORIGIN)
            .map(|v| v.to_str().unwrap_or(""));
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .or_else(|| request.uri().authority().map(|a| a.as_str()));
        let foreign_origin = origin.is_some_and(|origin| match (origin_authority(origin), host) {
            (Some(authority), Some(host)) => !authority.eq_ignore_ascii_case(host),
            _ => true,
        });
        if cross_site || foreign_origin {
            // The route template, never the path: paths can hold IDs.
            tracing::warn!(
                method = %request.method(),
                route = request
                    .extensions()
                    .get::<axum::extract::MatchedPath>()
                    .map_or("", |m| m.as_str()),
                "refused a cross-site state-changing request"
            );
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "cross_site_request",
                "state-changing requests must come from the dashboard's own origin",
            )
            .into_response();
        }
    }
    next.run(request).await
}

/// The minimum role a handler needs.
pub trait MinRole: Send + Sync + 'static {
    const ROLE: Role;
}

/// Marker for [`Authorized`]: any signed-in account.
#[derive(Debug)]
pub struct Viewer;
/// Marker for [`Authorized`]: analysts and admins.
#[derive(Debug)]
pub struct Analyst;
/// Marker for [`Authorized`]: admins only.
#[derive(Debug)]
pub struct Admin;

impl MinRole for Viewer {
    const ROLE: Role = Role::Viewer;
}
impl MinRole for Analyst {
    const ROLE: Role = Role::Analyst;
}
impl MinRole for Admin {
    const ROLE: Role = Role::Admin;
}

/// Extractor: the signed-in account, if its role includes `R`. Otherwise the
/// request is refused with `403` and the refusal is audited.
#[derive(Debug)]
pub struct Authorized<R: MinRole>(pub CurrentUser, PhantomData<R>);

impl<R: MinRole> Authorized<R> {
    pub fn user(&self) -> &CurrentUser {
        &self.0
    }
}

impl<R: MinRole> FromRequestParts<AppState> for Authorized<R> {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = parts
            .extensions
            .get::<CurrentUser>()
            .cloned()
            .ok_or_else(unauthenticated)?;
        if user.role.includes(R::ROLE) {
            return Ok(Self(user, PhantomData));
        }
        audit::record(
            state,
            NewAuditEvent {
                actor_id: Some(user.user_id),
                actor: Some(user.username.clone()),
                action: "access.denied",
                outcome: AuditOutcome::Denied,
                target_type: None,
                target_id: None,
                client_ip: client_ip(parts),
                details: json!({
                    "reason": "role",
                    "role": user.role,
                    "required": R::ROLE,
                    "method": parts.method.as_str(),
                    "path": audit::path_of(parts),
                }),
            },
        )
        .await;
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            format!("this action needs the {} role", R::ROLE),
        ))
    }
}

/// Lowercases a username and checks it: 1 to 64 characters, ASCII letters,
/// digits, `.`, `_` or `-`, starting with a letter or digit.
pub fn normalize_username(name: &str) -> Result<String, ApiError> {
    let lower = name.to_ascii_lowercase();
    let mut chars = lower.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if first_ok && rest_ok && lower.chars().count() <= MAX_USERNAME_CHARS {
        Ok(lower)
    } else {
        Err(ApiError::bad_request(
            "invalid_username",
            "usernames have 1 to 64 letters, digits, '.', '_' or '-', and start with a letter or digit",
        ))
    }
}

/// Checks a new password: 12 to 256 characters, not containing the username
/// (of 4 or more characters) or equal to it, and not one repeated character.
/// Any characters are allowed; there are no composition rules
/// (NIST SP 800-63B).
pub fn check_new_password(password: &str, username: &str) -> Result<(), ApiError> {
    let chars = password.chars().count();
    let weak = |message: &str| Err(ApiError::bad_request("weak_password", message));
    if !(MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&chars) {
        return weak("passwords need 12 to 256 characters");
    }
    let lower = password.to_lowercase();
    if lower == username || (username.chars().count() >= 4 && lower.contains(username)) {
        return weak("the password must not contain the username");
    }
    let mut distinct = password.chars();
    let first = distinct.next();
    if distinct.all(|c| Some(c) == first) {
        return weak("the password must not be one repeated character");
    }
    Ok(())
}

fn hasher() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
}

/// Hashes a password to an Argon2id PHC string. Slow by design: call it on a
/// blocking thread.
pub fn hash_password(password: &str) -> Result<String, String> {
    hasher()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| e.to_string())
}

/// Checks a password against a stored PHC string. Slow by design.
pub fn verify_password(password: &str, hash: &str) -> bool {
    hasher().verify_password(password.as_bytes(), hash).is_ok()
}

/// A hash of a random password, verified when the username does not exist
/// so that sign-in takes as long as for a real account.
pub fn decoy_hash() -> &'static str {
    static DECOY: OnceLock<String> = OnceLock::new();
    DECOY.get_or_init(|| {
        let mut random = [0u8; 16];
        // On failure the decoy is still a valid hash, of a fixed string.
        let _ = getrandom::fill(&mut random);
        hash_password(&hex(&random)).unwrap_or_default()
    })
}

/// Waits up to 10 s for a hashing slot.
pub async fn hash_slot(state: &AppState) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
    let acquire = std::sync::Arc::clone(&state.hash_slots).acquire_owned();
    match tokio::time::timeout(Duration::from_secs(10), acquire).await {
        Ok(Ok(permit)) => Ok(permit),
        _ => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_busy",
            "the server is busy; try again shortly",
        )),
    }
}

/// Runs password hashing or checking on a blocking thread.
pub async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| ApiError::internal("password hashing", &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_trip_through_their_cookie_form() {
        let token = SessionToken::generate().unwrap();
        let text = token.to_hex();
        assert_eq!(text.len(), 64);
        assert_eq!(SessionToken::parse(&text), Some(token.clone()));
        assert_ne!(SessionToken::generate().unwrap(), token);
        assert!(!format!("{token:?}").contains(&text));
        for bad in [
            "",
            &text[..63],
            &format!("{text}0"),
            &text.to_uppercase(),
            &format!("{}g", &text[..63]),
            &format!("{}é", &text[..62]),
        ] {
            assert_eq!(SessionToken::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn digests_and_csrf_tokens_differ_from_the_token() {
        let token = SessionToken::parse(&"ab".repeat(32)).unwrap();
        assert_ne!(hex(&token.digest()), token.to_hex());
        assert_ne!(token.csrf_token(), token.to_hex());
        assert_ne!(token.csrf_token(), hex(&token.digest()));
        assert_eq!(token.csrf_token().len(), 64);
        let other = SessionToken::parse(&"cd".repeat(32)).unwrap();
        assert_ne!(token.csrf_token(), other.csrf_token());
    }

    #[test]
    fn the_session_cookie_is_found_among_others() {
        let token = SessionToken::parse(&"0f".repeat(32)).unwrap();
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("theme=dark"));
        headers.append(
            header::COOKIE,
            HeaderValue::try_from(format!("a=1; {COOKIE_NAME}={}; b=2", token.to_hex())).unwrap(),
        );
        assert_eq!(
            SessionToken::from_headers(&headers, COOKIE_NAME),
            Some(token)
        );
        assert_eq!(
            SessionToken::from_headers(&headers, SECURE_COOKIE_NAME),
            None
        );
        let mut bad = HeaderMap::new();
        bad.insert(
            header::COOKIE,
            HeaderValue::from_static("flowsentinel_session=short"),
        );
        assert_eq!(SessionToken::from_headers(&bad, COOKIE_NAME), None);
    }

    #[test]
    fn cookies_are_http_only_strict_and_secure_when_configured() {
        let token = SessionToken::parse(&"11".repeat(32)).unwrap();
        let plain = AuthConfig::default().session_cookie(&token).unwrap();
        let plain = plain.to_str().unwrap();
        assert!(plain.starts_with("flowsentinel_session="));
        assert!(plain.contains("; HttpOnly; SameSite=Strict; Max-Age=43200"));
        assert!(!plain.contains("Secure"));
        let secure = AuthConfig {
            secure_cookies: true,
            ..AuthConfig::default()
        };
        let cookie = secure.session_cookie(&token).unwrap();
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.starts_with("__Host-flowsentinel_session="));
        assert!(cookie.ends_with("; Secure"));
        assert!(cookie.contains("Path=/"));
        assert!(!cookie.contains("Domain"));
        let clear = secure.clear_cookie().unwrap();
        assert!(clear.to_str().unwrap().contains("Max-Age=0"));
    }

    #[test]
    fn usernames_are_normalized_and_validated() {
        assert_eq!(normalize_username("Ana.Lyst-2").unwrap(), "ana.lyst-2");
        assert_eq!(normalize_username(&"a".repeat(64)).unwrap().len(), 64);
        for bad in [
            "",
            ".hidden",
            "-dash",
            "has space",
            "semi;colon",
            "ünïcode",
            &"a".repeat(65),
        ] {
            assert_eq!(
                normalize_username(bad).unwrap_err().code,
                "invalid_username",
                "{bad}"
            );
        }
    }

    #[test]
    fn new_passwords_are_checked() {
        assert!(check_new_password("correct horse battery", "ana").is_ok());
        assert!(check_new_password("ünïcödé pässwörd ✓", "ana").is_ok());
        assert!(check_new_password("bananas and apples", "an").is_ok());
        assert_eq!(
            check_new_password("ANNA-is-the-best-user", "anna")
                .unwrap_err()
                .code,
            "weak_password"
        );
        assert_eq!(
            check_new_password("abcdefghijklm", "abcdefghijklm")
                .unwrap_err()
                .code,
            "weak_password"
        );
        for bad in ["short", "aaaaaaaaaaaaaaaa", &"x".repeat(257)] {
            assert_eq!(
                check_new_password(bad, "ana").unwrap_err().code,
                "weak_password",
                "{bad}"
            );
        }
    }

    #[test]
    fn passwords_hash_to_argon2id_and_verify() {
        let hash = hash_password("correct horse battery").unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{hash}"
        );
        assert!(verify_password("correct horse battery", &hash));
        assert!(!verify_password("correct horse battery!", &hash));
        assert!(!verify_password("correct horse battery", "not a hash"));
        assert_ne!(hash_password("correct horse battery").unwrap(), hash);
        assert!(!verify_password("anything", decoy_hash()));
        assert!(decoy_hash().starts_with("$argon2id$"));
    }

    #[test]
    fn origins_are_compared_by_authority() {
        assert_eq!(
            origin_authority("http://127.0.0.1:8080"),
            Some("127.0.0.1:8080")
        );
        assert_eq!(origin_authority("https://lab.example"), Some("lab.example"));
        assert_eq!(origin_authority("null"), None);
        assert_eq!(origin_authority("http://a/b"), None);
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
