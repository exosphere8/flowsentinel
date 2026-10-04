//! Sign-in, sign-out, password changes, account management and the audit
//! log (`/api/v1/auth/...`, `/api/v1/users`, `/api/v1/audit`).

use std::fmt;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use storage::{
    AccountChange, AuditEvent, AuditFilter, AuditOutcome, NewAuditEvent, Paged, Role, User,
    UserUpdate,
};
use utoipa::{IntoParams, ToSchema};

use crate::audit;
use crate::auth::{
    self, Admin, Authorized, ClientIp, CurrentUser, MAX_PASSWORD_BYTES, MAX_SESSIONS_PER_USER,
    SessionToken, Viewer,
};
use crate::error::{ApiError, ErrorResponse};
use crate::extract::{ApiJson, ApiPath, ApiQuery};
use crate::routes::page_of;
use crate::state::AppState;

/// The signed-in account, as the dashboard sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SessionAccount {
    pub id: i64,
    pub username: String,
    pub role: Role,
}

/// A signed-in session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SessionInfo {
    pub user: SessionAccount,
    /// Send this in the `X-CSRF-Token` header with every `POST`, `PUT`,
    /// `PATCH` and `DELETE` request.
    pub csrf_token: String,
    /// When the session ends at the latest (RFC 3339 UTC).
    pub expires_at: String,
    /// The session also ends after this many seconds without a request.
    pub idle_timeout_seconds: u64,
}

/// Credentials for `POST /auth/login`. `Debug` never shows the password.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// Body of `PUT /auth/password`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasswordChange {
    pub current_password: String,
    /// 12 to 256 characters, not containing the username.
    pub new_password: String,
}

impl fmt::Debug for PasswordChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordChange { .. }")
    }
}

/// Body of `POST /users`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewUser {
    /// 1 to 64 letters, digits, `.`, `_` or `-`; stored lowercase.
    pub username: String,
    /// 12 to 256 characters, not containing the username.
    pub password: String,
    pub role: Role,
}

impl fmt::Debug for NewUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewUser")
            .field("username", &self.username)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// Body of `PATCH /users/{id}`. Changing the role, the enabled state or the
/// password ends the account's sessions.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UserPatch {
    pub role: Option<Role>,
    pub disabled: Option<bool>,
    /// A new password, set by an admin.
    pub password: Option<String>,
}

impl fmt::Debug for UserPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserPatch")
            .field("role", &self.role)
            .field("disabled", &self.disabled)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub struct UserListParams {
    /// 1-based page number (default 1, at most 1000000).
    #[param(minimum = 1, maximum = 1000000)]
    pub page: Option<u32>,
    /// Items per page, 1-500 (default 50).
    #[param(minimum = 1, maximum = 500)]
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub struct AuditListParams {
    /// 1-based page number (default 1, at most 1000000).
    #[param(minimum = 1, maximum = 1000000)]
    pub page: Option<u32>,
    /// Items per page, 1-500 (default 50).
    #[param(minimum = 1, maximum = 500)]
    pub per_page: Option<u32>,
    /// Only this action, for example `auth.login`.
    pub action: Option<String>,
    /// `success`, `failure` or `denied`.
    pub outcome: Option<String>,
    /// Only events by this account name.
    pub actor: Option<String>,
}

fn session_info(state: &AppState, user: &CurrentUser) -> SessionInfo {
    SessionInfo {
        user: SessionAccount {
            id: user.user_id,
            username: user.username.clone(),
            role: user.role,
        },
        csrf_token: user.csrf_token.clone(),
        expires_at: user.expires_at.clone(),
        idle_timeout_seconds: state.config.auth.session_idle.as_secs(),
    }
}

/// Starts a session for an account and builds the response that sets its
/// cookie.
async fn start_session(
    state: &AppState,
    user_id: i64,
    username: &str,
    role: Role,
    status: StatusCode,
) -> Result<Response, ApiError> {
    let auth = state.config.auth;
    let token = SessionToken::generate()?;
    let expires_at = state
        .storage
        .create_auth_session(
            user_id,
            &token.digest(),
            auth.session_lifetime,
            MAX_SESSIONS_PER_USER,
        )
        .await?;
    let info = SessionInfo {
        user: SessionAccount {
            id: user_id,
            username: username.to_owned(),
            role,
        },
        csrf_token: token.csrf_token(),
        expires_at,
        idle_timeout_seconds: auth.session_idle.as_secs(),
    };
    Ok((
        status,
        [
            (header::SET_COOKIE, auth.session_cookie(&token)?),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(info),
    )
        .into_response())
}

fn invalid_credentials() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_credentials",
        "the username or password is wrong, or the account is disabled",
    )
}

fn too_many_attempts(retry_after: std::time::Duration) -> Response {
    let seconds = retry_after.as_secs().max(1);
    let mut response = ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "too_many_attempts",
        format!("too many failed attempts; try again in {seconds} seconds"),
    )
    .into_response();
    if let Ok(value) = HeaderValue::try_from(seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// The name used for rate limiting and auditing a sign-in attempt: the
/// normalized username, or a marker for an invalid one.
fn attempted_name(username: &str) -> String {
    auth::normalize_username(username).unwrap_or_else(|_| "(invalid)".to_owned())
}

/// Sign in.
///
/// Sets the session cookie and returns the CSRF token. After 5 failures for
/// one username (or 20 from one address) within 15 minutes, attempts are
/// refused with `429` until the oldest failure is 15 minutes old.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    security(()),
    responses(
        (status = 200, description = "Signed in; the response sets the session cookie", body = SessionInfo),
        (status = 401, description = "Wrong username or password, or disabled account", body = ErrorResponse),
        (status = 403, description = "Cross-site request", body = ErrorResponse),
        (status = 422, description = "Malformed body", body = ErrorResponse),
        (status = 429, description = "Too many failed attempts; see Retry-After", body = ErrorResponse),
        (status = 503, description = "Server busy or database unavailable", body = ErrorResponse),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    ApiJson(request): ApiJson<LoginRequest>,
) -> Result<Response, ApiError> {
    let name = attempted_name(&request.username);
    let failed = |reason: &'static str| NewAuditEvent {
        actor_id: None,
        actor: Some(name.clone()),
        action: "auth.login",
        outcome: AuditOutcome::Failure,
        target_type: None,
        target_id: None,
        client_ip,
        details: json!({ "reason": reason }),
    };
    if let Err(retry_after) = state.login_limiter.check(&name, client_ip, Instant::now()) {
        audit::record(&state, failed("rate_limited")).await;
        return Ok(too_many_attempts(retry_after));
    }

    let _hashing = auth::hash_slot(&state).await?;
    let credentials = {
        let _slot = state.read_slot().await?;
        state.storage.credentials(&name).await?
    };
    let password = request.password;
    let too_long = password.len() > MAX_PASSWORD_BYTES;
    let stored = credentials.as_ref().map(|c| c.password_hash.clone());
    let matches = auth::blocking(move || match stored {
        Some(hash) if !too_long => auth::verify_password(&password, &hash),
        // The same work for unknown names, so timing does not reveal them.
        _ => {
            let _ = auth::verify_password("", auth::decoy_hash());
            false
        }
    })
    .await?;

    let account = match credentials {
        Some(account) if matches && !account.disabled => account,
        other => {
            state
                .login_limiter
                .failure(&name, client_ip, Instant::now());
            let reason = match other {
                None => "unknown_user",
                Some(_) if !matches => "wrong_password",
                Some(_) => "account_disabled",
            };
            audit::record(&state, failed(reason)).await;
            return Err(invalid_credentials());
        }
    };
    state.login_limiter.success(&account.username);
    let response = start_session(
        &state,
        account.id,
        &account.username,
        account.role,
        StatusCode::OK,
    )
    .await?;
    audit::record(
        &state,
        NewAuditEvent {
            actor_id: Some(account.id),
            outcome: AuditOutcome::Success,
            details: json!({ "role": account.role }),
            ..failed("")
        },
    )
    .await;
    Ok(response)
}

/// The current session.
#[utoipa::path(
    get,
    path = "/api/v1/auth/session",
    tag = "auth",
    responses(
        (status = 200, description = "The signed-in account and its CSRF token", body = SessionInfo),
        (status = 401, description = "Not signed in", body = ErrorResponse),
    )
)]
pub async fn session(State(state): State<AppState>, user: Authorized<Viewer>) -> Response {
    (
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(session_info(&state, user.user())),
    )
        .into_response()
}

/// Sign out: ends the session and removes its cookie.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    responses(
        (status = 204, description = "Signed out"),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Missing CSRF token or cross-site request", body = ErrorResponse),
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    user: Authorized<Viewer>,
) -> Result<Response, ApiError> {
    let user = user.user();
    state.storage.delete_auth_session(user.session_id).await?;
    audit::record(
        &state,
        NewAuditEvent {
            client_ip,
            ..audit::by(user, "auth.logout")
        },
    )
    .await;
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, state.config.auth.clear_cookie()?)],
    )
        .into_response())
}

/// Change your own password.
///
/// Ends every session of the account, including this one, and starts a new
/// session for this client: the response sets a new cookie and CSRF token.
#[utoipa::path(
    put,
    path = "/api/v1/auth/password",
    tag = "auth",
    request_body = PasswordChange,
    responses(
        (status = 200, description = "Changed; a new session", body = SessionInfo),
        (status = 400, description = "Wrong current password, or the new one is too weak", body = ErrorResponse),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Missing CSRF token or cross-site request", body = ErrorResponse),
        (status = 429, description = "Too many failed attempts; see Retry-After", body = ErrorResponse),
    )
)]
pub async fn change_password(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    user: Authorized<Viewer>,
    ApiJson(change): ApiJson<PasswordChange>,
) -> Result<Response, ApiError> {
    let user = user.user().clone();
    let event = |outcome, details| NewAuditEvent {
        client_ip,
        outcome,
        details,
        ..audit::by(&user, "auth.password_change")
    };
    if let Err(retry_after) = state
        .login_limiter
        .check(&user.username, client_ip, Instant::now())
    {
        audit::record(
            &state,
            event(AuditOutcome::Failure, json!({ "reason": "rate_limited" })),
        )
        .await;
        return Ok(too_many_attempts(retry_after));
    }
    auth::check_new_password(&change.new_password, &user.username)?;
    let _hashing = auth::hash_slot(&state).await?;
    let stored = state
        .storage
        .password_hash(user.user_id)
        .await?
        .ok_or_else(auth::unauthenticated)?;
    let current = change.current_password;
    let new = change.new_password;
    let too_long = current.len() > MAX_PASSWORD_BYTES;
    let hashed = auth::blocking(move || {
        if too_long || !auth::verify_password(&current, &stored) {
            return Ok(None);
        }
        auth::hash_password(&new).map(Some)
    })
    .await?
    .map_err(|e| ApiError::internal("password hashing", &e))?;
    let Some(hash) = hashed else {
        state
            .login_limiter
            .failure(&user.username, client_ip, Instant::now());
        audit::record(
            &state,
            event(AuditOutcome::Failure, json!({ "reason": "wrong_password" })),
        )
        .await;
        return Err(ApiError::bad_request(
            "wrong_password",
            "the current password is wrong",
        ));
    };
    if !state.storage.change_password(user.user_id, &hash).await? {
        return Err(auth::unauthenticated());
    }
    let response = start_session(
        &state,
        user.user_id,
        &user.username,
        user.role,
        StatusCode::OK,
    )
    .await?;
    audit::record(&state, event(AuditOutcome::Success, json!({}))).await;
    Ok(response)
}

/// List accounts (admin).
#[utoipa::path(
    get,
    path = "/api/v1/users",
    tag = "users",
    params(UserListParams),
    responses(
        (status = 200, description = "A page of accounts, by username", body = Paged<User>),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the admin role", body = ErrorResponse),
    )
)]
pub async fn list_users(
    State(state): State<AppState>,
    _admin: Authorized<Admin>,
    ApiQuery(params): ApiQuery<UserListParams>,
) -> Result<Json<Paged<User>>, ApiError> {
    let _slot = state.read_slot().await?;
    let page = page_of(params.page, params.per_page)?;
    Ok(Json(state.storage.list_users(page).await?))
}

/// Create an account (admin).
#[utoipa::path(
    post,
    path = "/api/v1/users",
    tag = "users",
    request_body = NewUser,
    responses(
        (status = 201, description = "Created", body = User),
        (status = 400, description = "Invalid username or weak password", body = ErrorResponse),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the admin role", body = ErrorResponse),
        (status = 409, description = "The username is taken", body = ErrorResponse),
        (status = 422, description = "Malformed body or unknown role", body = ErrorResponse),
    )
)]
pub async fn create_user(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    admin: Authorized<Admin>,
    ApiJson(new): ApiJson<NewUser>,
) -> Result<Response, ApiError> {
    let username = auth::normalize_username(&new.username)?;
    auth::check_new_password(&new.password, &username)?;
    let _hashing = auth::hash_slot(&state).await?;
    let password = new.password;
    let hash = auth::blocking(move || auth::hash_password(&password))
        .await?
        .map_err(|e| ApiError::internal("password hashing", &e))?;
    let created = {
        let _slot = state.read_slot().await?;
        state
            .storage
            .create_user(&username, &hash, new.role)
            .await?
    };
    let Some(user) = created else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "username_taken",
            "an account with this username exists",
        ));
    };
    audit::record(
        &state,
        NewAuditEvent {
            client_ip,
            target_type: Some("user"),
            target_id: Some(user.id.to_string()),
            details: json!({ "username": user.username, "role": user.role }),
            ..audit::by(admin.user(), "user.create")
        },
    )
    .await;
    Ok((StatusCode::CREATED, Json(user)).into_response())
}

fn last_admin() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "last_admin",
        "this would leave no enabled admin account; make another account admin first",
    )
}

/// Change an account's role, enabled state or password (admin).
///
/// Any of these changes ends the account's sessions. The last enabled admin
/// cannot be demoted or disabled.
#[utoipa::path(
    patch,
    path = "/api/v1/users/{id}",
    tag = "users",
    params(("id" = i64, Path, description = "Account ID")),
    request_body = UserPatch,
    responses(
        (status = 200, description = "The updated account", body = User),
        (status = 400, description = "Nothing to change, or a weak password", body = ErrorResponse),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the admin role", body = ErrorResponse),
        (status = 404, description = "No such account", body = ErrorResponse),
        (status = 409, description = "It would leave no enabled admin", body = ErrorResponse),
        (status = 422, description = "Malformed body or unknown role", body = ErrorResponse),
    )
)]
pub async fn update_user(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    admin: Authorized<Admin>,
    ApiPath(id): ApiPath<i64>,
    ApiJson(patch): ApiJson<UserPatch>,
) -> Result<Json<User>, ApiError> {
    if patch.role.is_none() && patch.disabled.is_none() && patch.password.is_none() {
        return Err(ApiError::bad_request(
            "nothing_to_change",
            "send at least one of role, disabled and password",
        ));
    }
    let password_hash = match patch.password {
        None => None,
        Some(password) => {
            let username = {
                let _slot = state.read_slot().await?;
                state
                    .storage
                    .user(id)
                    .await?
                    .ok_or_else(|| ApiError::not_found("account"))?
                    .username
            };
            auth::check_new_password(&password, &username)?;
            let _hashing = auth::hash_slot(&state).await?;
            Some(
                auth::blocking(move || auth::hash_password(&password))
                    .await?
                    .map_err(|e| ApiError::internal("password hashing", &e))?,
            )
        }
    };
    let update = UserUpdate {
        role: patch.role,
        disabled: patch.disabled,
        password_hash,
    };
    let changed = {
        let _slot = state.read_slot().await?;
        state.storage.update_user(id, &update).await?
    };
    let user = match changed {
        AccountChange::Done(user) => user,
        AccountChange::NotFound => return Err(ApiError::not_found("account")),
        AccountChange::LastAdmin => return Err(last_admin()),
    };
    audit::record(
        &state,
        NewAuditEvent {
            client_ip,
            target_type: Some("user"),
            target_id: Some(user.id.to_string()),
            details: json!({
                "username": user.username,
                "role": patch.role,
                "disabled": patch.disabled,
                "password_reset": update.password_hash.is_some(),
            }),
            ..audit::by(admin.user(), "user.update")
        },
    )
    .await;
    Ok(Json(user))
}

/// Delete an account and end its sessions (admin).
///
/// Admins cannot delete their own account, and the last enabled admin
/// cannot be deleted.
#[utoipa::path(
    delete,
    path = "/api/v1/users/{id}",
    tag = "users",
    params(("id" = i64, Path, description = "Account ID")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, description = "Cannot delete your own account", body = ErrorResponse),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the admin role", body = ErrorResponse),
        (status = 404, description = "No such account", body = ErrorResponse),
        (status = 409, description = "It would leave no enabled admin", body = ErrorResponse),
    )
)]
pub async fn delete_user(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    admin: Authorized<Admin>,
    ApiPath(id): ApiPath<i64>,
) -> Result<StatusCode, ApiError> {
    if id == admin.user().user_id {
        return Err(ApiError::bad_request(
            "cannot_delete_self",
            "admins cannot delete their own account",
        ));
    }
    let deleted = {
        let _slot = state.read_slot().await?;
        state.storage.delete_user(id).await?
    };
    let user = match deleted {
        AccountChange::Done(user) => user,
        AccountChange::NotFound => return Err(ApiError::not_found("account")),
        AccountChange::LastAdmin => return Err(last_admin()),
    };
    audit::record(
        &state,
        NewAuditEvent {
            client_ip,
            target_type: Some("user"),
            target_id: Some(user.id.to_string()),
            details: json!({ "username": user.username, "role": user.role }),
            ..audit::by(admin.user(), "user.delete")
        },
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Read the audit log, newest first (admin).
#[utoipa::path(
    get,
    path = "/api/v1/audit",
    tag = "audit",
    params(AuditListParams),
    responses(
        (status = 200, description = "A page of audit events", body = Paged<AuditEvent>),
        (status = 400, description = "Invalid filter", body = ErrorResponse),
        (status = 401, description = "Not signed in", body = ErrorResponse),
        (status = 403, description = "Needs the admin role", body = ErrorResponse),
    )
)]
pub async fn list_audit(
    State(state): State<AppState>,
    _admin: Authorized<Admin>,
    ApiQuery(params): ApiQuery<AuditListParams>,
) -> Result<Json<Paged<AuditEvent>>, ApiError> {
    let page = page_of(params.page, params.per_page)?;
    let action = params.action.filter(|a| !a.is_empty());
    if let Some(action) = &action {
        let valid = action.len() <= 64
            && action.split_once('.').is_some_and(|(area, verb)| {
                [area, verb].iter().all(|part| {
                    !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                })
            });
        if !valid {
            return Err(ApiError::bad_request(
                "invalid_action",
                "action looks like auth.login: lowercase letters and '_' around one '.'",
            ));
        }
    }
    let outcome = match params.outcome.as_deref().filter(|o| !o.is_empty()) {
        None => None,
        Some(text) => Some(AuditOutcome::parse(text).ok_or_else(|| {
            ApiError::bad_request(
                "invalid_outcome",
                "outcome must be success, failure or denied",
            )
        })?),
    };
    let actor = params.actor.filter(|a| !a.is_empty());
    if actor.as_ref().is_some_and(|a| a.chars().count() > 64) {
        return Err(ApiError::bad_request(
            "invalid_actor",
            "actor has at most 64 characters",
        ));
    }
    let filter = AuditFilter {
        action,
        outcome,
        actor,
    };
    let _slot = state.read_slot().await?;
    Ok(Json(state.storage.list_audit(page, &filter).await?))
}
