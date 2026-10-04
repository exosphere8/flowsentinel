//! Accounts, sign-in sessions and the audit log.
//!
//! Passwords arrive here already hashed (Argon2id PHC strings) and session
//! tokens as SHA-256 digests: this module never sees a password or a token.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{Postgres, QueryBuilder, Row};
use utoipa::ToSchema;

use crate::{Page, Paged, Storage, StorageError};

/// What an account may do. Each role includes everything the roles below it
/// may do: `viewer` < `analyst` < `admin`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Reads captures, packets, flows, alerts and settings.
    Viewer,
    /// Also imports captures and triages alerts.
    Analyst,
    /// Also deletes captures, changes settings, manages accounts and reads
    /// the audit log.
    Admin,
}

impl Role {
    pub const ALL: [Self; 3] = [Self::Viewer, Self::Analyst, Self::Admin];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Analyst => "analyst",
            Self::Admin => "admin",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.as_str() == text)
    }

    /// Whether this role includes `required`.
    pub fn includes(self, required: Self) -> bool {
        self >= required
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An account, without its password hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: Role,
    /// A disabled account cannot sign in, and its sessions end.
    pub disabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub password_changed_at: String,
    pub last_login_at: Option<String>,
}

/// What sign-in needs to check a password. `Debug` never shows the hash.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub id: i64,
    pub username: String,
    pub role: Role,
    pub disabled: bool,
    pub password_hash: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("role", &self.role)
            .field("disabled", &self.disabled)
            .field("password_hash", &"[redacted]")
            .finish()
    }
}

/// The account behind a valid sign-in session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUser {
    pub session_id: i64,
    pub user_id: i64,
    pub username: String,
    pub role: Role,
    /// When the session ends at the latest (RFC 3339 UTC).
    pub expires_at: String,
}

/// Changes to an account; `None` leaves a field as it is.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UserUpdate {
    pub role: Option<Role>,
    pub disabled: Option<bool>,
    /// A new Argon2id PHC string.
    pub password_hash: Option<String>,
}

impl fmt::Debug for UserUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserUpdate")
            .field("role", &self.role)
            .field("disabled", &self.disabled)
            .field(
                "password_hash",
                &self.password_hash.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// Result of an account change that must keep at least one active admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountChange<T> {
    Done(T),
    NotFound,
    /// Refused: it would leave no enabled admin account.
    LastAdmin,
}

/// How an audited action ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Success,
    /// The action was attempted and failed (for example a wrong password).
    Failure,
    /// The action was refused for lack of permission.
    Denied,
}

impl AuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [Self::Success, Self::Failure, Self::Denied]
            .into_iter()
            .find(|outcome| outcome.as_str() == text)
    }
}

/// An event to append to the audit log. `details` must be a JSON object of
/// at most 4 KiB, without secrets.
#[derive(Debug, Clone, PartialEq)]
pub struct NewAuditEvent {
    pub actor_id: Option<i64>,
    /// The acting account's name, or for a failed sign-in the name tried.
    pub actor: Option<String>,
    /// `area.verb`, for example `auth.login`.
    pub action: &'static str,
    pub outcome: AuditOutcome,
    pub target_type: Option<&'static str>,
    pub target_id: Option<String>,
    pub client_ip: Option<IpAddr>,
    pub details: serde_json::Value,
}

/// A stored audit event.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct AuditEvent {
    pub id: i64,
    /// RFC 3339 UTC.
    pub at: String,
    pub actor_id: Option<i64>,
    pub actor: Option<String>,
    pub action: String,
    pub outcome: AuditOutcome,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub client_ip: Option<String>,
    #[schema(value_type = Object)]
    pub details: serde_json::Value,
}

/// Optional audit-log filters, matched exactly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    pub action: Option<String>,
    pub outcome: Option<AuditOutcome>,
    pub actor: Option<String>,
}

/// Longest stored actor name; longer values are cut.
const MAX_ACTOR_CHARS: usize = 64;

const USER_COLUMNS: &str = concat!(
    "id, username, role, disabled, ",
    "to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at, ",
    "to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS updated_at, ",
    "to_char(password_changed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
     AS password_changed_at, ",
    "to_char(last_login_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS last_login_at"
);

const AUDIT_COLUMNS: &str = concat!(
    "id, to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS at, ",
    "actor_id, actor, action, outcome, target_type, target_id, ",
    "host(client_ip) AS client_ip, details"
);

fn role_from(text: &str) -> Result<Role, StorageError> {
    Role::parse(text).ok_or(StorageError::Corrupt("unknown role"))
}

fn user_from_row(row: &PgRow) -> Result<User, StorageError> {
    let role: String = row.try_get("role")?;
    Ok(User {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        role: role_from(&role)?,
        disabled: row.try_get("disabled")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        password_changed_at: row.try_get("password_changed_at")?,
        last_login_at: row.try_get("last_login_at")?,
    })
}

fn audit_from_row(row: &PgRow) -> Result<AuditEvent, StorageError> {
    let outcome: String = row.try_get("outcome")?;
    Ok(AuditEvent {
        id: row.try_get("id")?,
        at: row.try_get("at")?,
        actor_id: row.try_get("actor_id")?,
        actor: row.try_get("actor")?,
        action: row.try_get("action")?,
        outcome: AuditOutcome::parse(&outcome)
            .ok_or(StorageError::Corrupt("unknown audit outcome"))?,
        target_type: row.try_get("target_type")?,
        target_id: row.try_get("target_id")?,
        client_ip: row.try_get("client_ip")?,
        details: row.try_get("details")?,
    })
}

/// PostgreSQL's `unique_violation`.
const UNIQUE_VIOLATION: &str = "23505";

fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.code().as_deref() == Some(UNIQUE_VIOLATION))
}

fn seconds(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

fn cut(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

/// Locks every enabled admin row and returns their IDs, so concurrent
/// changes cannot both remove "the other" admin.
async fn lock_active_admins(
    tx: &mut sqlx::Transaction<'static, Postgres>,
) -> Result<Vec<i64>, StorageError> {
    Ok(sqlx::query_scalar(
        "SELECT id FROM users WHERE role = 'admin' AND NOT disabled ORDER BY id FOR UPDATE",
    )
    .fetch_all(&mut **tx)
    .await?)
}

impl Storage {
    /// Number of accounts.
    pub async fn count_users(&self) -> Result<i64, StorageError> {
        Ok(sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(self.pool())
            .await?)
    }

    /// Creates an account. Returns `None` if the username is taken. The
    /// username must already be validated and lowercase.
    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: Role,
    ) -> Result<Option<User>, StorageError> {
        let sql = format!(
            "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) \
             RETURNING {USER_COLUMNS}"
        );
        match sqlx::query(&sql)
            .bind(username)
            .bind(password_hash)
            .bind(role.as_str())
            .fetch_one(self.pool())
            .await
        {
            Ok(row) => Ok(Some(user_from_row(&row)?)),
            Err(err) if is_unique_violation(&err) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Creates the first admin account, only if no account exists yet.
    /// Returns `None` when accounts already exist.
    pub async fn create_first_admin(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<Option<User>, StorageError> {
        let mut tx = self.pool().begin().await?;
        // Serializes concurrent bootstraps (several server replicas).
        sqlx::query("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        let existing: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&mut *tx)
            .await?;
        if existing > 0 {
            return Ok(None);
        }
        let sql = format!(
            "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin') \
             RETURNING {USER_COLUMNS}"
        );
        let row = sqlx::query(&sql)
            .bind(username)
            .bind(password_hash)
            .fetch_one(&mut *tx)
            .await?;
        let user = user_from_row(&row)?;
        tx.commit().await?;
        Ok(Some(user))
    }

    /// The password hash and status of an account, for sign-in.
    pub async fn credentials(&self, username: &str) -> Result<Option<Credentials>, StorageError> {
        let row = sqlx::query(
            "SELECT id, username, role, disabled, password_hash FROM users WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            let role: String = row.try_get("role")?;
            Ok(Credentials {
                id: row.try_get("id")?,
                username: row.try_get("username")?,
                role: role_from(&role)?,
                disabled: row.try_get("disabled")?,
                password_hash: row.try_get("password_hash")?,
            })
        })
        .transpose()
    }

    pub async fn user(&self, id: i64) -> Result<Option<User>, StorageError> {
        let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE id = $1");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(self.pool())
            .await?;
        row.as_ref().map(user_from_row).transpose()
    }

    /// Accounts in username order.
    pub async fn list_users(&self, page: Page) -> Result<Paged<User>, StorageError> {
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(self.pool())
            .await?;
        let sql = format!("SELECT {USER_COLUMNS} FROM users ORDER BY username LIMIT $1 OFFSET $2");
        let rows = sqlx::query(&sql)
            .bind(page.limit())
            .bind(page.offset())
            .fetch_all(self.pool())
            .await?;
        let items = rows.iter().map(user_from_row).collect::<Result<_, _>>()?;
        Ok(page.wrap(items, total))
    }

    /// Changes an account. A change of role, enabled state or password ends
    /// all of the account's sessions. Refuses to leave no enabled admin.
    pub async fn update_user(
        &self,
        id: i64,
        update: &UserUpdate,
    ) -> Result<AccountChange<User>, StorageError> {
        let mut tx = self.pool().begin().await?;
        let admins = lock_active_admins(&mut tx).await?;
        let current: Option<(String, bool)> =
            sqlx::query_as("SELECT role, disabled FROM users WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((role, disabled)) = current else {
            return Ok(AccountChange::NotFound);
        };
        let role = role_from(&role)?;
        let new_role = update.role.unwrap_or(role);
        let new_disabled = update.disabled.unwrap_or(disabled);
        let stays_admin = new_role == Role::Admin && !new_disabled;
        if admins.contains(&id) && !stays_admin && admins.len() <= 1 {
            return Ok(AccountChange::LastAdmin);
        }
        let sql = format!(
            "UPDATE users SET role = $2, disabled = $3, \
             password_hash = COALESCE($4, password_hash), \
             password_changed_at = CASE WHEN $4 IS NULL THEN password_changed_at ELSE now() END, \
             updated_at = now() \
             WHERE id = $1 RETURNING {USER_COLUMNS}"
        );
        let row = sqlx::query(&sql)
            .bind(id)
            .bind(new_role.as_str())
            .bind(new_disabled)
            .bind(update.password_hash.as_deref())
            .fetch_one(&mut *tx)
            .await?;
        let user = user_from_row(&row)?;
        let ends_sessions =
            new_role != role || new_disabled != disabled || update.password_hash.is_some();
        if ends_sessions {
            sqlx::query("DELETE FROM auth_sessions WHERE user_id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(AccountChange::Done(user))
    }

    /// Deletes an account and its sessions. Refuses to delete the last
    /// enabled admin.
    pub async fn delete_user(&self, id: i64) -> Result<AccountChange<User>, StorageError> {
        let mut tx = self.pool().begin().await?;
        let admins = lock_active_admins(&mut tx).await?;
        if admins.contains(&id) && admins.len() <= 1 {
            return Ok(AccountChange::LastAdmin);
        }
        let sql = format!("DELETE FROM users WHERE id = $1 RETURNING {USER_COLUMNS}");
        let Some(row) = sqlx::query(&sql).bind(id).fetch_optional(&mut *tx).await? else {
            return Ok(AccountChange::NotFound);
        };
        let user = user_from_row(&row)?;
        tx.commit().await?;
        Ok(AccountChange::Done(user))
    }

    /// Replaces an account's password and ends all its sessions; the caller
    /// starts a new one for the client that made the change. Returns whether
    /// the account exists.
    pub async fn change_password(
        &self,
        user_id: i64,
        password_hash: &str,
    ) -> Result<bool, StorageError> {
        let mut tx = self.pool().begin().await?;
        let updated = sqlx::query(
            "UPDATE users SET password_hash = $2, password_changed_at = now(), \
             updated_at = now() WHERE id = $1",
        )
        .bind(user_id)
        .bind(password_hash)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM auth_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(updated.rows_affected() > 0)
    }

    /// The current password hash of an account.
    pub async fn password_hash(&self, user_id: i64) -> Result<Option<String>, StorageError> {
        Ok(
            sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(self.pool())
                .await?,
        )
    }

    /// Starts a session for `token_sha256` lasting at most `lifetime`, and
    /// ends the account's oldest sessions beyond `max_per_user`. Returns the
    /// expiry time (RFC 3339 UTC).
    ///
    /// `password_hash` is the hash the caller verified the password against.
    /// If the account's password changed (or the account was disabled) in the
    /// meantime, no session is started and `None` is returned: a password
    /// change ends every session, including ones whose sign-in was still
    /// being checked.
    pub async fn create_auth_session(
        &self,
        user_id: i64,
        token_sha256: &[u8; 32],
        lifetime: Duration,
        max_per_user: u32,
        password_hash: &str,
    ) -> Result<Option<String>, StorageError> {
        let mut tx = self.pool().begin().await?;
        // Waits for a concurrent password change to commit, then re-checks.
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM users WHERE id = $1 AND password_hash = $2 AND NOT disabled \
             FOR SHARE",
        )
        .bind(user_id)
        .bind(password_hash)
        .fetch_optional(&mut *tx)
        .await?;
        if current.is_none() {
            return Ok(None);
        }
        let expires_at: String = sqlx::query_scalar(
            "INSERT INTO auth_sessions (token_sha256, user_id, expires_at) \
             VALUES ($1, $2, now() + make_interval(secs => $3)) \
             RETURNING to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
        )
        .bind(token_sha256.as_slice())
        .bind(user_id)
        .bind(seconds(lifetime))
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM auth_sessions WHERE id IN ( \
               SELECT id FROM auth_sessions WHERE user_id = $1 \
               ORDER BY created_at DESC, id DESC OFFSET $2)",
        )
        .bind(user_id)
        .bind(i64::from(max_per_user.max(1)))
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(expires_at))
    }

    /// The account behind a session token, if the session has neither
    /// expired nor been idle longer than `idle`, and the account is enabled.
    /// Marks the session as used (at most once a minute).
    pub async fn session_user(
        &self,
        token_sha256: &[u8; 32],
        idle: Duration,
    ) -> Result<Option<SessionUser>, StorageError> {
        let row = sqlx::query(
            "SELECT s.id AS session_id, s.user_id, u.username, u.role, \
             to_char(s.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
             AS expires_at, \
             s.last_seen_at < now() - interval '60 seconds' AS stale \
             FROM auth_sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.token_sha256 = $1 AND s.expires_at > now() \
             AND s.last_seen_at > now() - make_interval(secs => $2) AND NOT u.disabled",
        )
        .bind(token_sha256.as_slice())
        .bind(seconds(idle))
        .fetch_optional(self.pool())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let role: String = row.try_get("role")?;
        let user = SessionUser {
            session_id: row.try_get("session_id")?,
            user_id: row.try_get("user_id")?,
            username: row.try_get("username")?,
            role: role_from(&role)?,
            expires_at: row.try_get("expires_at")?,
        };
        let stale: bool = row.try_get("stale")?;
        if stale {
            sqlx::query("UPDATE auth_sessions SET last_seen_at = now() WHERE id = $1")
                .bind(user.session_id)
                .execute(self.pool())
                .await?;
        }
        Ok(Some(user))
    }

    /// Ends one session. Returns whether it existed.
    pub async fn delete_auth_session(&self, session_id: i64) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM auth_sessions WHERE id = $1")
            .bind(session_id)
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Deletes expired and idle sessions. Returns how many were deleted.
    pub async fn purge_auth_sessions(&self, idle: Duration) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "DELETE FROM auth_sessions WHERE expires_at <= now() \
             OR last_seen_at <= now() - make_interval(secs => $1)",
        )
        .bind(seconds(idle))
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Appends an event to the audit log.
    pub async fn record_audit(&self, event: &NewAuditEvent) -> Result<i64, StorageError> {
        let details = if event.details.is_object() {
            event.details.clone()
        } else {
            serde_json::Value::Object(serde_json::Map::new())
        };
        Ok(sqlx::query_scalar(
            "INSERT INTO audit_events \
             (actor_id, actor, action, outcome, target_type, target_id, client_ip, details) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
        )
        .bind(event.actor_id)
        .bind(event.actor.as_deref().map(|a| cut(a, MAX_ACTOR_CHARS)))
        .bind(event.action)
        .bind(event.outcome.as_str())
        .bind(event.target_type)
        .bind(event.target_id.as_deref().map(|t| cut(t, 64)))
        .bind(event.client_ip)
        .bind(details)
        .fetch_one(self.pool())
        .await?)
    }

    /// Audit events, newest first.
    pub async fn list_audit(
        &self,
        page: Page,
        filter: &AuditFilter,
    ) -> Result<Paged<AuditEvent>, StorageError> {
        fn conditions<'a>(builder: &mut QueryBuilder<'a, Postgres>, filter: &'a AuditFilter) {
            builder.push(" WHERE TRUE");
            if let Some(action) = &filter.action {
                builder.push(" AND action = ").push_bind(action.as_str());
            }
            if let Some(outcome) = filter.outcome {
                builder.push(" AND outcome = ").push_bind(outcome.as_str());
            }
            if let Some(actor) = &filter.actor {
                builder.push(" AND actor = ").push_bind(actor.as_str());
            }
        }
        let mut count = QueryBuilder::<Postgres>::new("SELECT count(*) FROM audit_events");
        conditions(&mut count, filter);
        let total: i64 = count.build_query_scalar().fetch_one(self.pool()).await?;
        let mut select =
            QueryBuilder::<Postgres>::new(format!("SELECT {AUDIT_COLUMNS} FROM audit_events"));
        conditions(&mut select, filter);
        select
            .push(" ORDER BY id DESC LIMIT ")
            .push_bind(page.limit())
            .push(" OFFSET ")
            .push_bind(page.offset());
        let rows = select.build().fetch_all(self.pool()).await?;
        let items = rows.iter().map(audit_from_row).collect::<Result<_, _>>()?;
        Ok(page.wrap(items, total))
    }

    /// Deletes audit events older than `days`. Returns how many.
    pub async fn purge_audit(&self, days: u32) -> Result<u64, StorageError> {
        let result =
            sqlx::query("DELETE FROM audit_events WHERE at < now() - make_interval(days => $1)")
                .bind(i32::try_from(days).unwrap_or(i32::MAX))
                .execute(self.pool())
                .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_ordered_and_round_trip() {
        assert!(Role::Admin.includes(Role::Analyst));
        assert!(Role::Analyst.includes(Role::Viewer));
        assert!(Role::Viewer.includes(Role::Viewer));
        assert!(!Role::Viewer.includes(Role::Analyst));
        assert!(!Role::Analyst.includes(Role::Admin));
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
            assert_eq!(
                serde_json::to_value(role).unwrap(),
                serde_json::json!(role.as_str())
            );
        }
        assert_eq!(Role::parse("Admin"), None);
        assert_eq!(Role::parse("root"), None);
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let credentials = Credentials {
            id: 1,
            username: "ana".into(),
            role: Role::Analyst,
            disabled: false,
            password_hash: "$argon2id$v=19$secret-hash".into(),
        };
        assert!(!format!("{credentials:?}").contains("secret-hash"));
        let update = UserUpdate {
            password_hash: Some("$argon2id$v=19$secret-hash".into()),
            ..UserUpdate::default()
        };
        assert!(!format!("{update:?}").contains("secret-hash"));
    }
}
