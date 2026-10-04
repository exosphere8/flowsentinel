//! Creating accounts outside the API: the first admin from a password file
//! at startup, and `flowsentinel-api create-user` on the command line.

use std::io::Read;
use std::path::Path;

use serde_json::json;
use storage::{AuditOutcome, NewAuditEvent, Role, Storage, User};

use crate::auth;

/// Longest password file or standard-input line read.
const MAX_PASSWORD_INPUT: u64 = 1024;

/// Reads a password: the whole input up to 1 KiB, without one trailing line
/// ending. Never echoes the content in errors.
pub fn read_password(mut input: impl Read) -> Result<String, String> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(MAX_PASSWORD_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read the password: {e}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PASSWORD_INPUT {
        return Err("the password input is longer than 1 KiB".to_owned());
    }
    let mut text =
        String::from_utf8(bytes).map_err(|_| "the password is not valid UTF-8".to_owned())?;
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    Ok(text)
}

/// Reads a password file (see [`read_password`]).
pub fn read_password_file(path: &Path) -> Result<String, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    read_password(file)
}

fn checked(username: &str, password: &str) -> Result<String, String> {
    let username = auth::normalize_username(username).map_err(|e| e.message)?;
    auth::check_new_password(password, &username).map_err(|e| e.message)?;
    Ok(username)
}

async fn hash(password: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || auth::hash_password(&password))
        .await
        .map_err(|e| e.to_string())?
}

fn command_line_event(user: &User, action: &'static str) -> NewAuditEvent {
    NewAuditEvent {
        actor_id: None,
        actor: Some("(command line)".to_owned()),
        action,
        outcome: AuditOutcome::Success,
        target_type: Some("user"),
        target_id: Some(user.id.to_string()),
        client_ip: None,
        details: json!({ "username": user.username, "role": user.role }),
    }
}

/// Creates the first admin account if no account exists. Returns `None`
/// when accounts already exist (the password is then ignored).
pub async fn first_admin(
    storage: &Storage,
    username: &str,
    password: String,
) -> Result<Option<User>, String> {
    let username = checked(username, &password)?;
    if storage.count_users().await.map_err(|e| e.to_string())? > 0 {
        return Ok(None);
    }
    let hash = hash(password).await?;
    let created = storage
        .create_first_admin(&username, &hash)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(user) = &created {
        storage
            .record_audit(&command_line_event(user, "user.bootstrap"))
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(created)
}

/// Creates an account from the command line.
pub async fn create_user(
    storage: &Storage,
    username: &str,
    role: Role,
    password: String,
) -> Result<User, String> {
    let username = checked(username, &password)?;
    let hash = hash(password).await?;
    let user = storage
        .create_user(&username, &hash, role)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("an account named {username:?} exists"))?;
    storage
        .record_audit(&command_line_event(&user, "user.create"))
        .await
        .map_err(|e| e.to_string())?;
    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_lose_one_line_ending_only() {
        assert_eq!(
            read_password(&b"secret words\n"[..]).unwrap(),
            "secret words"
        );
        assert_eq!(
            read_password(&b"secret words\r\n"[..]).unwrap(),
            "secret words"
        );
        assert_eq!(read_password(&b" spaced \n\n"[..]).unwrap(), " spaced \n");
        assert_eq!(read_password(&b"no ending"[..]).unwrap(), "no ending");
        let long = vec![b'a'; 1025];
        assert!(read_password(&long[..]).unwrap_err().contains("1 KiB"));
        let err = read_password(&[0xff, 0xfe][..]).unwrap_err();
        assert!(err.contains("UTF-8"));
    }

    #[test]
    fn names_and_passwords_are_checked_first() {
        assert!(checked("Admin", "correct horse battery").is_ok());
        assert_eq!(checked("Admin", "correct horse battery").unwrap(), "admin");
        assert!(checked("bad name", "correct horse battery").is_err());
        assert!(checked("admin", "short").is_err());
    }
}
