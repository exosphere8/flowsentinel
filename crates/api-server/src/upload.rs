//! Streams an uploaded capture to a private temporary file.

use std::path::Path;
use std::time::Duration;

use axum::body::Body;
use axum::http::StatusCode;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use tokio::io::{AsyncWriteExt, BufWriter};

use crate::error::ApiError;

/// Longest pause between two chunks of an upload before it is abandoned.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// After this long, an upload must average at least [`MIN_BYTES_PER_SECOND`],
/// so a client trickling bytes cannot hold an import slot indefinitely.
pub const RATE_GRACE: Duration = Duration::from_secs(30);
/// Slowest accepted average upload rate after [`RATE_GRACE`] (16 KiB/s).
pub const MIN_BYTES_PER_SECOND: u64 = 16 * 1024;

/// Whether `size` bytes after `elapsed` is too slow.
pub fn too_slow(size: u64, elapsed: Duration) -> bool {
    elapsed > RATE_GRACE
        && u128::from(size) * 1000 < u128::from(MIN_BYTES_PER_SECOND) * elapsed.as_millis()
}

/// Prefix of temporary upload files.
pub const UPLOAD_PREFIX: &str = "flowsentinel-upload-";

/// A received upload. The temporary file is deleted when this is dropped.
#[derive(Debug)]
pub struct Upload {
    pub file: NamedTempFile,
    pub size_bytes: u64,
    /// Lowercase hex SHA-256 of the content.
    pub sha256: String,
}

/// Checks that other users cannot tamper with the upload directory: on
/// Unix, a directory writable by its group or by others must have the
/// sticky bit (like `/tmp`), so nobody else can replace or delete the
/// server's files. Uploads themselves are created with random names and
/// owner-only permissions.
pub fn check_directory(dir: &Path) -> Result<(), String> {
    let metadata = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        let shared = mode & 0o022 != 0;
        let sticky = mode & 0o1000 != 0;
        if shared && !sticky {
            return Err(format!(
                "{} is writable by other users (mode {:o}); use a directory only the server \
                 can write to (chmod 700)",
                dir.display(),
                mode & 0o7777
            ));
        }
    }
    Ok(())
}

/// Writes `body` to a new temporary file in `dir`, enforcing `max_bytes`
/// while streaming. The file name is random and ends in `.pcap` so the
/// capture reader's extension check applies. On Unix the file is created
/// with owner-only permissions (0600).
pub async fn receive(body: Body, dir: &Path, max_bytes: u64) -> Result<Upload, ApiError> {
    let file = tempfile::Builder::new()
        .prefix(UPLOAD_PREFIX)
        .suffix(".pcap")
        .tempfile_in(dir)
        .map_err(|e| ApiError::internal("creating upload file", &e))?;
    let handle = file
        .reopen()
        .map_err(|e| ApiError::internal("opening upload file", &e))?;
    let mut writer = BufWriter::with_capacity(64 * 1024, tokio::fs::File::from_std(handle));
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut stream = body.into_data_stream();
    let started = tokio::time::Instant::now();
    loop {
        let next = tokio::time::timeout(IDLE_TIMEOUT, stream.next())
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::REQUEST_TIMEOUT,
                    "upload_timeout",
                    "the upload stalled for more than 30 seconds",
                )
            })?;
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|_| {
            ApiError::bad_request(
                "upload_interrupted",
                "the upload ended before it was complete",
            )
        })?;
        size = size.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if size > max_bytes {
            return Err(too_large(max_bytes));
        }
        if too_slow(size, started.elapsed()) {
            return Err(ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                "upload_too_slow",
                format!(
                    "the upload averaged less than {} KiB/s",
                    MIN_BYTES_PER_SECOND / 1024
                ),
            ));
        }
        hasher.update(&chunk);
        writer
            .write_all(&chunk)
            .await
            .map_err(|e| ApiError::internal("writing upload file", &e))?;
    }
    writer
        .flush()
        .await
        .map_err(|e| ApiError::internal("writing upload file", &e))?;
    if size == 0 {
        return Err(ApiError::bad_request(
            "empty_upload",
            "the request body is empty",
        ));
    }
    let sha256 = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(Upload {
        file,
        size_bytes: size,
        sha256,
    })
}

/// Deletes upload files left in `dir` by a server that stopped abruptly
/// (for example, killed mid-import). Returns how many were removed. Only
/// regular files named like this server's uploads are touched.
pub fn remove_stale(dir: &Path) -> std::io::Result<usize> {
    let mut removed = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let ours = name.starts_with(UPLOAD_PREFIX) && name.ends_with(".pcap");
        if ours && entry.file_type()?.is_file() && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn too_large(max_bytes: u64) -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "upload_too_large",
        format!("uploads are limited to {max_bytes} bytes"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_uploads_are_cut_after_the_grace_period() {
        let secs = Duration::from_secs;
        assert!(!too_slow(1, secs(29)));
        assert!(too_slow(1, secs(31)));
        assert!(!too_slow(16 * 1024 * 40, secs(40)));
        assert!(too_slow(16 * 1024 * 40 - 1, secs(40)));
    }

    #[cfg(unix)]
    #[test]
    fn shared_upload_directories_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let set = |mode| {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap()
        };
        set(0o700);
        assert!(check_directory(dir.path()).is_ok());
        set(0o777);
        assert!(
            check_directory(dir.path())
                .unwrap_err()
                .contains("chmod 700")
        );
        set(0o775);
        assert!(check_directory(dir.path()).is_err());
        // Like /tmp: shared but sticky.
        set(0o1777);
        assert!(check_directory(dir.path()).is_ok());
        set(0o700);
        assert!(check_directory(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn stale_uploads_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("flowsentinel-upload-abc123.pcap"), b"x").unwrap();
        std::fs::write(dir.path().join("other.pcap"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("flowsentinel-upload-dir.pcap")).unwrap();
        assert_eq!(remove_stale(dir.path()).unwrap(), 1);
        assert!(dir.path().join("other.pcap").exists());
        assert!(dir.path().join("flowsentinel-upload-dir.pcap").exists());
    }
}
