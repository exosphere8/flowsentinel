//! Shared request state.

use std::path::PathBuf;
use std::sync::Arc;

use std::time::Duration;

use axum::http::StatusCode;
use capture::CaptureLimits;
use detection_engine::DetectionConfig;
use flow_engine::FlowConfig;
use storage::Storage;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::ApiError;
use crate::host::HostPolicy;

/// Longest wait for a database slot before a request is refused.
const READ_SLOT_WAIT: Duration = Duration::from_secs(10);

/// Settings that shape request handling.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Largest accepted upload, in bytes.
    pub max_upload_bytes: u64,
    /// Directory for temporary upload files.
    pub upload_dir: PathBuf,
    /// Limits applied when analyzing an upload.
    pub capture_limits: CaptureLimits,
    pub flow_config: FlowConfig,
    /// Accepted `Host` header values.
    pub host_policy: HostPolicy,
    /// Validated rule thresholds, applied to every import.
    pub detection: DetectionConfig,
    /// Built dashboard to serve at `/` (a directory with `index.html`).
    pub dashboard_dir: Option<PathBuf>,
}

/// State shared by all handlers.
#[derive(Debug, Clone)]
pub struct AppState {
    pub storage: Storage,
    pub config: Arc<ApiConfig>,
    /// One permit per concurrent import.
    pub import_slots: Arc<Semaphore>,
    /// One permit per concurrent read or settings request. The pool keeps
    /// two connections per import slot in reserve, so heavy reading cannot
    /// starve imports.
    pub read_slots: Arc<Semaphore>,
    /// One permit per concurrent filtered list query: at most half the read
    /// slots, so expensive filters cannot starve other reads.
    pub filter_slots: Arc<Semaphore>,
}

impl AppState {
    pub fn new(storage: Storage, config: ApiConfig, max_concurrent_imports: usize) -> Self {
        let imports = max_concurrent_imports.max(1);
        let pool = usize::try_from(storage.max_connections()).unwrap_or(1);
        let reads = pool.saturating_sub(imports.saturating_mul(2)).max(1);
        Self {
            storage,
            config: Arc::new(config),
            import_slots: Arc::new(Semaphore::new(imports)),
            read_slots: Arc::new(Semaphore::new(reads)),
            filter_slots: Arc::new(Semaphore::new((reads / 2).max(1))),
        }
    }

    /// Waits up to 10 s for a database slot for a non-import request.
    pub async fn read_slot(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        let acquire = Arc::clone(&self.read_slots).acquire_owned();
        match tokio::time::timeout(READ_SLOT_WAIT, acquire).await {
            Ok(Ok(permit)) => Ok(permit),
            _ => Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_busy",
                "the server is busy; try again shortly",
            )),
        }
    }
}
