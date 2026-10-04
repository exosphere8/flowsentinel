//! PostgreSQL persistence for capture metadata.
//!
//! Every query is parameterized. The only SQL assembled at runtime comes from
//! fixed fragments chosen by enums (sort orders) or from a trusted
//! [`SqlCondition`] that binds every value as a parameter. Nothing stored can
//! hold packet payload bytes: packets keep decoded header and application
//! metadata only.

mod ingest;
mod models;
#[cfg(feature = "test-support")]
pub mod testing;

use std::time::Duration;

use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::{Postgres, QueryBuilder, Row, Transaction};

pub use ingest::{ImportMeta, ImportTransaction, PacketRow};
pub use models::{
    DnsEvent, FlowDetail, FlowSummaryRow, HttpEvent, PacketDetail, PacketSummary, Paged,
    RetentionSettings, Session, SessionDetail, TlsEvent, rfc3339_from_nanos,
};

/// Embedded, checksummed migrations from `crates/storage/migrations`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Storage failures. Messages never include SQL text or row data.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database unavailable: {0}")]
    Connection(#[source] sqlx::Error),
    #[error("database migration failed: {0}")]
    Migration(#[source] sqlx::migrate::MigrateError),
    #[error("database query failed: {0}")]
    Query(#[source] sqlx::Error),
    #[error("stored data is inconsistent: {0}")]
    Corrupt(&'static str),
    #[error("the query took longer than the time limit")]
    QueryTimeout,
}

/// PostgreSQL's `query_canceled` (statement timeout).
const QUERY_CANCELED: &str = "57014";

impl From<sqlx::Error> for StorageError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) => {
                Self::Connection(err)
            }
            sqlx::Error::Database(ref db) if db.code().as_deref() == Some(QUERY_CANCELED) => {
                Self::QueryTimeout
            }
            other => Self::Query(other),
        }
    }
}

/// A validated page request (1-based page number).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    page: u32,
    per_page: u32,
}

impl Page {
    pub const MAX_PER_PAGE: u32 = 500;
    pub const MAX_PAGE: u32 = 1_000_000;

    /// Clamps to `1 <= page <= 1_000_000` and `1 <= per_page <= 500`.
    pub fn new(page: u32, per_page: u32) -> Self {
        Self {
            page: page.clamp(1, Self::MAX_PAGE),
            per_page: per_page.clamp(1, Self::MAX_PER_PAGE),
        }
    }

    pub fn page(self) -> u32 {
        self.page
    }

    pub fn per_page(self) -> u32 {
        self.per_page
    }

    fn offset(self) -> i64 {
        // At most 999_999 * 500, far below i64::MAX.
        i64::from(self.page - 1) * i64::from(self.per_page)
    }

    fn limit(self) -> i64 {
        i64::from(self.per_page)
    }

    fn wrap<T>(self, items: Vec<T>, total: i64) -> Paged<T> {
        Paged {
            items,
            page: self.page,
            per_page: self.per_page,
            total,
        }
    }
}

/// Session list orders. Each maps to a fixed SQL fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionSort {
    #[default]
    NewestFirst,
    OldestFirst,
    MostPackets,
    Largest,
}

impl SessionSort {
    fn sql(self) -> &'static str {
        match self {
            Self::NewestFirst => "created_at DESC, id DESC",
            Self::OldestFirst => "created_at ASC, id ASC",
            Self::MostPackets => "packets_processed DESC, id DESC",
            Self::Largest => "file_size_bytes DESC, id DESC",
        }
    }
}

/// Packet list orders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacketSort {
    #[default]
    Index,
    IndexDesc,
    Time,
    LengthDesc,
}

impl PacketSort {
    fn sql(self) -> &'static str {
        match self {
            Self::Index => "packet_index ASC",
            Self::IndexDesc => "packet_index DESC",
            Self::Time => "ts_ns ASC NULLS LAST, packet_index ASC",
            Self::LengthDesc => "original_length DESC, packet_index ASC",
        }
    }
}

/// Flow list orders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowSort {
    #[default]
    Start,
    BytesDesc,
    PacketsDesc,
    DurationDesc,
}

impl FlowSort {
    fn sql(self) -> &'static str {
        match self {
            Self::Start => "flow_id ASC",
            Self::BytesDesc => "bytes_total DESC, flow_id ASC",
            Self::PacketsDesc => "packets_total DESC, flow_id ASC",
            Self::DurationDesc => "duration_seconds DESC, flow_id ASC",
        }
    }
}

/// An extra `WHERE` condition, appended with `AND`. Implementations must
/// push only fixed SQL text and bind every value with
/// [`QueryBuilder::push_bind`].
pub trait SqlCondition: Send + Sync {
    fn push(&self, builder: &mut QueryBuilder<'_, Postgres>);
}

/// Handle to the database.
#[derive(Debug, Clone)]
pub struct Storage {
    pool: PgPool,
    query_timeout: Duration,
}

/// Default limit for one filtered list query.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Rows of `table` in a session that satisfy `condition`.
async fn count<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    table: &'static str,
    session_id: i64,
    condition: Option<&dyn SqlCondition>,
) -> Result<i64, StorageError> {
    let mut builder =
        QueryBuilder::<Postgres>::new(format!("SELECT count(*) FROM {table} WHERE session_id = "));
    builder.push_bind(session_id);
    push_condition(&mut builder, condition);
    Ok(builder.build_query_scalar().fetch_one(executor).await?)
}

/// RFC 3339 UTC text for a TIMESTAMPTZ column, computed by the database.
macro_rules! utc_text {
    ($column:literal) => {
        concat!(
            "to_char(",
            $column,
            " AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS ",
            $column
        )
    };
}

const SESSION_COLUMNS: &str = concat!(
    "id, file_name, file_size_bytes, sha256, source, completion_state, pcap_version, \
     endianness, timestamp_resolution, link_type, link_type_name, snap_length, \
     packets_processed, packets_stored, captured_bytes_total, original_bytes_total, \
     first_packet_ns, last_packet_ns, flows_total, flows_stored, ",
    utc_text!("created_at"),
    ", ",
    utc_text!("expires_at")
);

const PACKET_COLUMNS: &str = "packet_index, ts_ns, captured_length, original_length, \
    decode_status, top_protocol, source, destination, src_port, dst_port, flow_id, info";

const FLOW_COLUMNS: &str = "flow_id, ip_version, protocol, protocol_name, initiator_ip, \
    initiator_port, responder_ip, responder_port, first_seen_ns, last_seen_ns, \
    duration_seconds, packets_total, bytes_total, tcp_state, end_reason, dominant_endpoint";

fn session_from_row(row: &PgRow) -> Result<Session, sqlx::Error> {
    let first: Option<i64> = row.try_get("first_packet_ns")?;
    let last: Option<i64> = row.try_get("last_packet_ns")?;
    Ok(Session {
        id: row.try_get("id")?,
        file_name: row.try_get("file_name")?,
        file_size_bytes: row.try_get("file_size_bytes")?,
        sha256: row.try_get("sha256")?,
        source: row.try_get("source")?,
        completion_state: row.try_get("completion_state")?,
        pcap_version: row.try_get("pcap_version")?,
        endianness: row.try_get("endianness")?,
        timestamp_resolution: row.try_get("timestamp_resolution")?,
        link_type: row.try_get("link_type")?,
        link_type_name: row.try_get("link_type_name")?,
        snap_length: row.try_get("snap_length")?,
        packets_processed: row.try_get("packets_processed")?,
        packets_stored: row.try_get("packets_stored")?,
        captured_bytes_total: row.try_get("captured_bytes_total")?,
        original_bytes_total: row.try_get("original_bytes_total")?,
        first_packet_ns: first,
        first_packet_time: first.and_then(rfc3339_from_nanos),
        last_packet_ns: last,
        last_packet_time: last.and_then(rfc3339_from_nanos),
        flows_total: row.try_get("flows_total")?,
        flows_stored: row.try_get("flows_stored")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
    })
}

fn packet_from_row(row: &PgRow) -> Result<PacketSummary, sqlx::Error> {
    let ts: Option<i64> = row.try_get("ts_ns")?;
    Ok(PacketSummary {
        packet_index: row.try_get("packet_index")?,
        ts_ns: ts,
        time: ts.and_then(rfc3339_from_nanos),
        captured_length: row.try_get("captured_length")?,
        original_length: row.try_get("original_length")?,
        decode_status: row.try_get("decode_status")?,
        top_protocol: row.try_get("top_protocol")?,
        source: row.try_get("source")?,
        destination: row.try_get("destination")?,
        src_port: row.try_get("src_port")?,
        dst_port: row.try_get("dst_port")?,
        flow_id: row.try_get("flow_id")?,
        info: row.try_get("info")?,
    })
}

fn flow_from_row(row: &PgRow) -> Result<FlowSummaryRow, sqlx::Error> {
    let first: Option<i64> = row.try_get("first_seen_ns")?;
    let initiator: std::net::IpAddr = row.try_get("initiator_ip")?;
    let responder: std::net::IpAddr = row.try_get("responder_ip")?;
    Ok(FlowSummaryRow {
        flow_id: row.try_get("flow_id")?,
        ip_version: row.try_get("ip_version")?,
        protocol: row.try_get("protocol")?,
        protocol_name: row.try_get("protocol_name")?,
        initiator_ip: initiator.to_string(),
        initiator_port: row.try_get("initiator_port")?,
        responder_ip: responder.to_string(),
        responder_port: row.try_get("responder_port")?,
        first_seen_ns: first,
        first_seen: first.and_then(rfc3339_from_nanos),
        last_seen_ns: row.try_get("last_seen_ns")?,
        duration_seconds: row.try_get("duration_seconds")?,
        packets_total: row.try_get("packets_total")?,
        bytes_total: row.try_get("bytes_total")?,
        tcp_state: row.try_get("tcp_state")?,
        end_reason: row.try_get("end_reason")?,
        dominant_endpoint: row.try_get("dominant_endpoint")?,
    })
}

fn push_condition(builder: &mut QueryBuilder<'_, Postgres>, condition: Option<&dyn SqlCondition>) {
    if let Some(condition) = condition {
        builder.push(" AND (");
        condition.push(builder);
        builder.push(")");
    }
}

impl Storage {
    /// Connects with a bounded pool and a connect timeout.
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .acquire_timeout(Duration::from_secs(10))
            .connect(database_url)
            .await
            .map_err(StorageError::Connection)?;
        Ok(Self::from_pool(pool))
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            pool,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
        }
    }

    /// Sets the time limit for list queries that take a filter condition.
    pub fn with_query_timeout(mut self, timeout: Duration) -> Self {
        self.query_timeout = timeout.max(Duration::from_millis(1));
        self
    }

    /// Connections in the pool.
    pub fn max_connections(&self) -> u32 {
        self.pool.options().get_max_connections()
    }

    /// A read-only transaction whose statements are cancelled after the
    /// query timeout, so one expensive filter cannot hold a connection for
    /// long. The count and the page come from the same snapshot.
    async fn read_transaction(&self) -> Result<Transaction<'static, Postgres>, StorageError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('statement_timeout', $1, true)")
            .bind(self.query_timeout.as_millis().to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Applies pending migrations. Already-applied migrations are verified
    /// against their checksums.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(StorageError::Migration)
    }

    /// Round-trips a trivial query.
    pub async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn list_sessions(
        &self,
        page: Page,
        sort: SessionSort,
    ) -> Result<Paged<Session>, StorageError> {
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM capture_sessions")
            .fetch_one(&self.pool)
            .await?;
        let sql = format!(
            "SELECT {SESSION_COLUMNS} FROM capture_sessions ORDER BY {} LIMIT $1 OFFSET $2",
            sort.sql()
        );
        let rows = sqlx::query(&sql)
            .bind(page.limit())
            .bind(page.offset())
            .fetch_all(&self.pool)
            .await?;
        let items = rows
            .iter()
            .map(session_from_row)
            .collect::<Result<_, _>>()?;
        Ok(page.wrap(items, total))
    }

    pub async fn get_session(&self, id: i64) -> Result<Option<SessionDetail>, StorageError> {
        let sql = format!(
            "SELECT {SESSION_COLUMNS}, capture_warnings, decode_summary, flow_summary \
             FROM capture_sessions WHERE id = $1"
        );
        let Some(row) = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(SessionDetail {
            session: session_from_row(&row)?,
            capture_warnings: row.try_get("capture_warnings")?,
            decode_summary: row.try_get("decode_summary")?,
            flow_summary: row.try_get("flow_summary")?,
        }))
    }

    /// Deletes a session and (by cascade) everything stored for it.
    pub async fn delete_session(&self, id: i64) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM capture_sessions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn session_exists(&self, id: i64) -> Result<bool, StorageError> {
        Ok(
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM capture_sessions WHERE id = $1)")
                .bind(id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    /// Lists packets of a session, optionally restricted by `condition`.
    pub async fn list_packets(
        &self,
        session_id: i64,
        page: Page,
        sort: PacketSort,
        condition: Option<&dyn SqlCondition>,
    ) -> Result<Paged<PacketSummary>, StorageError> {
        let mut tx = self.read_transaction().await?;
        let total = count(&mut *tx, "packets", session_id, condition).await?;
        let mut builder = QueryBuilder::<Postgres>::new(format!(
            "SELECT {PACKET_COLUMNS} FROM packets WHERE session_id = "
        ));
        builder.push_bind(session_id);
        push_condition(&mut builder, condition);
        builder.push(format!(" ORDER BY {} LIMIT ", sort.sql()));
        builder.push_bind(page.limit());
        builder.push(" OFFSET ");
        builder.push_bind(page.offset());
        let rows = builder.build().fetch_all(&mut *tx).await?;
        tx.commit().await?;
        let items = rows.iter().map(packet_from_row).collect::<Result<_, _>>()?;
        Ok(page.wrap(items, total))
    }

    pub async fn get_packet(
        &self,
        session_id: i64,
        index: i64,
    ) -> Result<Option<PacketDetail>, StorageError> {
        let sql = format!(
            "SELECT {PACKET_COLUMNS}, layers, warnings FROM packets \
             WHERE session_id = $1 AND packet_index = $2"
        );
        let Some(row) = sqlx::query(&sql)
            .bind(session_id)
            .bind(index)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(PacketDetail {
            summary: packet_from_row(&row)?,
            layers: row.try_get("layers")?,
            warnings: row.try_get("warnings")?,
        }))
    }

    /// Lists flows of a session, optionally restricted by `condition`.
    pub async fn list_flows(
        &self,
        session_id: i64,
        page: Page,
        sort: FlowSort,
        condition: Option<&dyn SqlCondition>,
    ) -> Result<Paged<FlowSummaryRow>, StorageError> {
        let mut tx = self.read_transaction().await?;
        let total = count(&mut *tx, "flows", session_id, condition).await?;
        let mut builder = QueryBuilder::<Postgres>::new(format!(
            "SELECT {FLOW_COLUMNS} FROM flows WHERE session_id = "
        ));
        builder.push_bind(session_id);
        push_condition(&mut builder, condition);
        builder.push(format!(" ORDER BY {} LIMIT ", sort.sql()));
        builder.push_bind(page.limit());
        builder.push(" OFFSET ");
        builder.push_bind(page.offset());
        let rows = builder.build().fetch_all(&mut *tx).await?;
        tx.commit().await?;
        let items = rows.iter().map(flow_from_row).collect::<Result<_, _>>()?;
        Ok(page.wrap(items, total))
    }

    pub async fn get_flow(
        &self,
        session_id: i64,
        flow_id: i64,
    ) -> Result<Option<FlowDetail>, StorageError> {
        let sql = format!(
            "SELECT {FLOW_COLUMNS}, record FROM flows WHERE session_id = $1 AND flow_id = $2"
        );
        let Some(row) = sqlx::query(&sql)
            .bind(session_id)
            .bind(flow_id)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(FlowDetail {
            summary: flow_from_row(&row)?,
            record: row.try_get("record")?,
        }))
    }

    /// Counts rows of `table` (a fixed name chosen by this crate) for a
    /// session.
    async fn count(
        &self,
        table: &'static str,
        session_id: i64,
        condition: Option<&dyn SqlCondition>,
    ) -> Result<i64, StorageError> {
        count(&self.pool, table, session_id, condition).await
    }

    pub async fn list_dns_events(
        &self,
        session_id: i64,
        page: Page,
    ) -> Result<Paged<DnsEvent>, StorageError> {
        let total = self.count("dns_events", session_id, None).await?;
        let rows = sqlx::query(
            "SELECT packet_index, ts_ns, flow_id, transaction_id, is_response, query_name, \
             query_type, response_code, answer_count, answers FROM dns_events \
             WHERE session_id = $1 ORDER BY packet_index LIMIT $2 OFFSET $3",
        )
        .bind(session_id)
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(&self.pool)
        .await?;
        let items = rows
            .iter()
            .map(|row| {
                let ts: Option<i64> = row.try_get("ts_ns")?;
                Ok(DnsEvent {
                    packet_index: row.try_get("packet_index")?,
                    ts_ns: ts,
                    time: ts.and_then(rfc3339_from_nanos),
                    flow_id: row.try_get("flow_id")?,
                    transaction_id: row.try_get("transaction_id")?,
                    is_response: row.try_get("is_response")?,
                    query_name: row.try_get("query_name")?,
                    query_type: row.try_get("query_type")?,
                    response_code: row.try_get("response_code")?,
                    answer_count: row.try_get("answer_count")?,
                    answers: row.try_get("answers")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()?;
        Ok(page.wrap(items, total))
    }

    pub async fn list_http_events(
        &self,
        session_id: i64,
        page: Page,
    ) -> Result<Paged<HttpEvent>, StorageError> {
        let total = self.count("http_events", session_id, None).await?;
        let rows = sqlx::query(
            "SELECT packet_index, ts_ns, flow_id, kind, method, host, path, status_code, \
             content_type, redacted FROM http_events \
             WHERE session_id = $1 ORDER BY packet_index LIMIT $2 OFFSET $3",
        )
        .bind(session_id)
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(&self.pool)
        .await?;
        let items = rows
            .iter()
            .map(|row| {
                let ts: Option<i64> = row.try_get("ts_ns")?;
                Ok(HttpEvent {
                    packet_index: row.try_get("packet_index")?,
                    ts_ns: ts,
                    time: ts.and_then(rfc3339_from_nanos),
                    flow_id: row.try_get("flow_id")?,
                    kind: row.try_get("kind")?,
                    method: row.try_get("method")?,
                    host: row.try_get("host")?,
                    path: row.try_get("path")?,
                    status_code: row.try_get("status_code")?,
                    content_type: row.try_get("content_type")?,
                    redacted: row.try_get("redacted")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()?;
        Ok(page.wrap(items, total))
    }

    pub async fn list_tls_events(
        &self,
        session_id: i64,
        page: Page,
    ) -> Result<Paged<TlsEvent>, StorageError> {
        let total = self.count("tls_events", session_id, None).await?;
        let rows = sqlx::query(
            "SELECT packet_index, ts_ns, flow_id, handshake_type, server_name, alpn, \
             negotiated_version, cipher_suite_count FROM tls_events \
             WHERE session_id = $1 ORDER BY packet_index LIMIT $2 OFFSET $3",
        )
        .bind(session_id)
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(&self.pool)
        .await?;
        let items = rows
            .iter()
            .map(|row| {
                let ts: Option<i64> = row.try_get("ts_ns")?;
                Ok(TlsEvent {
                    packet_index: row.try_get("packet_index")?,
                    ts_ns: ts,
                    time: ts.and_then(rfc3339_from_nanos),
                    flow_id: row.try_get("flow_id")?,
                    handshake_type: row.try_get("handshake_type")?,
                    server_name: row.try_get("server_name")?,
                    alpn: row.try_get("alpn")?,
                    negotiated_version: row.try_get("negotiated_version")?,
                    cipher_suite_count: row.try_get("cipher_suite_count")?,
                    visibility: decoder::app::tls::VISIBILITY,
                })
            })
            .collect::<Result<_, sqlx::Error>>()?;
        Ok(page.wrap(items, total))
    }

    pub async fn retention(&self) -> Result<RetentionSettings, StorageError> {
        let row = sqlx::query(
            "SELECT session_ttl_days, max_packets_stored FROM retention_settings WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::Corrupt("retention settings row is missing"))?;
        Ok(RetentionSettings {
            session_ttl_days: row.try_get("session_ttl_days")?,
            max_packets_stored: row.try_get("max_packets_stored")?,
        })
    }

    /// Updates retention. The database range-checks the values too.
    /// Existing sessions keep their expiry; new imports use the new values.
    pub async fn update_retention(
        &self,
        settings: RetentionSettings,
    ) -> Result<RetentionSettings, StorageError> {
        sqlx::query(
            "UPDATE retention_settings SET session_ttl_days = $1, max_packets_stored = $2, \
             updated_at = now() WHERE id = 1",
        )
        .bind(settings.session_ttl_days)
        .bind(settings.max_packets_stored)
        .execute(&self.pool)
        .await?;
        self.retention().await
    }

    /// Deletes sessions whose retention period has passed, with everything
    /// stored for them. Returns how many sessions were deleted.
    pub async fn purge_expired(&self) -> Result<u64, StorageError> {
        let result = sqlx::query("DELETE FROM capture_sessions WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
