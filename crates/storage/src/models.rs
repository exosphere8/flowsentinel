//! Rows returned by [`Storage`](crate::Storage) queries. These are also the
//! API's response bodies, so every field is metadata only.

use serde::Serialize;
use utoipa::ToSchema;

/// Converts stored Unix nanoseconds to an RFC 3339 string with nanosecond
/// precision. Returns `None` for values outside the PCAP timestamp range.
pub fn rfc3339_from_nanos(nanos: i64) -> Option<String> {
    let nanos = u64::try_from(nanos).ok()?;
    let seconds = u32::try_from(nanos / 1_000_000_000).ok()?;
    let fraction = u32::try_from(nanos % 1_000_000_000).ok()?;
    capture::Timestamp::from_record(seconds, fraction, capture::TimestampResolution::Nanosecond)
        .map(|ts| ts.to_rfc3339())
}

/// A page of results.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Paged<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub per_page: u32,
    /// Total matching items across all pages.
    pub total: i64,
}

/// A stored capture session.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Session {
    pub id: i64,
    pub file_name: String,
    pub file_size_bytes: i64,
    /// SHA-256 of the uploaded file, for identifying duplicates.
    pub sha256: String,
    pub source: String,
    pub completion_state: String,
    pub pcap_version: String,
    pub endianness: String,
    pub timestamp_resolution: String,
    pub link_type: i32,
    pub link_type_name: Option<String>,
    pub snap_length: i64,
    pub packets_processed: i64,
    /// Packets with stored metadata (may be fewer than processed, see
    /// retention settings).
    pub packets_stored: i64,
    pub captured_bytes_total: i64,
    pub original_bytes_total: i64,
    pub first_packet_ns: Option<i64>,
    pub first_packet_time: Option<String>,
    pub last_packet_ns: Option<i64>,
    pub last_packet_time: Option<String>,
    pub flows_total: i64,
    /// Flows with stored records (may be fewer than the total when the flow
    /// engine's retention limit was reached).
    pub flows_stored: i64,
    /// Alerts raised by the detection rules (heuristic indicators).
    pub alerts_total: i64,
    /// RFC 3339, UTC.
    pub created_at: String,
    /// RFC 3339, UTC. The session and everything stored for it are deleted
    /// after this time.
    pub expires_at: String,
}

/// A session with its stored summaries.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct SessionDetail {
    #[serde(flatten)]
    pub session: Session,
    #[schema(value_type = Vec<Object>)]
    pub capture_warnings: serde_json::Value,
    #[schema(value_type = Object)]
    pub decode_summary: serde_json::Value,
    #[schema(value_type = Object)]
    pub flow_summary: serde_json::Value,
    /// Alert counts by rule and severity, and what the rules evaluated.
    #[schema(value_type = Object)]
    pub detection_summary: serde_json::Value,
}

/// One stored alert: a heuristic indicator with its evidence. Never proof
/// of compromise.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct AlertRow {
    pub alert_id: i64,
    pub rule_id: String,
    pub rule_name: String,
    /// `low`, `medium` or `high`.
    pub severity: String,
    /// `low`, `medium` or `high`.
    pub confidence: String,
    /// `open`, `acknowledged`, `resolved` or `false_positive`.
    pub status: String,
    /// Always the same statement that alerts are heuristic indicators.
    pub nature: &'static str,
    pub first_seen_ns: Option<i64>,
    pub first_seen: Option<String>,
    pub last_seen_ns: Option<i64>,
    pub last_seen: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub destination_port: Option<i32>,
    pub related_flow_ids: Vec<i64>,
    pub related_packet_indexes: Vec<i64>,
    /// `[{"name": ..., "value": ...}]`: the measured facts behind the alert.
    #[schema(value_type = Vec<Object>)]
    pub evidence: serde_json::Value,
    pub explanation: String,
    pub uncertainty: String,
    pub likely_false_positives: Vec<String>,
    /// MITRE ATT&CK techniques as context only; not a claim that a technique
    /// was used.
    pub mitre_attack: Vec<String>,
    /// RFC 3339, UTC: when an analyst last changed the status.
    pub status_changed_at: Option<String>,
}

/// One packet's indexed metadata.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct PacketSummary {
    pub packet_index: i64,
    pub ts_ns: Option<i64>,
    pub time: Option<String>,
    pub captured_length: i32,
    pub original_length: i32,
    pub decode_status: String,
    pub top_protocol: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub flow_id: Option<i64>,
    pub info: String,
}

/// A packet with its full decoded protocol tree.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct PacketDetail {
    #[serde(flatten)]
    pub summary: PacketSummary,
    /// Decoded layers as produced by the decoder (metadata only).
    #[schema(value_type = Vec<Object>)]
    pub layers: serde_json::Value,
    #[schema(value_type = Vec<Object>)]
    pub warnings: serde_json::Value,
}

/// One flow's indexed metadata.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct FlowSummaryRow {
    pub flow_id: i64,
    pub ip_version: i16,
    pub protocol: i16,
    pub protocol_name: Option<String>,
    pub initiator_ip: String,
    pub initiator_port: i32,
    pub responder_ip: String,
    pub responder_port: i32,
    pub first_seen_ns: Option<i64>,
    pub first_seen: Option<String>,
    pub last_seen_ns: Option<i64>,
    pub duration_seconds: f64,
    pub packets_total: i64,
    pub bytes_total: i64,
    pub tcp_state: Option<String>,
    pub end_reason: String,
    pub dominant_endpoint: String,
    /// Alerts that cite this flow (at most 16 are linked).
    pub alert_count: i32,
    /// `low`, `medium` or `high`: the most severe linked alert.
    pub max_alert_severity: Option<String>,
}

/// A flow with its full record (statistics, TCP, application metadata).
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct FlowDetail {
    #[serde(flatten)]
    pub summary: FlowSummaryRow,
    #[schema(value_type = Object)]
    pub record: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct DnsEvent {
    pub packet_index: i64,
    pub ts_ns: Option<i64>,
    pub time: Option<String>,
    pub flow_id: Option<i64>,
    pub transaction_id: i32,
    pub is_response: bool,
    pub query_name: Option<String>,
    pub query_type: Option<String>,
    pub response_code: Option<String>,
    pub answer_count: i32,
    #[schema(value_type = Vec<Object>)]
    pub answers: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct HttpEvent {
    pub packet_index: i64,
    pub ts_ns: Option<i64>,
    pub time: Option<String>,
    pub flow_id: Option<i64>,
    pub kind: String,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub status_code: Option<i32>,
    pub content_type: Option<String>,
    /// Credentials, cookies or a query string were present and removed.
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct TlsEvent {
    pub packet_index: i64,
    pub ts_ns: Option<i64>,
    pub time: Option<String>,
    pub flow_id: Option<i64>,
    pub handshake_type: String,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub negotiated_version: Option<String>,
    pub cipher_suite_count: i32,
    /// Always "visible handshake metadata only; nothing is decrypted".
    pub visibility: &'static str,
}

/// How long imported data is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RetentionSettings {
    /// Sessions are deleted this many days after import (1-3650).
    pub session_ttl_days: i32,
    /// Packets whose metadata is stored per session (0-1000000). Flows and
    /// summaries always cover the whole capture.
    pub max_packets_stored: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nanos_format_as_rfc3339() {
        assert_eq!(
            rfc3339_from_nanos(1_767_225_600_250_000_000).as_deref(),
            Some("2026-01-01T00:00:00.250000000Z")
        );
        assert_eq!(rfc3339_from_nanos(-1), None);
        assert_eq!(rfc3339_from_nanos(i64::MAX), None);
    }
}
