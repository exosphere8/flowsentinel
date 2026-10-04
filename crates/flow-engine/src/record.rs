//! Finished-flow summaries: the public output of the engine.

use std::sync::Arc;

use capture::Timestamp;
use decoder::Protocol;
use serde::Serialize;

use crate::key::Endpoint;
use crate::stats::Summary;

/// How the engine decided which endpoint started the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitiatorBasis {
    /// The first packet was a TCP SYN from the initiator.
    TcpSyn,
    /// The first packet was a TCP SYN-ACK, sent by the responder.
    TcpSynAck,
    /// No handshake was seen; the sender of the first packet is assumed to be
    /// the initiator.
    FirstPacket,
}

/// Approximate TCP connection state, inferred from flags only (no sequence
/// tracking).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpState {
    /// SYN seen, no SYN-ACK yet.
    SynSent,
    /// SYN-ACK seen, handshake not yet acknowledged.
    SynReceived,
    /// Handshake completed.
    Established,
    /// The flow was already running when the capture started (no SYN seen).
    Midstream,
    /// One side sent FIN.
    Closing,
    /// Both sides sent FIN.
    Closed,
    /// A RST was seen.
    Reset,
}

impl TcpState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SynSent => "syn_sent",
            Self::SynReceived => "syn_received",
            Self::Established => "established",
            Self::Midstream => "midstream",
            Self::Closing => "closing",
            Self::Closed => "closed",
            Self::Reset => "reset",
        }
    }

    /// Whether the connection has ended.
    pub fn is_finished(self) -> bool {
        matches!(self, Self::Closed | Self::Reset)
    }
}

/// Why a flow left the active table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// No packet for longer than the idle timeout.
    IdleTimeout,
    /// TCP closed (FIN both ways or RST) and the short linger elapsed.
    TcpFinished,
    /// The active-flow table was full; the least recently seen flow was
    /// evicted to make room.
    Evicted,
    /// Still active when the capture ended.
    CaptureEnd,
    /// The clock jumped back by more than a day (confirmed by two packets),
    /// so times before and after the jump cannot be compared; every active
    /// flow was ended.
    ClockReset,
}

impl EndReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdleTimeout => "idle_timeout",
            Self::TcpFinished => "tcp_finished",
            Self::Evicted => "evicted",
            Self::CaptureEnd => "capture_end",
            Self::ClockReset => "clock_reset",
        }
    }
}

/// Traffic in one direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DirectionCounters {
    pub packets: u64,
    /// On-the-wire frame bytes.
    pub bytes: u64,
    /// Transport payload bytes, from the decoded headers.
    pub payload_bytes: u64,
}

/// TCP details of a flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TcpSummary {
    pub state: TcpState,
    /// Union of flags sent by the initiator / responder.
    pub flags_initiator: Vec<&'static str>,
    pub flags_responder: Vec<&'static str>,
    pub syn_packets: u64,
    pub fin_packets: u64,
    pub rst_packets: u64,
    /// Segments identical (sequence number, payload length, flags) to the
    /// previous segment in the same direction: likely retransmissions or
    /// duplicated capture.
    pub duplicate_segments: u64,
}

/// Application metadata observed in a flow. Every list is bounded and
/// holds already-sanitized values from the decoder.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ApplicationSummary {
    /// Application protocols recognized in this flow.
    pub protocols: Vec<Protocol>,
    /// Names asked about in DNS messages carried by this flow.
    pub dns_queries: Vec<String>,
    /// Names that earlier DNS answers in the capture mapped to the
    /// responder's address (shared with the engine's name cache).
    pub responder_dns_names: Vec<Arc<str>>,
    pub http_hosts: Vec<String>,
    /// HTTP request paths (query strings already removed by the decoder).
    pub http_paths: Vec<String>,
    pub tls_server_names: Vec<String>,
    pub tls_alpn: Vec<String>,
}

/// Packet-size statistics in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct SizeSummary {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub stddev: f64,
    pub median: f64,
    /// `false` when the median was computed from the first 256 packets only.
    pub median_exact: bool,
}

/// Inter-arrival statistics in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct InterArrivalSummary {
    pub min_seconds: f64,
    pub max_seconds: f64,
    pub mean_seconds: f64,
    pub stddev_seconds: f64,
}

impl From<Summary> for InterArrivalSummary {
    fn from(s: Summary) -> Self {
        Self {
            min_seconds: s.min,
            max_seconds: s.max,
            mean_seconds: s.mean,
            stddev_seconds: s.stddev,
        }
    }
}

/// Which side sent more bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dominance {
    Initiator,
    Responder,
    /// Neither side sent more than 55% of the bytes.
    Balanced,
}

/// A non-fatal oddity seen in a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowWarningCode {
    /// A packet's timestamp was earlier than the flow's latest packet.
    OutOfOrderTimestamp,
    /// A packet had no valid timestamp; the latest valid time was used.
    MissingTimestamp,
    /// Non-initial IP fragments carry no ports, so they were counted in a
    /// port-less flow for the same addresses.
    PortlessFragments,
    /// TCP or UDP packets whose transport header was missing (cut by the
    /// snapshot length or malformed) were counted in a port-less flow.
    MissingTransportHeader,
    /// Packets whose timestamp was more than a day away from the engine's
    /// clock and was never confirmed. Those timestamps are left out of
    /// `first_seen`, `last_seen` and the timing statistics.
    TimestampOutlier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FlowWarning {
    pub code: FlowWarningCode,
    pub count: u64,
}

/// Summary of one finished flow.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FlowRecord {
    /// Sequential, starting at 1, in order of each flow's first packet.
    pub flow_id: u64,
    pub ip_version: u8,
    pub protocol: u8,
    pub protocol_name: Option<&'static str>,
    pub initiator: Endpoint,
    pub responder: Endpoint,
    pub initiator_basis: InitiatorBasis,
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
    pub duration_seconds: f64,
    pub first_packet_index: u64,
    pub last_packet_index: u64,
    pub initiator_to_responder: DirectionCounters,
    pub responder_to_initiator: DirectionCounters,
    pub packets_total: u64,
    pub bytes_total: u64,
    pub packet_size: Option<SizeSummary>,
    /// Gaps between consecutive packets; `None` with fewer than 2 packets.
    pub inter_arrival: Option<InterArrivalSummary>,
    pub tcp: Option<TcpSummary>,
    pub application: ApplicationSummary,
    pub dominant_endpoint: Dominance,
    pub end_reason: EndReason,
    pub warnings: Vec<FlowWarning>,
    /// IDs of alerts that reference this flow (filled by the detection
    /// engine in a later milestone; empty for now).
    pub alert_ids: Vec<u64>,
}
