//! State of one active flow.

use std::net::IpAddr;
use std::sync::Arc;

use capture::Timestamp;
use decoder::{Layer, TcpFlags, ip_protocol_name};

use crate::key::{Endpoint, FlowKey};
use crate::observe::{Observation, TcpView};
use crate::record::{
    ApplicationSummary, DirectionCounters, Dominance, EndReason, FlowRecord, FlowWarning,
    FlowWarningCode, InitiatorBasis, SizeSummary, TcpState, TcpSummary,
};
use crate::stats::{MedianSample, Running};

/// Each application list on a flow keeps at most this many distinct values,
/// so a flow's memory stays small however long its names are.
const MAX_DNS_QUERIES: usize = 4;
const MAX_NAMES: usize = 4;
const MAX_TLS_NAMES: usize = 4;
const NANOS_PER_SECOND: f64 = 1_000_000_000.0;

/// One packet as the flow engine sees it.
#[derive(Debug, Clone, Copy)]
pub struct FlowPacket<'a> {
    /// 1-based index in the capture.
    pub index: u64,
    /// `None` when the capture record's timestamp was invalid.
    pub timestamp: Option<Timestamp>,
    /// On-the-wire length.
    pub wire_length: u32,
    pub decoded: &'a decoder::DecodedPacket,
}

#[derive(Debug, Clone, Default)]
struct TcpTracker {
    state: Option<TcpState>,
    flags_initiator: u16,
    flags_responder: u16,
    syn: u64,
    fin: u64,
    rst: u64,
    duplicates: u64,
    fin_initiator: bool,
    fin_responder: bool,
    last_initiator: Option<TcpView>,
    last_responder: Option<TcpView>,
}

impl TcpTracker {
    fn update(&mut self, view: TcpView, from_initiator: bool) {
        let flags = view.flags;
        let (syn, ack, fin, rst) = (
            flags.contains(TcpFlags::SYN),
            flags.contains(TcpFlags::ACK),
            flags.contains(TcpFlags::FIN),
            flags.contains(TcpFlags::RST),
        );
        self.syn = self.syn.saturating_add(u64::from(syn));
        self.fin = self.fin.saturating_add(u64::from(fin));
        self.rst = self.rst.saturating_add(u64::from(rst));

        let (seen_flags, last) = if from_initiator {
            (&mut self.flags_initiator, &mut self.last_initiator)
        } else {
            (&mut self.flags_responder, &mut self.last_responder)
        };
        *seen_flags |= flags.0;
        // Only segments that consume sequence space (data, SYN or FIN) can be
        // retransmitted; pure ACKs legitimately repeat a sequence number.
        if view.payload_length > 0 || syn || fin {
            if *last == Some(view) {
                self.duplicates = self.duplicates.saturating_add(1);
            }
            *last = Some(view);
        }

        let state = match self.state {
            None if rst => TcpState::Reset,
            None if syn && !ack => TcpState::SynSent,
            None if syn && ack => TcpState::SynReceived,
            None => TcpState::Midstream,
            Some(TcpState::Reset) => TcpState::Reset,
            Some(_) if rst => TcpState::Reset,
            Some(TcpState::SynSent) if syn && ack => TcpState::SynReceived,
            Some(TcpState::SynReceived) if ack && !syn => TcpState::Established,
            Some(state) => state,
        };
        if fin {
            if from_initiator {
                self.fin_initiator = true;
            } else {
                self.fin_responder = true;
            }
        }
        self.state = Some(match state {
            TcpState::Reset => TcpState::Reset,
            _ if self.fin_initiator && self.fin_responder => TcpState::Closed,
            _ if self.fin_initiator || self.fin_responder => TcpState::Closing,
            other => other,
        });
    }

    fn summary(&self) -> TcpSummary {
        TcpSummary {
            state: self.state.unwrap_or(TcpState::Midstream),
            flags_initiator: TcpFlags(self.flags_initiator).names(),
            flags_responder: TcpFlags(self.flags_responder).names(),
            syn_packets: self.syn,
            fin_packets: self.fin,
            rst_packets: self.rst,
            duplicate_segments: self.duplicates,
        }
    }
}

fn push_bounded(list: &mut Vec<String>, value: &str, max: usize) {
    if list.len() < max && !list.iter().any(|v| v == value) {
        list.push(value.to_owned());
    }
}

/// An active flow.
#[derive(Debug, Clone)]
pub(crate) struct ActiveFlow {
    pub id: u64,
    pub key: FlowKey,
    initiator: Endpoint,
    responder: Endpoint,
    basis: InitiatorBasis,
    first_seen: Option<Timestamp>,
    last_seen: Option<Timestamp>,
    /// The engine's clock at this flow's latest packet; used for expiry.
    pub last_ns: u128,
    /// Engine-wide sequence number of the latest packet; used for
    /// least-recently-seen eviction.
    pub last_sequence: u64,
    first_index: u64,
    last_index: u64,
    forward: DirectionCounters,
    reverse: DirectionCounters,
    sizes: Running,
    median: MedianSample,
    gaps: Running,
    previous_ns: Option<u128>,
    tcp: Option<TcpTracker>,
    application: ApplicationSummary,
    out_of_order: u64,
    missing_timestamp: u64,
    portless_fragments: u64,
    missing_transport: u64,
    timestamp_outliers: u64,
    /// The latest timestamp the clock held instead of accepting; it does
    /// not count in the time range unless confirmed.
    held: Option<Timestamp>,
}

impl ActiveFlow {
    /// Starts a flow from its first packet. `responder_names` are DNS names
    /// previously resolved to the responder's address.
    pub(crate) fn new(
        id: u64,
        obs: &Observation<'_>,
        packet: &FlowPacket<'_>,
        now_ns: Option<u128>,
        sequence: u64,
        held_timestamp: bool,
        responder_names: impl Fn(IpAddr) -> Vec<Arc<str>>,
    ) -> Self {
        let (initiator, responder, basis) = match obs.tcp {
            Some(t) if t.flags.contains(TcpFlags::SYN) && !t.flags.contains(TcpFlags::ACK) => {
                (obs.source, obs.destination, InitiatorBasis::TcpSyn)
            }
            Some(t) if t.flags.contains(TcpFlags::SYN) && t.flags.contains(TcpFlags::ACK) => {
                (obs.destination, obs.source, InitiatorBasis::TcpSynAck)
            }
            _ => (obs.source, obs.destination, InitiatorBasis::FirstPacket),
        };
        let mut application = ApplicationSummary::default();
        let mut names = responder_names(responder.ip);
        names.truncate(MAX_NAMES);
        application.responder_dns_names = names;
        let mut flow = Self {
            id,
            key: obs.key,
            initiator,
            responder,
            basis,
            first_seen: None,
            last_seen: None,
            last_ns: 0,
            last_sequence: sequence,
            first_index: packet.index,
            last_index: packet.index,
            forward: DirectionCounters::default(),
            reverse: DirectionCounters::default(),
            sizes: Running::default(),
            median: MedianSample::default(),
            gaps: Running::default(),
            previous_ns: None,
            tcp: obs.tcp.map(|_| TcpTracker::default()),
            application,
            out_of_order: 0,
            missing_timestamp: 0,
            portless_fragments: 0,
            missing_transport: 0,
            timestamp_outliers: 0,
            held: None,
        };
        flow.update(obs, packet, now_ns, sequence, held_timestamp);
        flow
    }

    pub(crate) fn update(
        &mut self,
        obs: &Observation<'_>,
        packet: &FlowPacket<'_>,
        now_ns: Option<u128>,
        sequence: u64,
        held_timestamp: bool,
    ) {
        self.last_sequence = sequence;
        // Flows are timed by the engine's clock, not by raw timestamps.
        if let Some(now) = now_ns {
            self.last_ns = self.last_ns.max(now);
        }
        let from_initiator = obs.source == self.initiator;
        let counters = if from_initiator {
            &mut self.forward
        } else {
            &mut self.reverse
        };
        counters.packets = counters.packets.saturating_add(1);
        counters.bytes = counters.bytes.saturating_add(u64::from(packet.wire_length));
        counters.payload_bytes = counters.payload_bytes.saturating_add(obs.payload_bytes);
        self.last_index = packet.index;
        self.sizes.add(f64::from(packet.wire_length));
        self.median.add(packet.wire_length);
        if obs.portless_fragment {
            self.portless_fragments = self.portless_fragments.saturating_add(1);
        }
        if obs.missing_transport {
            self.missing_transport = self.missing_transport.saturating_add(1);
        }

        match packet.timestamp {
            // A held timestamp is kept aside until the clock confirms it.
            Some(ts) if held_timestamp => {
                self.timestamp_outliers = self.timestamp_outliers.saturating_add(1);
                self.held = Some(ts);
            }
            Some(ts) => {
                let ns = ts.as_unix_nanos();
                if self.first_seen.is_none_or(|first| ts < first) {
                    self.first_seen = Some(ts);
                }
                if self.last_seen.is_none_or(|last| ts >= last) {
                    self.last_seen = Some(ts);
                } else {
                    self.out_of_order = self.out_of_order.saturating_add(1);
                }
                if let Some(previous) = self.previous_ns {
                    // Gaps are measured in arrival order; an out-of-order
                    // packet contributes a zero gap rather than a negative one.
                    let gap = ns.saturating_sub(previous) as f64 / NANOS_PER_SECOND;
                    self.gaps.add(gap);
                }
                self.previous_ns = Some(self.previous_ns.map_or(ns, |p| p.max(ns)));
            }
            None => self.missing_timestamp = self.missing_timestamp.saturating_add(1),
        }

        if let (Some(tracker), Some(view)) = (self.tcp.as_mut(), obs.tcp) {
            tracker.update(view, from_initiator);
        }
        if let Some(layer) = obs.application {
            self.record_application(layer);
        }
    }

    fn record_application(&mut self, layer: &Layer) {
        let app = &mut self.application;
        let protocol = layer.protocol();
        if !app.protocols.contains(&protocol) {
            app.protocols.push(protocol);
        }
        match layer {
            Layer::Dns(m) => {
                for q in &m.questions {
                    push_bounded(&mut app.dns_queries, &q.name, MAX_DNS_QUERIES);
                }
            }
            Layer::Http(m) => {
                if let Some(host) = &m.host {
                    push_bounded(&mut app.http_hosts, host, MAX_NAMES);
                }
                if let Some(path) = &m.path {
                    push_bounded(&mut app.http_paths, path, MAX_NAMES);
                }
            }
            Layer::Tls(m) => {
                if let Some(sni) = &m.server_name {
                    push_bounded(&mut app.tls_server_names, sni, MAX_TLS_NAMES);
                }
                for alpn in &m.alpn {
                    push_bounded(&mut app.tls_alpn, alpn, MAX_NAMES);
                }
            }
            _ => {}
        }
    }

    /// The clock confirmed this flow's held timestamp: count it in the
    /// flow's time range after all. Returns it in nanoseconds.
    pub(crate) fn confirm_held(&mut self) -> Option<u128> {
        let ts = self.held.take()?;
        self.timestamp_outliers = self.timestamp_outliers.saturating_sub(1);
        let ns = ts.as_unix_nanos();
        if self.first_seen.is_none_or(|first| ts < first) {
            self.first_seen = Some(ts);
        }
        if self.last_seen.is_none_or(|last| ts > last) {
            self.last_seen = Some(ts);
        }
        self.previous_ns = Some(self.previous_ns.map_or(ns, |p| p.max(ns)));
        Some(ns)
    }

    /// Whether the TCP connection has finished (FIN both ways, or RST).
    pub(crate) fn tcp_finished(&self) -> bool {
        self.tcp
            .as_ref()
            .and_then(|t| t.state)
            .is_some_and(TcpState::is_finished)
    }

    pub(crate) fn into_record(self, end_reason: EndReason) -> FlowRecord {
        let duration_seconds = match (self.first_seen, self.last_seen) {
            (Some(first), Some(last)) => {
                last.as_unix_nanos().saturating_sub(first.as_unix_nanos()) as f64 / NANOS_PER_SECOND
            }
            _ => 0.0,
        };
        let packet_size =
            self.sizes
                .summary()
                .zip(self.median.median())
                .map(|(s, (median, median_exact))| SizeSummary {
                    min: s.min,
                    max: s.max,
                    mean: s.mean,
                    stddev: s.stddev,
                    median,
                    median_exact,
                });
        let (fwd, rev) = (self.forward.bytes, self.reverse.bytes);
        let total = fwd.saturating_add(rev);
        // A side dominates when it sent more than 55% of the bytes.
        let dominant_endpoint = if total == 0 {
            Dominance::Balanced
        } else if u128::from(fwd) * 100 > u128::from(total) * 55 {
            Dominance::Initiator
        } else if u128::from(rev) * 100 > u128::from(total) * 55 {
            Dominance::Responder
        } else {
            Dominance::Balanced
        };
        let mut warnings = Vec::new();
        for (code, count) in [
            (FlowWarningCode::OutOfOrderTimestamp, self.out_of_order),
            (FlowWarningCode::MissingTimestamp, self.missing_timestamp),
            (FlowWarningCode::PortlessFragments, self.portless_fragments),
            (
                FlowWarningCode::MissingTransportHeader,
                self.missing_transport,
            ),
            (FlowWarningCode::TimestampOutlier, self.timestamp_outliers),
        ] {
            if count > 0 {
                warnings.push(FlowWarning { code, count });
            }
        }
        FlowRecord {
            flow_id: self.id,
            ip_version: self.key.ip_version(),
            protocol: self.key.protocol,
            protocol_name: ip_protocol_name(self.key.protocol),
            initiator: self.initiator,
            responder: self.responder,
            initiator_basis: self.basis,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            duration_seconds,
            first_packet_index: self.first_index,
            last_packet_index: self.last_index,
            initiator_to_responder: self.forward,
            responder_to_initiator: self.reverse,
            packets_total: self.forward.packets.saturating_add(self.reverse.packets),
            bytes_total: total,
            packet_size,
            inter_arrival: self.gaps.summary().map(Into::into),
            tcp: self.tcp.as_ref().map(TcpTracker::summary),
            application: self.application,
            dominant_endpoint,
            end_reason,
            warnings,
            alert_ids: Vec::new(),
        }
    }
}
