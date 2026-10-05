//! Flow reconstruction scenarios built from synthetic packets.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::IpAddr;
use std::time::Duration;

use capture::{Timestamp, TimestampResolution};
use decoder::{DecodedPacket, LINKTYPE_ETHERNET, TcpFlags, decode_packet};
use flow_engine::{
    Dominance, EndReason, FlowConfig, FlowEngine, FlowPacket, FlowRecord, FlowWarningCode,
    InitiatorBasis, TcpState,
};
use proptest::prelude::*;

const A: [u8; 4] = [192, 0, 2, 10];
const B: [u8; 4] = [198, 51, 100, 20];
const C: [u8; 4] = [203, 0, 113, 5];
const BASE: u32 = 1_767_225_600;

fn checksum(header: &mut [u8]) {
    let mut sum: u32 = 0;
    for pair in header.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    header[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}

fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1];
    out.extend(ethertype.to_be_bytes());
    out.extend(payload);
    out
}

fn ipv4(src: [u8; 4], dst: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut header = vec![0x45, 0];
    header.extend(total.to_be_bytes());
    header.extend([0, 1, 0x40, 0, 64, protocol, 0, 0]);
    header.extend(src);
    header.extend(dst);
    checksum(&mut header);
    header.extend(payload);
    header
}

fn ipv6(src: u8, dst: u8, next: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60, 0, 0, 0];
    out.extend((payload.len() as u16).to_be_bytes());
    out.extend([next, 64]);
    for last in [src, dst] {
        out.extend([0x20, 0x01, 0x0d, 0xb8]);
        out.extend([0; 11]);
        out.push(last);
    }
    out.extend(payload);
    out
}

fn tcp(sport: u16, dport: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = sport.to_be_bytes().to_vec();
    out.extend(dport.to_be_bytes());
    out.extend(seq.to_be_bytes());
    out.extend(1u32.to_be_bytes());
    out.extend([0x50, flags as u8, 0xFA, 0xF0, 0, 0, 0, 0]);
    out.extend(payload);
    out
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = sport.to_be_bytes().to_vec();
    out.extend(dport.to_be_bytes());
    out.extend(((8 + payload.len()) as u16).to_be_bytes());
    out.extend([0, 0]);
    out.extend(payload);
    out
}

fn tcp4(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    flags: u16,
    seq: u32,
    len: usize,
) -> Vec<u8> {
    ethernet(
        0x0800,
        &ipv4(
            src,
            dst,
            6,
            &tcp(sport, dport, flags, seq, &vec![0x41; len]),
        ),
    )
}

fn udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, len: usize) -> Vec<u8> {
    ethernet(
        0x0800,
        &ipv4(src, dst, 17, &udp(sport, dport, &vec![0x41; len])),
    )
}

/// Builder for a sequence of timed packets.
#[derive(Default)]
struct Trace {
    packets: Vec<(Option<Timestamp>, Vec<u8>)>,
}

impl Trace {
    /// Adds a frame at `millis` after the base time.
    fn at(mut self, millis: u64, frame: Vec<u8>) -> Self {
        let secs = BASE + u32::try_from(millis / 1000).unwrap();
        let micros = u32::try_from((millis % 1000) * 1000).unwrap();
        let ts = Timestamp::from_record(secs, micros, TimestampResolution::Microsecond);
        self.packets.push((ts, frame));
        self
    }

    /// Adds a frame at an absolute Unix time in seconds.
    fn at_unix(mut self, seconds: u32, frame: Vec<u8>) -> Self {
        let ts = Timestamp::from_record(seconds, 0, TimestampResolution::Microsecond);
        self.packets.push((ts, frame));
        self
    }

    fn untimed(mut self, frame: Vec<u8>) -> Self {
        self.packets.push((None, frame));
        self
    }

    fn run(&self, config: FlowConfig) -> flow_engine::FlowReport {
        let decoded: Vec<DecodedPacket> = self
            .packets
            .iter()
            .map(|(_, f)| decode_packet(LINKTYPE_ETHERNET, f, f.len() as u32))
            .collect();
        let mut engine = FlowEngine::new(config);
        for (i, ((ts, frame), decoded)) in self.packets.iter().zip(&decoded).enumerate() {
            let _ = engine.process(&FlowPacket {
                index: i as u64 + 1,
                timestamp: *ts,
                wire_length: frame.len() as u32,
                decoded,
            });
        }
        engine.finish()
    }

    fn flows(&self) -> Vec<FlowRecord> {
        self.run(FlowConfig::default()).flows
    }
}

fn ip(octets: [u8; 4]) -> IpAddr {
    IpAddr::from(octets)
}

const SYN: u16 = TcpFlags::SYN;
const SYN_ACK: u16 = TcpFlags::SYN | TcpFlags::ACK;
const ACK: u16 = TcpFlags::ACK;
const PSH_ACK: u16 = TcpFlags::PSH | TcpFlags::ACK;
const FIN_ACK: u16 = TcpFlags::FIN | TcpFlags::ACK;
const RST: u16 = TcpFlags::RST;

#[test]
fn forward_and_reverse_packets_share_one_flow() {
    let flows = Trace::default()
        .at(0, tcp4(A, B, 40000, 443, SYN, 100, 0))
        .at(10, tcp4(B, A, 443, 40000, SYN_ACK, 500, 0))
        .at(20, tcp4(A, B, 40000, 443, ACK, 101, 0))
        .at(30, tcp4(A, B, 40000, 443, PSH_ACK, 101, 100))
        .at(40, tcp4(B, A, 443, 40000, PSH_ACK, 501, 1000))
        .flows();
    assert_eq!(flows.len(), 1);
    let f = &flows[0];
    assert_eq!(f.flow_id, 1);
    assert_eq!((f.initiator.ip, f.initiator.port), (ip(A), 40000));
    assert_eq!((f.responder.ip, f.responder.port), (ip(B), 443));
    assert_eq!(f.initiator_basis, InitiatorBasis::TcpSyn);
    assert_eq!(f.initiator_to_responder.packets, 3);
    assert_eq!(f.responder_to_initiator.packets, 2);
    assert_eq!(f.initiator_to_responder.payload_bytes, 100);
    assert_eq!(f.responder_to_initiator.payload_bytes, 1000);
    assert_eq!(f.packets_total, 5);
    assert_eq!(f.bytes_total, 54 * 3 + 154 + 1054);
    assert_eq!(f.tcp.as_ref().unwrap().state, TcpState::Established);
    assert_eq!(f.dominant_endpoint, Dominance::Responder);
    assert!((f.duration_seconds - 0.04).abs() < 1e-9);
    assert_eq!(f.end_reason, EndReason::CaptureEnd);
    assert_eq!((f.first_packet_index, f.last_packet_index), (1, 5));
    assert_eq!(f.protocol_name, Some("TCP"));
}

#[test]
fn initiator_comes_from_the_handshake_not_from_address_order() {
    // The higher address/port side initiates: sort order must not decide.
    let flows = Trace::default()
        .at(0, tcp4(B, A, 50000, 22, SYN, 1, 0))
        .at(1, tcp4(A, B, 22, 50000, SYN_ACK, 1, 0))
        .flows();
    assert_eq!(flows[0].initiator.ip, ip(B));
    assert_eq!(flows[0].tcp.as_ref().unwrap().state, TcpState::SynReceived);

    // Capture starts at the SYN-ACK: the receiver of the SYN-ACK initiated.
    let flows = Trace::default()
        .at(0, tcp4(A, B, 443, 40000, SYN_ACK, 1, 0))
        .at(1, tcp4(B, A, 40000, 443, ACK, 2, 0))
        .flows();
    assert_eq!(flows[0].initiator_basis, InitiatorBasis::TcpSynAck);
    assert_eq!(
        (flows[0].initiator.ip, flows[0].initiator.port),
        (ip(B), 40000)
    );
    assert_eq!(flows[0].tcp.as_ref().unwrap().state, TcpState::Established);

    // Mid-stream: first sender is assumed to be the initiator.
    let flows = Trace::default()
        .at(0, tcp4(B, A, 443, 40000, PSH_ACK, 1, 10))
        .flows();
    assert_eq!(flows[0].initiator_basis, InitiatorBasis::FirstPacket);
    assert_eq!(flows[0].initiator.ip, ip(B));
    assert_eq!(flows[0].tcp.as_ref().unwrap().state, TcpState::Midstream);
}

#[test]
fn tcp_state_approximation() {
    let base = || {
        Trace::default()
            .at(0, tcp4(A, B, 40000, 80, SYN, 1, 0))
            .at(1, tcp4(B, A, 80, 40000, SYN_ACK, 1, 0))
            .at(2, tcp4(A, B, 40000, 80, ACK, 2, 0))
    };
    let state = |t: Trace| t.flows()[0].tcp.clone().unwrap();
    assert_eq!(
        state(Trace::default().at(0, tcp4(A, B, 1, 2, SYN, 1, 0))).state,
        TcpState::SynSent
    );
    let closing = state(base().at(3, tcp4(A, B, 40000, 80, FIN_ACK, 2, 0)));
    assert_eq!(closing.state, TcpState::Closing);
    let closed = state(
        base()
            .at(3, tcp4(A, B, 40000, 80, FIN_ACK, 2, 0))
            .at(4, tcp4(B, A, 80, 40000, FIN_ACK, 2, 0)),
    );
    assert_eq!(closed.state, TcpState::Closed);
    assert_eq!(closed.fin_packets, 2);
    assert_eq!(closed.flags_initiator, ["FIN", "SYN", "ACK"]);
    let reset = state(base().at(3, tcp4(B, A, 80, 40000, RST, 2, 0)));
    assert_eq!(reset.state, TcpState::Reset);
    assert_eq!(reset.rst_packets, 1);
}

#[test]
fn ipv6_and_udp_flows() {
    let v6 = ethernet(0x86DD, &ipv6(0x0a, 0x14, 17, &udp(5000, 6000, &[0; 10])));
    let v6_reply = ethernet(0x86DD, &ipv6(0x14, 0x0a, 17, &udp(6000, 5000, &[0; 30])));
    let flows = Trace::default()
        .at(0, v6)
        .at(5, v6_reply)
        .at(6, udp4(A, B, 1000, 2000, 5))
        .flows();
    assert_eq!(flows.len(), 2);
    assert_eq!(flows[0].ip_version, 6);
    assert_eq!(flows[0].protocol, 17);
    assert_eq!(flows[0].packets_total, 2);
    assert_eq!(flows[0].initiator.port, 5000);
    assert!(flows[0].tcp.is_none());
    assert_eq!(flows[1].ip_version, 4);
}

#[test]
fn different_ports_or_protocols_are_different_flows() {
    let flows = Trace::default()
        .at(0, udp4(A, B, 1000, 53, 10))
        .at(1, udp4(A, B, 1001, 53, 10))
        .at(2, tcp4(A, B, 1000, 53, SYN, 1, 0))
        .at(3, udp4(A, C, 1000, 53, 10))
        .flows();
    assert_eq!(flows.len(), 4);
    let ids: Vec<u64> = flows.iter().map(|f| f.flow_id).collect();
    assert_eq!(ids, [1, 2, 3, 4]);
}

#[test]
fn idle_flows_expire_and_restart() {
    let flows = Trace::default()
        .at(0, udp4(A, B, 1000, 2000, 1))
        .at(30_000, udp4(A, B, 1000, 2000, 1)) // within 60 s
        .at(100_000, udp4(A, B, 1000, 2000, 1)) // 70 s idle: new flow
        .flows();
    assert_eq!(flows.len(), 2);
    assert_eq!(flows[0].end_reason, EndReason::IdleTimeout);
    assert_eq!(flows[0].packets_total, 2);
    assert_eq!(flows[1].packets_total, 1);
    assert_eq!(flows[1].end_reason, EndReason::CaptureEnd);
}

#[test]
fn tcp_uses_its_own_idle_timeout_and_finished_linger() {
    let flows = Trace::default()
        .at(0, tcp4(A, B, 1, 2, PSH_ACK, 1, 1))
        .at(200_000, tcp4(A, B, 1, 2, PSH_ACK, 2, 1)) // 200 s < 300 s
        .flows();
    assert_eq!(flows.len(), 1);

    let flows = Trace::default()
        .at(0, tcp4(A, B, 1, 2, SYN, 1, 0))
        .at(1, tcp4(B, A, 2, 1, RST, 1, 0))
        .at(20_000, udp4(A, C, 3, 4, 1)) // advances time past the 10 s linger
        .flows();
    assert_eq!(flows[0].end_reason, EndReason::TcpFinished);
    assert_eq!(flows[1].end_reason, EndReason::CaptureEnd);
}

#[test]
fn full_tables_evict_the_least_recently_seen_flow() {
    let config = FlowConfig {
        max_active_flows: 2,
        ..FlowConfig::default()
    };
    let report = Trace::default()
        .at(0, udp4(A, B, 1, 1, 1)) // flow 1
        .at(1, udp4(A, B, 2, 2, 1)) // flow 2
        .at(2, udp4(A, B, 1, 1, 1)) // flow 1 is now most recent
        .at(3, udp4(A, B, 3, 3, 1)) // flow 3 evicts flow 2
        .run(config);
    let reasons: Vec<(u64, EndReason)> = report
        .flows
        .iter()
        .map(|f| (f.flow_id, f.end_reason))
        .collect();
    assert_eq!(
        reasons,
        [
            (1, EndReason::CaptureEnd),
            (2, EndReason::Evicted),
            (3, EndReason::CaptureEnd)
        ]
    );
    assert_eq!(report.summary.peak_active_flows, 2);
    assert_eq!(report.summary.end_reasons[&EndReason::Evicted], 1);
}

#[test]
fn retained_flows_are_capped_but_counted() {
    let config = FlowConfig {
        max_retained_flows: 2,
        ..FlowConfig::default()
    };
    let mut trace = Trace::default();
    for port in 0..5 {
        trace = trace.at(u64::from(port), udp4(A, B, port, port, 1));
    }
    let report = trace.run(config);
    assert_eq!(report.flows.len(), 2);
    assert_eq!(report.summary.flows_total, 5);
    assert_eq!(report.summary.flows_not_retained, 3);
}

#[test]
fn statistics_are_exact_for_small_flows() {
    let flows = Trace::default()
        .at(0, udp4(A, B, 1, 2, 0)) // 42 bytes
        .at(100, udp4(B, A, 2, 1, 10)) // 52
        .at(300, udp4(A, B, 1, 2, 20)) // 62
        .flows();
    let f = &flows[0];
    let size = f.packet_size.unwrap();
    assert_eq!((size.min, size.max, size.median), (42.0, 62.0, 52.0));
    assert!((size.mean - 52.0).abs() < 1e-9);
    assert!(size.median_exact);
    let gaps = f.inter_arrival.unwrap();
    assert!((gaps.min_seconds - 0.1).abs() < 1e-9);
    assert!((gaps.max_seconds - 0.2).abs() < 1e-9);
    assert!((gaps.mean_seconds - 0.15).abs() < 1e-9);
}

#[test]
fn duplicates_are_detected() {
    let flows = Trace::default()
        .at(0, tcp4(A, B, 1, 2, PSH_ACK, 10, 5))
        .at(1, tcp4(A, B, 1, 2, PSH_ACK, 10, 5))
        .at(2, tcp4(A, B, 1, 2, PSH_ACK, 15, 5))
        .flows();
    assert_eq!(flows[0].tcp.as_ref().unwrap().duplicate_segments, 1);
}

#[test]
fn out_of_order_and_missing_timestamps_are_warnings() {
    let flows = Trace::default()
        .at(1000, udp4(A, B, 1, 2, 1))
        .at(500, udp4(A, B, 1, 2, 1))
        .untimed(udp4(A, B, 1, 2, 1))
        .at(1500, udp4(A, B, 1, 2, 1))
        .flows();
    let f = &flows[0];
    let codes: Vec<(FlowWarningCode, u64)> = f.warnings.iter().map(|w| (w.code, w.count)).collect();
    assert_eq!(
        codes,
        [
            (FlowWarningCode::OutOfOrderTimestamp, 1),
            (FlowWarningCode::MissingTimestamp, 1)
        ]
    );
    // First/last seen are the true minimum and maximum.
    assert!((f.duration_seconds - 1.0).abs() < 1e-9);
    // Negative gaps are clamped to zero.
    assert_eq!(f.inter_arrival.unwrap().min_seconds, 0.0);
}

#[test]
fn process_reports_the_assigned_flow() {
    let frames = [
        udp4(A, B, 1, 2, 1),
        udp4(B, A, 2, 1, 1),
        udp4(A, C, 1, 2, 1),
    ];
    let mut engine = FlowEngine::new(FlowConfig::default());
    let ids: Vec<Option<u64>> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let decoded = decode_packet(LINKTYPE_ETHERNET, f, f.len() as u32);
            engine.process(&FlowPacket {
                index: i as u64 + 1,
                timestamp: None,
                wire_length: f.len() as u32,
                decoded: &decoded,
            })
        })
        .collect();
    assert_eq!(ids, [Some(1), Some(1), Some(2)]);
    let arp = decode_packet(LINKTYPE_ETHERNET, &[0; 20], 20);
    let none = engine.process(&FlowPacket {
        index: 4,
        timestamp: None,
        wire_length: 20,
        decoded: &arp,
    });
    assert_eq!(none, None);
}

#[test]
fn non_ip_packets_are_counted_not_flowed() {
    let arp = ethernet(
        0x0806,
        &[
            0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1, 192, 0, 2, 10, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1,
        ],
    );
    let report = Trace::default()
        .at(0, arp)
        .at(1, udp4(A, B, 1, 2, 1))
        .run(FlowConfig::default());
    assert_eq!(report.summary.packets_seen, 2);
    assert_eq!(report.summary.packets_without_ip, 1);
    assert_eq!(report.summary.packets_in_flows, 1);
    assert_eq!(report.flows.len(), 1);
}

#[test]
fn output_is_deterministic() {
    let trace = || {
        let mut t = Trace::default();
        for i in 0..200u16 {
            let src = if i % 3 == 0 { A } else { C };
            t = t.at(
                u64::from(i) * 7,
                udp4(src, B, 1000 + i % 17, 53 + i % 5, usize::from(i % 50)),
            );
        }
        t
    };
    let config = FlowConfig {
        max_active_flows: 8,
        ..FlowConfig::default()
    };
    let first = serde_json::to_string(&trace().run(config)).unwrap();
    let second = serde_json::to_string(&trace().run(config)).unwrap();
    assert_eq!(first, second);
}

#[test]
fn json_has_no_payload_and_documented_shape() {
    let report = Trace::default()
        .at(0, tcp4(A, B, 1, 2, PSH_ACK, 1, 40))
        .run(FlowConfig::default());
    let json = serde_json::to_value(&report).unwrap();
    let flow = &json["flows"][0];
    assert_eq!(flow["initiator"]["ip"], "192.0.2.10");
    assert_eq!(
        flow["tcp"]["flags_initiator"],
        serde_json::json!(["PSH", "ACK"])
    );
    assert_eq!(flow["alert_ids"], serde_json::json!([]));
    assert!(!json.to_string().contains("AAAA"));
}

#[test]
fn engine_respects_timeout_configuration() {
    let config = FlowConfig {
        idle_timeout: Duration::from_secs(1),
        ..FlowConfig::default()
    };
    let report = Trace::default()
        .at(0, udp4(A, B, 1, 2, 1))
        .at(1500, udp4(A, B, 1, 2, 1))
        .run(config);
    assert_eq!(report.flows.len(), 2);
}

#[test]
fn one_far_future_timestamp_does_not_end_or_freeze_flows() {
    let report = Trace::default()
        .at(0, udp4(A, B, 1, 2, 1)) // flow 1
        .at(10, udp4(A, C, 3, 4, 1)) // flow 2
        .at_unix(u32::MAX, udp4(A, B, 1, 2, 1)) // corrupt record on flow 1
        .at(20, udp4(A, B, 1, 2, 1)) // still flow 1
        .at(120_000, udp4(A, B, 1, 2, 1)) // two minutes later: a new flow
        .run(FlowConfig::default());
    let flows: Vec<(u64, u64, EndReason)> = report
        .flows
        .iter()
        .map(|f| (f.flow_id, f.packets_total, f.end_reason))
        .collect();
    assert_eq!(
        flows,
        [
            (1, 3, EndReason::IdleTimeout),
            (2, 1, EndReason::IdleTimeout),
            (3, 1, EndReason::CaptureEnd),
        ]
    );
    assert!(
        report.flows[0]
            .warnings
            .iter()
            .any(|w| w.code == FlowWarningCode::TimestampOutlier && w.count == 1)
    );
    assert_eq!(report.summary.timestamp_outliers, 1);
    assert_eq!(report.summary.clock_jumps, 0);
}

#[test]
fn a_corrupt_first_record_does_not_merge_traffic_an_hour_apart() {
    let flows = Trace::default()
        .at_unix(u32::MAX, udp4(C, B, 9, 9, 1))
        .at(0, udp4(A, B, 1, 2, 1))
        .at(3_600_000, udp4(A, B, 1, 2, 1))
        .flows();
    let packets: Vec<u64> = flows.iter().map(|f| f.packets_total).collect();
    assert_eq!(packets, [1, 1, 1]);
}

#[test]
fn sparse_traffic_is_not_mistaken_for_outliers() {
    let mut trace = Trace::default();
    for i in 0..20u64 {
        trace = trace.at(i * 400_000, udp4(A, B, 1, 2, 1));
    }
    let report = trace.run(FlowConfig::default());
    assert_eq!(report.flows.len(), 20);
    assert_eq!(report.summary.peak_active_flows, 1);
    assert_eq!(report.summary.timestamp_outliers, 0);

    let mut trace = Trace::default();
    for i in 0..10u64 {
        trace = trace.at(i * 10_000, udp4(A, B, 1, 2, 1));
    }
    let short = FlowConfig {
        idle_timeout: Duration::from_secs(5),
        tcp_idle_timeout: Duration::from_secs(5),
        ..FlowConfig::default()
    };
    let report = trace.run(short);
    assert_eq!(report.flows.len(), 10);
    assert_eq!(report.summary.peak_active_flows, 1);
}

#[test]
fn merged_captures_with_clock_skew_keep_conversations_together() {
    // A second tap whose clock lags 120 s (more than the 60 s UDP timeout).
    let mut trace = Trace::default();
    for i in 0..10u64 {
        let at = 200_000 + i * 1000;
        trace = trace
            .at(at, udp4(A, B, 1, 2, 1))
            .at(at - 120_000, udp4(B, A, 2, 1, 1));
    }
    let flows = trace.flows();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].packets_total, 20);
}

#[test]
fn a_far_future_first_timestamp_is_corrected_by_the_packets_after_it() {
    let report = Trace::default()
        .untimed(udp4(A, B, 1, 2, 1)) // flow 1, before any time
        .at_unix(u32::MAX, udp4(C, B, 9, 9, 1)) // flow 2: the clock starts in 2106
        .at(0, udp4(A, B, 1, 2, 1)) // held
        .at(10, udp4(A, B, 1, 2, 1)) // confirms the jump back
        .at(100_000, udp4(A, B, 1, 2, 1)) // a later, separate flow
        .run(FlowConfig::default());
    let flows: Vec<(u64, u64, EndReason)> = report
        .flows
        .iter()
        .map(|f| (f.flow_id, f.packets_total, f.end_reason))
        .collect();
    assert_eq!(
        flows,
        [
            (1, 2, EndReason::ClockReset),
            (2, 1, EndReason::ClockReset),
            (3, 1, EndReason::IdleTimeout),
            (4, 1, EndReason::CaptureEnd),
        ]
    );
    assert_eq!(report.summary.clock_jumps, 1);
    assert_eq!(report.summary.timestamp_outliers, 0);
    // The confirmed timestamp counts in flow 1's time range; 2106 does not
    // appear anywhere else.
    assert!(
        report.flows[0]
            .warnings
            .iter()
            .all(|w| w.code != FlowWarningCode::TimestampOutlier)
    );
}

#[test]
fn a_real_gap_of_days_keeps_the_next_conversation_whole() {
    let two_days = 2 * 86_400_000;
    let report = Trace::default()
        .at(0, udp4(A, B, 1000, 53, 1))
        .at(5, udp4(B, A, 53, 1000, 1))
        .at(two_days, udp4(A, C, 2000, 53, 1)) // held, then confirmed
        .at(two_days + 5, udp4(C, A, 53, 2000, 1))
        .run(FlowConfig::default());
    let flows: Vec<(u64, u64, IpAddr)> = report
        .flows
        .iter()
        .map(|f| (f.flow_id, f.packets_total, f.initiator.ip))
        .collect();
    assert_eq!(flows, [(1, 2, ip(A)), (2, 2, ip(A))]);
    assert_eq!(report.flows[0].end_reason, EndReason::IdleTimeout);
    assert!(
        report.flows[1].warnings.is_empty(),
        "{:?}",
        report.flows[1].warnings
    );
    assert!(report.flows[1].first_seen.is_some());
    assert_eq!(report.summary.clock_jumps, 1);
    assert_eq!(report.summary.timestamp_outliers, 0);
}

#[test]
fn repeated_jumps_back_in_time_end_flows_once() {
    // Many active flows, then pairs of packets each stepping back more than
    // a day: every jump ends the active flows, so each flow is ended once.
    let mut trace = Trace::default();
    for port in 0..2000u16 {
        trace = trace.at(400 * 86_400_000, udp4(A, B, port, 9, 1));
    }
    for i in 1..=200u64 {
        let at = (400 - 2 * i) * 86_400_000;
        trace = trace
            .at(at, udp4(A, B, 1, 9, 1))
            .at(at + 1, udp4(A, B, 1, 9, 1));
    }
    let report = trace.run(FlowConfig::default());
    assert_eq!(report.summary.clock_jumps, 200);
    assert_eq!(
        report.summary.end_reasons[&EndReason::ClockReset],
        2000 + 199
    );
}

#[test]
fn a_far_future_first_timestamp_does_not_freeze_expiry() {
    let flows = Trace::default()
        .at_unix(u32::MAX, udp4(C, B, 5, 6, 1))
        .at(0, udp4(A, B, 1, 2, 1))
        .at(10, udp4(A, C, 3, 4, 1)) // confirms the real time
        .at(100_000, udp4(A, B, 1, 2, 1)) // 100 s later: new flow
        .at(100_010, udp4(A, B, 1, 2, 1))
        .flows();
    let packets: Vec<u64> = flows.iter().map(|f| f.packets_total).collect();
    assert_eq!(packets, [1, 1, 1, 2]);
    // The confirmed jump back in time ended the flows from before it.
    assert_eq!(flows[0].end_reason, EndReason::ClockReset);
    assert_eq!(flows[1].end_reason, EndReason::ClockReset);
    assert_eq!(flows[2].end_reason, EndReason::IdleTimeout);
}

#[test]
fn a_packet_after_its_flows_idle_timeout_starts_a_new_flow_even_in_sparse_captures() {
    // Each gap exceeds the clock's tolerance and is never confirmed, so the
    // clock does not move; the flow still splits on its own timing.
    let flows = Trace::default()
        .at(0, udp4(A, B, 1, 2, 1))
        .at(1_000_000, udp4(A, B, 1, 2, 1))
        .at(2_000_000, udp4(A, B, 1, 2, 1))
        .flows();
    assert_eq!(flows.len(), 3);
    assert_eq!(flows[0].end_reason, EndReason::IdleTimeout);
}

#[test]
fn untimed_first_packets_join_the_flow_of_later_timed_ones() {
    let flows = Trace::default()
        .untimed(udp4(A, B, 1000, 53, 1))
        .at(1, udp4(B, A, 53, 1000, 1))
        .flows();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].initiator.ip, ip(A));
    assert_eq!(flows[0].packets_total, 2);
}

#[test]
fn eviction_follows_packet_order_when_timestamps_tie() {
    let config = FlowConfig {
        max_active_flows: 2,
        ..FlowConfig::default()
    };
    // Everything at the same instant: the busy flow is touched before each
    // new flow arrives, so the other flow is always the least recent.
    let report = Trace::default()
        .at(0, udp4(A, B, 1, 1, 1)) // busy flow 1
        .at(0, udp4(A, B, 2, 2, 1)) // flow 2
        .at(0, udp4(A, B, 1, 1, 1))
        .at(0, udp4(A, B, 3, 3, 1)) // evicts 2
        .at(0, udp4(A, B, 1, 1, 1))
        .at(0, udp4(A, B, 4, 4, 1)) // evicts 3
        .run(config);
    let busy = &report.flows[0];
    assert_eq!((busy.flow_id, busy.packets_total), (1, 3));
    assert_eq!(busy.end_reason, EndReason::CaptureEnd);
    assert_eq!(report.summary.end_reasons[&EndReason::Evicted], 2);
}

#[test]
fn pure_acks_are_not_duplicates_but_retransmitted_data_is() {
    let mut trace = Trace::default()
        .at(0, tcp4(A, B, 1, 2, SYN, 100, 0))
        .at(1, tcp4(B, A, 2, 1, SYN_ACK, 500, 0))
        .at(2, tcp4(A, B, 1, 2, ACK, 101, 0));
    for i in 0..6u32 {
        let at = 3 + u64::from(i) * 2;
        trace = trace
            .at(at, tcp4(B, A, 2, 1, PSH_ACK, 501 + i * 10, 10))
            .at(at + 1, tcp4(A, B, 1, 2, ACK, 101, 0));
    }
    let flows = trace
        .at(20, tcp4(B, A, 2, 1, PSH_ACK, 551, 10)) // retransmission
        .flows();
    assert_eq!(flows[0].tcp.as_ref().unwrap().duplicate_segments, 1);
}

#[test]
fn a_new_syn_after_close_starts_a_new_flow() {
    let flows = Trace::default()
        .at(0, tcp4(A, B, 1, 2, SYN, 1, 0))
        .at(1, tcp4(B, A, 2, 1, RST, 0, 0))
        .at(2, tcp4(A, B, 1, 2, SYN, 7, 0)) // retry on the same ports
        .at(3, tcp4(B, A, 2, 1, SYN_ACK, 9, 0))
        .flows();
    assert_eq!(flows.len(), 2);
    assert_eq!(flows[0].end_reason, EndReason::TcpFinished);
    assert_eq!(flows[0].tcp.as_ref().unwrap().state, TcpState::Reset);
    assert_eq!(flows[1].tcp.as_ref().unwrap().state, TcpState::SynReceived);
}

#[test]
fn retained_flows_are_the_lowest_ids() {
    let config = FlowConfig {
        max_retained_flows: 2,
        idle_timeout: Duration::from_secs(1),
        ..FlowConfig::default()
    };
    // Flow 1 stays open longest, so it finishes last.
    let report = Trace::default()
        .at(0, udp4(A, B, 1, 1, 1))
        .at(10, udp4(A, B, 2, 2, 1))
        .at(20, udp4(A, B, 3, 3, 1))
        .at(900, udp4(A, B, 1, 1, 1))
        .at(1500, udp4(A, C, 9, 9, 1)) // expires flows 2 and 3
        .run(config);
    let ids: Vec<u64> = report.flows.iter().map(|f| f.flow_id).collect();
    assert_eq!(ids, [1, 2]);
    assert_eq!(report.summary.flows_not_retained, 2);
}

#[test]
fn tcp_without_a_transport_header_is_flagged() {
    // An IPv4 header announcing TCP, cut before the TCP header.
    let mut frame = tcp4(A, B, 1, 2, PSH_ACK, 1, 0);
    frame.truncate(14 + 20 + 4);
    let decoded = decode_packet(LINKTYPE_ETHERNET, &frame, 14 + 20 + 20);
    let mut engine = FlowEngine::new(FlowConfig::default());
    engine.process(&FlowPacket {
        index: 1,
        timestamp: None,
        wire_length: 54,
        decoded: &decoded,
    });
    let flow = &engine.finish().flows[0];
    assert_eq!(flow.initiator.port, 0);
    assert!(
        flow.warnings
            .iter()
            .any(|w| w.code == FlowWarningCode::MissingTransportHeader && w.count == 1),
        "{:?}",
        flow.warnings
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Packet and byte totals are conserved whatever the traffic, timing and
    /// table size, and flow IDs are unique and ordered.
    #[test]
    fn totals_are_conserved(
        packets in proptest::collection::vec((0u8..4, 0u16..6, 0u16..6, any::<bool>(), 0u64..120_000, 0usize..64), 1..120),
        max_active in 1usize..6,
    ) {
        let hosts = [A, B, C, [192, 0, 2, 99]];
        let mut trace = Trace::default();
        let mut expected_bytes = 0u64;
        for (host, sport, dport, is_tcp, at, len) in &packets {
            let (src, dst) = (hosts[usize::from(*host)], hosts[usize::from((*host + 1) % 4)]);
            let frame = if *is_tcp {
                tcp4(src, dst, *sport, *dport, PSH_ACK, 1, *len)
            } else {
                udp4(src, dst, *sport, *dport, *len)
            };
            expected_bytes += frame.len() as u64;
            trace = trace.at(*at, frame);
        }
        let report = trace.run(FlowConfig { max_active_flows: max_active, ..FlowConfig::default() });
        let packets_total: u64 = report.flows.iter().map(|f| f.packets_total).sum();
        let bytes_total: u64 = report.flows.iter().map(|f| f.bytes_total).sum();
        prop_assert_eq!(packets_total, packets.len() as u64);
        prop_assert_eq!(bytes_total, expected_bytes);
        prop_assert!(report.summary.peak_active_flows <= max_active as u64);
        let ids: Vec<u64> = report.flows.iter().map(|f| f.flow_id).collect();
        prop_assert!(ids.windows(2).all(|w| w[0] < w[1]));
        prop_assert_eq!(report.summary.flows_total, report.flows.len() as u64);
    }
}
