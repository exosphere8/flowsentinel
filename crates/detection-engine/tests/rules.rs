//! Every rule against synthetic traffic: one scenario that should alert and
//! one similar scenario that should not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use capture::{Timestamp, TimestampResolution};
use decoder::{LINKTYPE_ETHERNET, TcpFlags, decode_packet};
use detection_engine::{
    Alert, Confidence, DetectionConfig, DetectionReport, Detector, NATURE, RULES,
};
use flow_engine::{FlowConfig, FlowEngine, FlowPacket, FlowRecord};
use proptest::prelude::*;

const BASE: u32 = 1_767_225_600;
const SYN: u16 = TcpFlags::SYN;
const SYN_ACK: u16 = TcpFlags::SYN | TcpFlags::ACK;
const ACK: u16 = TcpFlags::ACK;
const PSH_ACK: u16 = TcpFlags::PSH | TcpFlags::ACK;
const RST_ACK: u16 = TcpFlags::RST | TcpFlags::ACK;

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

fn ethernet(src_mac: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0xff; 6];
    out.extend(src_mac);
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

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

fn tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u16, len: usize) -> Vec<u8> {
    let mut segment = sport.to_be_bytes().to_vec();
    segment.extend(dport.to_be_bytes());
    segment.extend(1u32.to_be_bytes());
    segment.extend(1u32.to_be_bytes());
    segment.extend([0x50, flags as u8, 0xFA, 0xF0, 0, 0, 0, 0]);
    segment.extend(vec![0x41; len]);
    ethernet(MAC, 0x0800, &ipv4(src, dst, 6, &segment))
}

fn udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut datagram = sport.to_be_bytes().to_vec();
    datagram.extend(dport.to_be_bytes());
    datagram.extend(((8 + payload.len()) as u16).to_be_bytes());
    datagram.extend([0, 0]);
    datagram.extend(payload);
    ethernet(MAC, 0x0800, &ipv4(src, dst, 17, &datagram))
}

fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    for v in [id, 0x0100, 1, 0, 0, 0] {
        out.extend(v.to_be_bytes());
    }
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend(label.as_bytes());
    }
    out.push(0);
    out.extend(qtype.to_be_bytes());
    out.extend([0, 1]);
    out
}

fn arp(mac: [u8; 6], operation: u16, sender: [u8; 4], target: [u8; 4]) -> Vec<u8> {
    let mut out = vec![0, 1, 0x08, 0x00, 6, 4];
    out.extend(operation.to_be_bytes());
    out.extend(mac);
    out.extend(sender);
    out.extend([0; 6]);
    out.extend(target);
    ethernet(mac, 0x0806, &out)
}

/// A timed list of frames.
#[derive(Default)]
struct Trace(Vec<(u64, Vec<u8>)>);

impl Trace {
    fn at(&mut self, millis: u64, frame: Vec<u8>) -> &mut Self {
        self.0.push((millis, frame));
        self
    }

    fn run_with(&self, config: DetectionConfig) -> (DetectionReport, Vec<FlowRecord>) {
        let mut engine = FlowEngine::new(FlowConfig::default());
        let mut detector = Detector::new(config).unwrap();
        for (i, (millis, frame)) in self.0.iter().enumerate() {
            let secs = BASE + u32::try_from(millis / 1000).unwrap();
            let micros = u32::try_from((millis % 1000) * 1000).unwrap();
            let ts = Timestamp::from_record(secs, micros, TimestampResolution::Microsecond);
            let decoded = decode_packet(LINKTYPE_ETHERNET, frame, frame.len() as u32);
            let index = i as u64 + 1;
            let flow = engine.process(&FlowPacket {
                index,
                timestamp: ts,
                wire_length: frame.len() as u32,
                decoded: &decoded,
            });
            detector.observe_packet(index, ts, &decoded, flow);
        }
        let mut flows = engine.finish().flows;
        let report = detector.finish(&mut flows);
        (report, flows)
    }

    fn alerts(&self) -> Vec<Alert> {
        self.run_with(DetectionConfig::default()).0.alerts
    }
}

fn rules(alerts: &[Alert]) -> Vec<&'static str> {
    let mut ids: Vec<&str> = alerts.iter().map(|a| a.rule_id).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn find<'a>(alerts: &'a [Alert], rule: &str) -> &'a Alert {
    alerts
        .iter()
        .find(|a| a.rule_id == rule)
        .unwrap_or_else(|| panic!("no {rule} in {:?}", rules(alerts)))
}

const A: [u8; 4] = [192, 0, 2, 10];
const B: [u8; 4] = [198, 51, 100, 20];
const C: [u8; 4] = [203, 0, 113, 5];

/// SYNs from A to `ports` on `dst`, each refused.
fn refused(trace: &mut Trace, dst: [u8; 4], ports: impl Iterator<Item = u16>, start: u64) {
    for (i, port) in ports.enumerate() {
        let at = start + i as u64 * 10;
        trace
            .at(at, tcp(A, dst, 40_000 + port, port, SYN, 0))
            .at(at + 1, tcp(dst, A, port, 40_000 + port, RST_ACK, 0));
    }
}

/// A full connection from A to `dst:port` with some data.
fn connection(trace: &mut Trace, dst: [u8; 4], sport: u16, port: u16, start: u64) {
    trace
        .at(start, tcp(A, dst, sport, port, SYN, 0))
        .at(start + 1, tcp(dst, A, port, sport, SYN_ACK, 0))
        .at(start + 2, tcp(A, dst, sport, port, ACK, 0))
        .at(start + 3, tcp(A, dst, sport, port, PSH_ACK, 20))
        .at(start + 4, tcp(dst, A, port, sport, PSH_ACK, 20));
}

#[test]
fn syn_scans_are_detected_but_normal_connections_are_not() {
    let mut scan = Trace::default();
    refused(&mut scan, B, 1..=25, 0);
    let alerts = scan.alerts();
    let alert = find(&alerts, "FS-SCAN-SYN");
    assert_eq!(alert.source, Some(A.into()));
    assert_eq!(alert.destination, Some(B.into()));
    assert_eq!(alert.related_flow_ids.len(), 25);
    assert!(
        alert
            .evidence
            .iter()
            .any(|e| e.name == "distinct_ports_unanswered_or_refused")
    );

    let mut fewer = Trace::default();
    refused(&mut fewer, B, 1..=15, 0);
    assert!(!rules(&fewer.alerts()).contains(&"FS-SCAN-SYN"));

    let mut normal = Trace::default();
    for port in 1..=25u16 {
        connection(&mut normal, B, 50_000 + port, port, u64::from(port) * 20);
    }
    assert!(!rules(&normal.alerts()).contains(&"FS-SCAN-SYN"));
}

#[test]
fn port_sweeps_and_horizontal_scans() {
    let mut sweep = Trace::default();
    for port in 1..=60u16 {
        sweep.at(u64::from(port) * 10, udp(A, B, 50_000, port, b"x"));
    }
    let alert = find(&sweep.alerts(), "FS-SCAN-PORTS").clone();
    assert!(
        alert
            .evidence
            .iter()
            .any(|e| e.name == "distinct_destination_ports" && e.value == "60")
    );

    let mut slow = Trace::default();
    for port in 1..=60u16 {
        // One port every 10 s: never more than 7 in a 60 s window.
        slow.at(u64::from(port) * 10_000, udp(A, B, 50_000, port, b"x"));
    }
    assert!(!rules(&slow.alerts()).contains(&"FS-SCAN-PORTS"));

    let mut horizontal = Trace::default();
    for host in 1..=25u8 {
        horizontal
            .at(
                u64::from(host) * 10,
                tcp(A, [198, 51, 100, host], 40_000, 22, SYN, 0),
            )
            .at(
                u64::from(host) * 10 + 1,
                tcp([198, 51, 100, host], A, 22, 40_000, RST_ACK, 0),
            );
    }
    let alerts = horizontal.alerts();
    let alert = find(&alerts, "FS-SCAN-HOSTS");
    assert_eq!(alert.destination_port, Some(22));

    let mut few = Trace::default();
    for host in 1..=10u8 {
        few.at(
            u64::from(host) * 10,
            tcp(A, [198, 51, 100, host], 40_000, 22, SYN, 0),
        );
    }
    assert!(!rules(&few.alerts()).contains(&"FS-SCAN-HOSTS"));
}

#[test]
fn many_failed_connections() {
    let mut failing = Trace::default();
    for i in 0..35u16 {
        let host = [198, 51, 100, (i % 200) as u8 + 1];
        failing.at(
            u64::from(i) * 100,
            tcp(A, host, 41_000 + i, 1000 + i, SYN, 0),
        );
    }
    let alerts = failing.alerts();
    let alert = find(&alerts, "FS-TCP-FAIL");
    assert_eq!(alert.source, Some(A.into()));

    let mut working = Trace::default();
    for i in 0..35u16 {
        connection(
            &mut working,
            [198, 51, 100, (i % 200) as u8 + 1],
            41_000 + i,
            1000 + i,
            u64::from(i) * 100,
        );
    }
    assert!(!rules(&working.alerts()).contains(&"FS-TCP-FAIL"));
}

#[test]
fn dns_volume() {
    let mut burst = Trace::default();
    for i in 0..250u16 {
        burst.at(
            u64::from(i) * 100,
            udp(A, C, 50_000, 53, &dns_query(i, "www.example.com", 1)),
        );
    }
    let alerts = burst.alerts();
    assert!(rules(&alerts).contains(&"FS-DNS-VOLUME"));
    assert!(
        !find(&alerts, "FS-DNS-VOLUME")
            .related_packet_indexes
            .is_empty()
    );

    let mut spread = Trace::default();
    for i in 0..250u16 {
        // One query every 3 s: about 20 per minute.
        spread.at(
            u64::from(i) * 3000,
            udp(A, C, 50_000, 53, &dns_query(i, "www.example.com", 1)),
        );
    }
    assert!(!rules(&spread.alerts()).contains(&"FS-DNS-VOLUME"));
}

#[test]
fn dns_tunneling() {
    let mut tunnel = Trace::default();
    for i in 0..15u16 {
        let label = format!(
            "{:064x}",
            u128::from(i).wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834)
        );
        let name = format!("{}.{}.exfil.example", &label[..40], &label[40..]);
        tunnel.at(
            u64::from(i) * 500,
            udp(A, C, 50_000, 53, &dns_query(i, &name, 16)),
        );
    }
    let alerts = tunnel.alerts();
    let alert = find(&alerts, "FS-DNS-TUNNEL");
    assert!(
        alert
            .evidence
            .iter()
            .any(|e| e.name == "parent_domain" && e.value == "exfil.example")
    );
    // Every query of the pattern is cited, from the first one on.
    assert_eq!(alert.related_packet_indexes, (1..=15).collect::<Vec<u64>>());
    let reached = |alert: &Alert| {
        alert
            .evidence
            .iter()
            .find(|e| e.name == "threshold_reached")
            .map(|e| e.value.clone())
    };
    assert_eq!(reached(alert).as_deref(), Some("min_suspicious_queries"));
    assert_eq!(alert.confidence, Confidence::Medium);

    // Many distinct short subdomains with a few TXT lookups: the spread
    // threshold alone.
    let mut spread = Trace::default();
    for i in 0..31u16 {
        let qtype = if i % 5 == 0 { 16 } else { 1 };
        spread.at(
            u64::from(i) * 500,
            udp(
                A,
                C,
                50_000,
                53,
                &dns_query(i, &format!("h{i}.spread.example"), qtype),
            ),
        );
    }
    let alerts = spread.alerts();
    let alert = find(&alerts, "FS-DNS-TUNNEL");
    assert_eq!(reached(alert).as_deref(), Some("min_distinct_subdomains"));

    let mut browsing = Trace::default();
    for i in 0..15u16 {
        let name = ["www.example.com", "mail.example.com", "cdn.example.org"][usize::from(i % 3)];
        browsing.at(
            u64::from(i) * 500,
            udp(A, C, 50_000, 53, &dns_query(i, name, 1)),
        );
    }
    assert!(!rules(&browsing.alerts()).contains(&"FS-DNS-TUNNEL"));
}

#[test]
fn beaconing() {
    let mut beacon = Trace::default();
    for i in 0..8u64 {
        // Every 60 s, with up to 0.3 s of jitter.
        connection(
            &mut beacon,
            C,
            45_000 + i as u16,
            443,
            i * 60_000 + (i % 3) * 100,
        );
    }
    let alerts = beacon.alerts();
    let alert = find(&alerts, "FS-BEACON");
    assert_eq!(alert.destination_port, Some(443));
    assert_eq!(alert.related_flow_ids.len(), 8);

    let mut irregular = Trace::default();
    for (i, at) in [
        0u64, 5_000, 70_000, 75_000, 200_000, 500_000, 510_000, 900_000,
    ]
    .iter()
    .enumerate()
    {
        connection(&mut irregular, C, 45_000 + i as u16, 443, *at);
    }
    assert!(!rules(&irregular.alerts()).contains(&"FS-BEACON"));
}

#[test]
fn rare_destination_ports() {
    let mut capture = Trace::default();
    for i in 0..60u16 {
        connection(
            &mut capture,
            B,
            30_000 + i,
            if i % 2 == 0 { 443 } else { 80 },
            u64::from(i) * 10,
        );
    }
    connection(&mut capture, B, 39_999, 4444, 1000);
    let alerts = capture.alerts();
    let alert = find(&alerts, "FS-RARE-PORT");
    assert_eq!(alert.destination_port, Some(4444));
    assert_eq!(
        alerts
            .iter()
            .filter(|a| a.rule_id == "FS-RARE-PORT")
            .count(),
        1
    );

    let mut small = Trace::default();
    for i in 0..10u16 {
        connection(&mut small, B, 30_000 + i, 443, u64::from(i) * 10);
    }
    connection(&mut small, B, 39_999, 4444, 1000);
    assert!(!rules(&small.alerts()).contains(&"FS-RARE-PORT"));
}

#[test]
fn large_outbound_transfers_from_internal_hosts() {
    let internal = [10, 0, 0, 5];
    let external = [203, 0, 113, 9];
    let upload = |from: [u8; 4], to: [u8; 4]| {
        let mut t = Trace::default();
        t.at(0, tcp(from, to, 40_000, 443, SYN, 0))
            .at(1, tcp(to, from, 443, 40_000, SYN_ACK, 0));
        for i in 0..1000u64 {
            t.at(2 + i, tcp(from, to, 40_000, 443, PSH_ACK, 1400));
        }
        t.at(2000, tcp(to, from, 443, 40_000, ACK, 0));
        t
    };
    let alerts = upload(internal, external).alerts();
    let alert = find(&alerts, "FS-OUTBOUND-RATIO");
    assert_eq!(alert.source, Some(internal.into()));
    // External to external, and internal to internal, are not flagged.
    assert!(!rules(&upload(external, [198, 51, 100, 7]).alerts()).contains(&"FS-OUTBOUND-RATIO"));
    assert!(!rules(&upload(internal, [10, 0, 0, 9]).alerts()).contains(&"FS-OUTBOUND-RATIO"));
}

#[test]
fn cleartext_login_protocols() {
    let mut telnet = Trace::default();
    connection(&mut telnet, B, 40_000, 23, 0);
    let alerts = telnet.alerts();
    let alert = find(&alerts, "FS-CLEARTEXT");
    assert!(alert.explanation.contains("Telnet"));

    let mut unanswered = Trace::default();
    unanswered.at(0, tcp(A, B, 40_000, 23, SYN, 0));
    assert!(!rules(&unanswered.alerts()).contains(&"FS-CLEARTEXT"));
}

#[test]
fn arp_conflicts_and_floods() {
    let gateway = [192, 0, 2, 1];
    let mut conflict = Trace::default();
    conflict
        .at(0, arp([2, 0, 0, 0, 0, 0x11], 2, gateway, A))
        .at(1000, arp([2, 0, 0, 0, 0, 0x66], 2, gateway, A));
    let alerts = conflict.alerts();
    let alert = find(&alerts, "FS-ARP-CONFLICT");
    // Both claims are cited, and the alert starts at the first.
    assert_eq!(alert.related_packet_indexes, [1, 2]);
    assert!(alert.first_seen < alert.last_seen);
    assert!(alert.evidence.iter().any(|e| e.name == "mac_addresses"
        && e.value == "02:00:00:00:00:11, 02:00:00:00:00:66"));

    // One address claimed by ever new MAC addresses: the alert lists a
    // bounded number of them.
    let mut many = Trace::default();
    for i in 0..200u64 {
        let mac = [2, 0, 0, 0, (i >> 8) as u8, i as u8];
        many.at(i * 10, arp(mac, 2, gateway, A));
    }
    let alerts = many.alerts();
    let alert = find(&alerts, "FS-ARP-CONFLICT");
    let listed = &alert
        .evidence
        .iter()
        .find(|e| e.name == "mac_addresses")
        .unwrap()
        .value;
    assert!(listed.ends_with("and at least 42 more"), "{listed}");

    let mut stable = Trace::default();
    for i in 0..10u64 {
        stable.at(i * 1000, arp([2, 0, 0, 0, 0, 0x11], 2, gateway, A));
    }
    assert!(stable.alerts().is_empty());

    let mut flood = Trace::default();
    for i in 0..25u64 {
        flood.at(
            i * 100,
            arp([2, 0, 0, 0, 0, 0x22], 2, [192, 0, 2, 50], [192, 0, 2, 50]),
        );
    }
    assert!(rules(&flood.alerts()).contains(&"FS-ARP-GRATUITOUS"));
    // ARP probes from 0.0.0.0 claim nothing.
    let mut probes = Trace::default();
    for i in 0..25u64 {
        probes.at(
            i * 100,
            arp([2, 0, 0, 0, 0, i as u8], 1, [0, 0, 0, 0], [192, 0, 2, 50]),
        );
    }
    assert!(probes.alerts().is_empty());
}

#[test]
fn every_alert_is_explained_and_linked_to_flows() {
    let mut trace = Trace::default();
    refused(&mut trace, B, 1..=25, 0);
    connection(&mut trace, B, 40_000, 23, 5_000);
    let (report, flows) = trace.run_with(DetectionConfig::default());
    assert!(report.summary.alerts_total >= 2);
    for (i, alert) in report.alerts.iter().enumerate() {
        assert_eq!(alert.alert_id, i as u64 + 1);
        assert_eq!(alert.nature, NATURE);
        assert!(!alert.explanation.is_empty() && !alert.evidence.is_empty());
        assert!(!alert.uncertainty.is_empty() && !alert.likely_false_positives.is_empty());
        assert!(!alert.mitre_attack.is_empty());
        assert!(alert.first_seen.is_some() && alert.last_seen >= alert.first_seen);
        let lower = alert.explanation.to_ascii_lowercase();
        assert!(!lower.contains("malware detected") && !lower.contains("compromised"));
        for flow_id in &alert.related_flow_ids {
            let flow = flows.iter().find(|f| f.flow_id == *flow_id).unwrap();
            assert!(flow.alert_ids.contains(&alert.alert_id));
        }
    }
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"severity\":\"medium\""));
    assert_eq!(RULES.len(), 12);
}

#[test]
fn rules_can_be_disabled_and_tuned() {
    let mut scan = Trace::default();
    refused(&mut scan, B, 1..=25, 0);
    let off = DetectionConfig::from_toml("[syn_scan]\nenabled = false\n").unwrap();
    assert!(!rules(&scan.run_with(off).0.alerts).contains(&"FS-SCAN-SYN"));
    let strict = DetectionConfig::from_toml("[syn_scan]\nmin_ports = 30\n").unwrap();
    assert!(!rules(&scan.run_with(strict).0.alerts).contains(&"FS-SCAN-SYN"));
    let loose = DetectionConfig::from_toml("[syn_scan]\nmin_ports = 5\n").unwrap();
    let alerts = scan.run_with(loose).0.alerts;
    assert_eq!(
        find(&alerts, "FS-SCAN-SYN").confidence,
        detection_engine::Confidence::High
    );
}

#[test]
fn results_are_deterministic() {
    let mut trace = Trace::default();
    refused(&mut trace, B, 1..=25, 0);
    for i in 0..250u16 {
        trace.at(
            10_000 + u64::from(i) * 100,
            udp(A, C, 50_000, 53, &dns_query(i, "www.example.com", 1)),
        );
    }
    let first = serde_json::to_string(&trace.run_with(DetectionConfig::default()).0).unwrap();
    let second = serde_json::to_string(&trace.run_with(DetectionConfig::default()).0).unwrap();
    assert_eq!(first, second);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Arbitrary frames at arbitrary times never panic, and the report
    /// always serializes.
    #[test]
    fn arbitrary_traffic_never_panics(
        frames in proptest::collection::vec((0u64..600_000, proptest::collection::vec(any::<u8>(), 0..200)), 0..60),
    ) {
        let mut trace = Trace::default();
        for (at, mut bytes) in frames {
            // Mostly well-formed headers so the rules are reached.
            let mut frame = udp(A, C, 50_000, 53, &dns_query(1, "a.b.example", 16));
            frame.truncate(14);
            frame.append(&mut bytes);
            trace.at(at, frame);
        }
        let (report, _) = trace.run_with(DetectionConfig::default());
        prop_assert!(serde_json::to_string(&report).is_ok());
    }
}

#[test]
fn each_rule_raises_a_bounded_number_of_alerts() {
    // 1,100 addresses, each claimed by two MAC addresses.
    let mut trace = Trace::default();
    for i in 0..1_100u64 {
        let ip = [10, 1, (i >> 8) as u8, i as u8];
        trace
            .at(i * 10, arp([2, 0, 0, 0, 0, 0x11], 2, ip, A))
            .at(i * 10 + 1, arp([2, 0, 0, 0, 0, 0x66], 2, ip, A));
    }
    let (report, _) = trace.run_with(DetectionConfig::default());
    let conflicts = report
        .alerts
        .iter()
        .filter(|a| a.rule_id == "FS-ARP-CONFLICT")
        .count();
    assert_eq!(conflicts, detection_engine::MAX_ALERTS_PER_RULE);
    assert!(
        report
            .summary
            .rules_at_alert_limit
            .contains("FS-ARP-CONFLICT")
    );
    // The earliest are kept, in time order.
    let first = report.alerts.first().unwrap();
    assert_eq!(first.source, Some("10.1.0.0".parse().unwrap()));
    assert!(
        report
            .alerts
            .windows(2)
            .all(|w| w[0].first_seen <= w[1].first_seen)
    );
}

fn dns_query_labels(id: u16, labels: &[&[u8]], qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    for v in [id, 0x0100, 1, 0, 0, 0] {
        out.extend(v.to_be_bytes());
    }
    for label in labels {
        out.push(label.len() as u8);
        out.extend(*label);
    }
    out.push(0);
    out.extend(qtype.to_be_bytes());
    out.extend([0, 1]);
    out
}

#[test]
fn tunnels_with_binary_labels_keep_their_parent_domain() {
    // iodine-style queries: two 60-byte labels of 8-bit bytes, whose escaped
    // form is longer than a shown name, under t.evil.example.
    let mut tunnel = Trace::default();
    for i in 0..40u16 {
        let label: Vec<u8> = (0..60u8).map(|b| 0x80 | (b ^ i as u8)).collect();
        let query = dns_query_labels(i, &[&label, &label, b"t", b"evil", b"example"], 16);
        tunnel.at(u64::from(i) * 500, udp(A, C, 50_000, 53, &query));
    }
    let (report, flows) = tunnel.run_with(DetectionConfig::default());
    let alert = find(&report.alerts, "FS-DNS-TUNNEL");
    assert!(
        alert
            .evidence
            .iter()
            .any(|e| e.name == "parent_domain" && e.value == "evil.example"),
        "{:?}",
        alert.evidence
    );
    // The DNS flow carrying the queries is linked to the alert, so flow
    // filters on alerts find it.
    assert!(!alert.related_flow_ids.is_empty());
    let flow = flows
        .iter()
        .find(|f| f.flow_id == alert.related_flow_ids[0])
        .unwrap();
    assert!(flow.alert_ids.contains(&alert.alert_id));
}

#[test]
fn browsing_many_sites_is_not_a_horizontal_scan() {
    let mut browsing = Trace::default();
    for host in 1..=25u8 {
        connection(
            &mut browsing,
            [198, 51, 100, host],
            40_000 + u16::from(host),
            443,
            u64::from(host) * 1000,
        );
    }
    assert!(!rules(&browsing.alerts()).contains(&"FS-SCAN-HOSTS"));
}

#[test]
fn counts_are_not_capped_at_the_cited_flows() {
    let mut telnet = Trace::default();
    for i in 0..60u16 {
        connection(&mut telnet, B, 41_000 + i, 23, u64::from(i) * 100);
    }
    let alerts = telnet.alerts();
    let alert = find(&alerts, "FS-CLEARTEXT");
    assert_eq!(alert.related_flow_ids.len(), 50);
    assert!(
        alert
            .evidence
            .iter()
            .any(|e| e.name == "connections" && e.value == "60"),
        "{:?}",
        alert.evidence
    );
}

#[test]
fn a_udp_reply_seen_first_is_not_a_rare_service() {
    // 60 ordinary flows, then a resolver reply whose request was not
    // captured: its "initiator" is the server on port 53.
    let mut trace = Trace::default();
    for i in 0..60u16 {
        connection(&mut trace, B, 42_000 + i, 443, u64::from(i) * 100);
    }
    trace
        .at(10_000, udp([10, 0, 0, 53], A, 53, 33_333, b"reply"))
        .at(10_001, udp(A, [10, 0, 0, 53], 33_333, 53, b"query"));
    assert!(!rules(&trace.alerts()).contains(&"FS-RARE-PORT"));
}

#[test]
fn flow_rules_build_at_most_the_alert_limit() {
    // 1,100 answered Telnet servers, one connection each.
    let mut trace = Trace::default();
    for i in 0..1_100u32 {
        let dst = [10, 2, (i >> 8) as u8, i as u8];
        connection(
            &mut trace,
            dst,
            40_000 + (i % 20_000) as u16,
            23,
            u64::from(i) * 10,
        );
    }
    let (report, _) = trace.run_with(DetectionConfig::default());
    let cleartext: Vec<&Alert> = report
        .alerts
        .iter()
        .filter(|a| a.rule_id == "FS-CLEARTEXT")
        .collect();
    assert_eq!(cleartext.len(), detection_engine::MAX_ALERTS_PER_RULE);
    assert!(report.summary.rules_at_alert_limit.contains("FS-CLEARTEXT"));
    // The earliest are kept.
    assert_eq!(cleartext[0].destination, Some("10.2.0.0".parse().unwrap()));
}

#[test]
fn a_far_future_timestamp_does_not_hide_later_queries() {
    let mut trace = Trace::default();
    trace
        .at(
            0,
            udp(A, C, 50_000, 53, &dns_query(1, "www.example.com", 1)),
        )
        .at(
            10,
            udp(A, C, 50_001, 53, &dns_query(2, "www.example.com", 1)),
        )
        // Decades later, then ordinary traffic again.
        .at(
            2_000_000_000_000,
            udp(A, C, 50_002, 53, &dns_query(3, "www.example.com", 1)),
        );
    for i in 0..400u64 {
        trace.at(
            1_000 + i * 50,
            udp(A, C, 50_100, 53, &dns_query(4, "www.example.com", 1)),
        );
    }
    let (report, _) = trace.run_with(DetectionConfig::default());
    assert!(rules(&report.alerts).contains(&"FS-DNS-VOLUME"));
    // The outlier is counted, not silently lost (once per DNS window it
    // reached).
    assert!(
        (1..=3).contains(&report.summary.events_not_evaluated),
        "{}",
        report.summary.events_not_evaluated
    );
}
