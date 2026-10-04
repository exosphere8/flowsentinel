//! Feeds a sequence of arbitrary packets through the decoder, a small flow
//! table and the detection rules with low thresholds, so every rule can
//! fire, then checks the report's invariants and that it serializes.
//!
//! Input: repeated `[length: u16 big-endian][time step: u8][frame]`. Time
//! steps: 255 = no valid timestamp, 254 = the far future (u32::MAX
//! seconds), 253 = the far past (0), otherwise forward (even) or backward
//! (odd) by `step` seconds, which crosses every rule window.
#![no_main]

use std::time::Duration;

use capture::{Timestamp, TimestampResolution};
use detection_engine::{DetectionConfig, Detector, MAX_ALERTS_PER_FLOW, MAX_RELATED, NATURE};
use flow_engine::{FlowConfig, FlowEngine, FlowPacket};
use libfuzzer_sys::fuzz_target;

const CONFIG: &str = "
[syn_scan]
min_ports = 2
window_seconds = 30
[port_sweep]
min_ports = 2
[horizontal_scan]
min_hosts = 2
[dns_volume]
min_queries = 2
[dns_tunneling]
min_long_queries = 2
min_unique_subdomains = 2
min_label_length = 4
[beaconing]
min_connections = 3
min_interval_seconds = 1.0
max_jitter_ratio = 1.0
[rare_destination_port]
min_flows = 2
[outbound_ratio]
min_bytes_out = 1
min_ratio = 1.0
[tcp_failures]
min_failures = 2
[arp]
min_gratuitous = 2
";

fuzz_target!(|data: &[u8]| {
    let Ok(config) = DetectionConfig::from_toml(CONFIG) else {
        panic!("fuzz configuration must be valid");
    };
    let Ok(mut detector) = Detector::new(config) else {
        panic!("fuzz configuration must be valid");
    };
    let mut engine = FlowEngine::new(FlowConfig {
        max_active_flows: 8,
        max_retained_flows: 64,
        tcp_idle_timeout: Duration::from_secs(300),
        idle_timeout: Duration::from_secs(60),
        tcp_finished_timeout: Duration::from_secs(10),
    });
    let mut rest = data;
    let mut seconds: u32 = 1_767_225_600;
    let mut index = 0u64;
    while let [hi, lo, step, tail @ ..] = rest {
        let length = usize::from(u16::from_be_bytes([*hi, *lo])).min(tail.len());
        let (frame, next) = tail.split_at(length);
        rest = next;
        index += 1;
        let timestamp = match *step {
            255 => None,
            254 => Timestamp::from_record(u32::MAX, 0, TimestampResolution::Microsecond),
            253 => Timestamp::from_record(0, 0, TimestampResolution::Microsecond),
            step => {
                let delta = u32::from(step);
                seconds = if step % 2 == 1 {
                    seconds.saturating_sub(delta)
                } else {
                    seconds.saturating_add(delta)
                };
                Timestamp::from_record(seconds, 0, TimestampResolution::Microsecond)
            }
        };
        let wire_length = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        let decoded = decoder::decode_packet(decoder::LINKTYPE_ETHERNET, frame, wire_length);
        let flow = engine.process(&FlowPacket {
            index,
            timestamp,
            wire_length,
            decoded: &decoded,
        });
        detector.observe_packet(index, timestamp, &decoded, flow);
    }
    let mut flows = engine.finish().flows;
    let report = detector.finish(&mut flows);
    assert_eq!(report.summary.alerts_total, report.alerts.len() as u64);
    for (i, alert) in report.alerts.iter().enumerate() {
        assert_eq!(alert.alert_id, i as u64 + 1);
        assert_eq!(alert.nature, NATURE);
        assert!(!alert.evidence.is_empty());
        assert!(!alert.explanation.is_empty());
        assert!(alert.related_flow_ids.len() <= MAX_RELATED);
        assert!(alert.related_packet_indexes.len() <= MAX_RELATED);
        assert!(alert.related_packet_indexes.iter().all(|&p| p >= 1 && p <= index));
        // Cited flows may be beyond the retention limit, so only their
        // range is checked here.
        assert!(alert.related_flow_ids.iter().all(|&id| id >= 1));
        if let (Some(first), Some(last)) = (alert.first_seen, alert.last_seen) {
            assert!(first <= last);
        }
    }
    for flow in &flows {
        assert!(flow.alert_ids.len() <= MAX_ALERTS_PER_FLOW);
        assert!(
            flow.alert_ids
                .iter()
                .all(|&id| id >= 1 && id <= report.alerts.len() as u64)
        );
    }
    assert!(serde_json::to_string(&report).is_ok());
});
