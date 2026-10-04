//! Feeds a sequence of arbitrary packets through the decoder and a small
//! flow table, so expiry, eviction and retention limits are all reached,
//! then checks the engine's accounting invariants and that the report
//! serializes to JSON (no NaN or infinite statistics).
//!
//! Input: repeated `[length: u16 big-endian][time step: u8][frame]`. Time
//! steps: 255 = no valid timestamp, 254 = the far future (u32::MAX
//! seconds), 253 = the far past (0), otherwise forward (even) or backward
//! (odd) by `step * 7` seconds, which crosses every idle timeout.
#![no_main]

use std::time::Duration;

use capture::{Timestamp, TimestampResolution};
use flow_engine::{FlowConfig, FlowEngine, FlowPacket};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut engine = FlowEngine::new(FlowConfig {
        max_active_flows: 4,
        max_retained_flows: 8,
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
                let delta = u32::from(step) * 7;
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
        engine.process(&FlowPacket {
            index,
            timestamp,
            wire_length,
            decoded: &decoded,
        });
    }
    let report = engine.finish();
    let s = &report.summary;
    assert_eq!(s.packets_seen, index);
    assert_eq!(s.packets_in_flows + s.packets_without_ip, s.packets_seen);
    assert_eq!(s.flows_retained + s.flows_not_retained, s.flows_total);
    assert_eq!(s.end_reasons.values().sum::<u64>(), s.flows_total);
    assert!(s.peak_active_flows <= 4);
    assert!(report.flows.len() <= 8);
    assert!(report.flows.windows(2).all(|w| w[0].flow_id < w[1].flow_id));
    for flow in &report.flows {
        assert_eq!(
            flow.initiator_to_responder.packets + flow.responder_to_initiator.packets,
            flow.packets_total
        );
        assert!(flow.duration_seconds >= 0.0);
    }
    assert!(serde_json::to_string(&report).is_ok());
});
