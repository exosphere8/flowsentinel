//! The two-pass pipeline against the committed fixtures.

use std::path::{Path, PathBuf};

use analysis::{
    AnalysisConfig, AnalyzedPacket, analyze_file, analyze_file_with_detection, replay_packets,
};
use capture::MonotonicClock;
use detection_engine::{DetectionConfig, Detector};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pcap")
        .join(name)
}

fn replay_all(
    path: &Path,
    config: &AnalysisConfig,
    batch: usize,
) -> (
    Vec<Vec<AnalyzedPacket>>,
    analysis::Replay,
    analysis::Analysis,
) {
    let analysis = analyze_file(path, config, &MonotonicClock::start()).unwrap();
    let mut batches = Vec::new();
    let replay = replay_packets(path, config, &analysis, batch, &mut |b| {
        batches.push(b);
        true
    })
    .unwrap();
    (batches, replay, analysis)
}

#[test]
fn passes_agree_and_packets_carry_flow_ids() {
    let config = AnalysisConfig::default();
    let (batches, replay, analysis) = replay_all(&fixture("flows-mixed.pcap"), &config, 4);
    assert!(
        analysis.report.packets.is_empty(),
        "per-record list is dropped"
    );
    assert_eq!(analysis.report.summary.packets_processed, 19);
    assert_eq!(analysis.replayable_packets, 19);
    assert_eq!(replay.packets, 19);
    assert_eq!(replay.fingerprint, analysis.fingerprint);
    assert!(!replay.stopped);
    assert!(batches.iter().all(|b| b.len() <= 4));
    assert_eq!(batches.iter().map(Vec::len).sum::<usize>(), 19);

    let packets: Vec<&AnalyzedPacket> = batches.iter().flatten().collect();
    let indexes: Vec<u64> = packets.iter().map(|p| p.record.index).collect();
    assert_eq!(indexes, (1..=19).collect::<Vec<_>>());
    // Every flow's first and last packet carry that flow's ID.
    for flow in &analysis.flows.flows {
        for index in [flow.first_packet_index, flow.last_packet_index] {
            let packet = packets[usize::try_from(index - 1).unwrap()];
            assert_eq!(packet.flow_id, Some(flow.flow_id), "packet {index}");
        }
    }
    // ARP has no flow.
    assert!(packets.iter().any(|p| p.flow_id.is_none()));
}

#[test]
fn replay_is_limited_and_fingerprint_covers_only_replayed_packets() {
    let config = AnalysisConfig {
        replay_packets: 5,
        ..AnalysisConfig::default()
    };
    let (batches, replay, analysis) = replay_all(&fixture("flows-mixed.pcap"), &config, 1000);
    assert_eq!(analysis.replayable_packets, 5);
    assert_eq!(
        analysis.flows.summary.flows_total, 6,
        "flows still cover the whole file"
    );
    assert_eq!(replay.packets, 5);
    assert_eq!(replay.fingerprint, analysis.fingerprint);
    assert_eq!(batches.len(), 1);

    let none = AnalysisConfig {
        replay_packets: 0,
        ..AnalysisConfig::default()
    };
    let (batches, replay, analysis) = replay_all(&fixture("flows-mixed.pcap"), &none, 10);
    assert!(batches.is_empty());
    assert_eq!(replay.packets, 0);
    assert_eq!(replay.fingerprint, analysis.fingerprint);
}

#[test]
fn a_changed_file_has_a_different_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("capture.pcap");
    let original = std::fs::read(fixture("flows-mixed.pcap")).unwrap();
    std::fs::write(&path, &original).unwrap();
    let config = AnalysisConfig::default();
    let analysis = analyze_file(&path, &config, &MonotonicClock::start()).unwrap();

    let mut changed = original.clone();
    *changed.last_mut().unwrap() ^= 0x01;
    std::fs::write(&path, &changed).unwrap();
    let replay = replay_packets(&path, &config, &analysis, 100, &mut |_| true).unwrap();
    assert_eq!(replay.packets, analysis.replayable_packets);
    assert_ne!(replay.fingerprint, analysis.fingerprint);
}

#[test]
fn callers_can_stop_early() {
    let config = AnalysisConfig::default();
    let path = fixture("flows-mixed.pcap");
    let analysis = analyze_file(&path, &config, &MonotonicClock::start()).unwrap();
    let mut seen = 0;
    let replay = replay_packets(&path, &config, &analysis, 3, &mut |b| {
        seen += b.len();
        false
    })
    .unwrap();
    assert!(replay.stopped);
    assert_eq!(seen, 3);
}

#[test]
fn invalid_captures_fail_in_the_first_pass() {
    let config = AnalysisConfig::default();
    for name in [
        "invalid-magic.pcap",
        "minimal.pcapng",
        "truncated-global-header.pcap",
    ] {
        assert!(
            analyze_file(&fixture(name), &config, &MonotonicClock::start()).is_err(),
            "{name}"
        );
    }
}

#[test]
fn detection_runs_in_the_first_pass_and_links_flows() {
    let path = fixture("detect-mixed.pcap");
    let config = AnalysisConfig::default();
    let plain = analyze_file(&path, &config, &MonotonicClock::start()).unwrap();
    assert!(plain.detection.is_none());
    let detector = Detector::new(DetectionConfig::default()).unwrap();
    let analysis =
        analyze_file_with_detection(&path, &config, detector, &MonotonicClock::start()).unwrap();
    let detection = analysis.detection.as_ref().unwrap();
    assert_eq!(detection.alerts.len(), 5);
    assert_eq!(detection.summary.flows_evaluated, 47);
    // Detection does not change what is replayed.
    assert_eq!(analysis.fingerprint, plain.fingerprint);
    for alert in &detection.alerts {
        for flow_id in &alert.related_flow_ids {
            let flow = analysis
                .flows
                .flows
                .iter()
                .find(|f| f.flow_id == *flow_id)
                .unwrap();
            assert!(flow.alert_ids.contains(&alert.alert_id));
        }
    }
    let unlinked = analysis
        .flows
        .flows
        .iter()
        .filter(|f| f.alert_ids.is_empty())
        .count();
    assert!(unlinked > 0 && unlinked < analysis.flows.flows.len());
}
