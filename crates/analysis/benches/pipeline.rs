//! Throughput of the analysis pipeline on synthetic captures generated at
//! run time: `cargo bench -p analysis`. Each case runs five times and the
//! median is reported. Numbers depend on the machine; docs/performance.md
//! records the ones we measured and where.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write;
use std::time::{Duration, Instant};

use analysis::{AnalysisConfig, analyze_file, analyze_file_with_detection};
use capture::{CaptureLimits, MonotonicClock};
use detection_engine::{DetectionConfig, Detector};

const PACKETS: u32 = 200_000;
const RUNS: usize = 5;

/// A classic pcap of `PACKETS` Ethernet/IPv4/UDP packets with 32-byte
/// payloads. `flow_of(i)` picks packet i's source port (one flow per port).
fn capture(flow_of: impl Fn(u32) -> u16) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().suffix(".pcap").tempfile().unwrap();
    let mut out = Vec::with_capacity(24 + PACKETS as usize * 90);
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&65_535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for i in 0..PACKETS {
        let port = flow_of(i);
        let mut frame = Vec::with_capacity(74);
        frame.extend_from_slice(&[2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00]);
        // IPv4: 20 + 8 + 32 = 60 bytes, UDP, 192.0.2.10 -> 198.51.100.20.
        let ip = [
            0x45, 0, 0, 60, 0, 0, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 10, 198, 51, 100, 20,
        ];
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&port.to_be_bytes());
        frame.extend_from_slice(&5_000u16.to_be_bytes());
        frame.extend_from_slice(&40u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&[0x5a; 32]);
        let micros = i * 100;
        out.extend_from_slice(&(1_767_225_600 + micros / 1_000_000).to_le_bytes());
        out.extend_from_slice(&(micros % 1_000_000).to_le_bytes());
        let len = frame.len() as u32;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&frame);
    }
    file.write_all(&out).unwrap();
    file
}

fn median(mut runs: Vec<Duration>) -> Duration {
    runs.sort();
    runs[runs.len() / 2]
}

fn report(name: &str, file: &tempfile::NamedTempFile, run: impl Fn()) {
    let bytes = std::fs::metadata(file.path()).unwrap().len();
    let runs: Vec<Duration> = (0..RUNS)
        .map(|_| {
            let started = Instant::now();
            run();
            started.elapsed()
        })
        .collect();
    let time = median(runs).as_secs_f64();
    println!(
        "{name:<44} {PACKETS} packets  {:>7.3} s  {:>10.0} packets/s  {:>7.1} MB/s",
        time,
        f64::from(PACKETS) / time,
        bytes as f64 / time / 1e6
    );
}

fn main() {
    let config = AnalysisConfig {
        limits: CaptureLimits {
            max_file_size_bytes: 1 << 30,
            max_packets: u64::from(PACKETS),
            max_duration: Duration::from_secs(600),
        },
        ..AnalysisConfig::default()
    };
    let one_flow = capture(|_| 40_000);
    let many_flows = capture(|i| 1_024 + (i % 60_000) as u16);
    println!("analysis pipeline, median of {RUNS} runs (release build)");
    for (name, file) in [("one flow", &one_flow), ("60,000 flows", &many_flows)] {
        report(&format!("decode + flows, {name}"), file, || {
            analyze_file(file.path(), &config, &MonotonicClock::start()).unwrap();
        });
        report(&format!("decode + flows + detection, {name}"), file, || {
            let detector = Detector::new(DetectionConfig::default()).unwrap();
            analyze_file_with_detection(file.path(), &config, detector, &MonotonicClock::start())
                .unwrap();
        });
    }
}
