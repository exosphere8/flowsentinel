//! The analysis pipeline shared by the API's import endpoint and other front
//! ends: read a capture, decode every packet and reconstruct flows, keeping
//! only metadata and never more than a bounded amount of it in memory.
//!
//! A capture is read in two passes:
//!
//! 1. [`analyze_file`] decodes every packet and runs the flow engine. It
//!    keeps the capture report (without per-packet records), the decode
//!    summary and the finished flows, plus a fingerprint of the packets that
//!    will be replayed.
//! 2. [`replay_packets`] reads the first packets again, decodes them, replays
//!    the deterministic flow engine to recover each packet's flow ID, and
//!    hands them to the caller in batches. At most one batch is in memory.
//!
//! [`Replay::fingerprint`] must equal [`Analysis::fingerprint`]; otherwise
//! the file changed between the passes and the caller must discard the
//! result.

use std::hash::{DefaultHasher, Hasher};
use std::path::Path;
use std::time::Duration;

use capture::{
    CaptureError, CaptureLimits, CaptureReport, Clock, MonotonicClock, PacketRecordMetadata,
    PacketSink, PcapGlobalHeader, inspect_file_with_sink,
};
use decoder::{DecodeSummary, DecodedPacket, decode_packet};
use flow_engine::{FlowConfig, FlowEngine, FlowPacket, FlowReport};

/// What to run and how much to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisConfig {
    pub limits: CaptureLimits,
    pub flows: FlowConfig,
    /// Packets that will be replayed (and typically stored) after the first
    /// pass. The fingerprint covers exactly these packets.
    pub replay_packets: u64,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            limits: CaptureLimits::default(),
            flows: FlowConfig::default(),
            replay_packets: 100_000,
        }
    }
}

/// Result of the first pass.
#[derive(Debug, Clone, PartialEq)]
pub struct Analysis {
    /// Capture summary, completion state and warnings. Per-packet records
    /// are not kept (`report.packets` is empty).
    pub report: CaptureReport,
    pub decode_summary: DecodeSummary,
    pub flows: FlowReport,
    /// How many packets [`replay_packets`] will yield: the smaller of
    /// [`AnalysisConfig::replay_packets`] and the packets processed.
    pub replayable_packets: u64,
    /// Fingerprint of the replayable packets.
    pub fingerprint: u64,
}

/// One decoded packet and the flow it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzedPacket {
    pub record: PacketRecordMetadata,
    pub decoded: DecodedPacket,
    pub flow_id: Option<u64>,
}

/// Result of the second pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replay {
    /// Packets handed to the caller.
    pub packets: u64,
    /// Fingerprint of those packets.
    pub fingerprint: u64,
    /// The caller asked to stop early.
    pub stopped: bool,
}

/// Running fingerprint of the global header and each record's metadata and
/// bytes. Not cryptographic: it detects a file that changed between the two
/// passes of one process, whose hashers are keyed identically.
#[derive(Debug, Default)]
struct Fingerprint(DefaultHasher);

impl Fingerprint {
    fn header(&mut self, header: &PcapGlobalHeader) {
        self.0.write_u16(header.link_type.0);
        self.0.write_u32(header.snap_length);
        self.0.write_i32(header.timezone_offset_seconds);
        self.0
            .write(header.timestamp_resolution.as_str().as_bytes());
        self.0.write(header.endianness.as_str().as_bytes());
    }

    fn record(&mut self, record: &PacketRecordMetadata, data: &[u8]) {
        self.0.write_u64(record.index);
        self.0.write_u64(record.file_offset);
        self.0
            .write_u128(record.timestamp.map_or(u128::MAX, |ts| ts.as_unix_nanos()));
        self.0.write_u32(record.captured_length);
        self.0.write_u32(record.original_length);
        self.0.write(data);
    }

    fn value(&self) -> u64 {
        self.0.finish()
    }
}

struct FirstPass {
    link_type: u16,
    engine: FlowEngine,
    summary: DecodeSummary,
    replay_packets: u64,
    fingerprint: Fingerprint,
}

impl PacketSink for FirstPass {
    fn start(&mut self, header: &PcapGlobalHeader) {
        self.link_type = header.link_type.0;
        self.fingerprint.header(header);
    }

    fn packet(&mut self, record: &PacketRecordMetadata, data: &[u8]) {
        if record.index <= self.replay_packets {
            self.fingerprint.record(record, data);
        }
        let decoded = decode_packet(self.link_type, data, record.original_length);
        self.summary.add(record.index, &decoded);
        self.engine.process(&FlowPacket {
            index: record.index,
            timestamp: record.timestamp,
            wire_length: record.original_length,
            decoded: &decoded,
        });
    }
}

/// First pass: validates, reads, decodes and flows `path`. Memory is bounded
/// by the flow engine's limits; no per-packet data is kept.
pub fn analyze_file(
    path: &Path,
    config: &AnalysisConfig,
    clock: &dyn Clock,
) -> Result<Analysis, CaptureError> {
    let mut pass = FirstPass {
        link_type: 0,
        engine: FlowEngine::new(config.flows),
        summary: DecodeSummary::default(),
        replay_packets: config.replay_packets,
        fingerprint: Fingerprint::default(),
    };
    let mut report = inspect_file_with_sink(path, &config.limits, clock, Some(&mut pass))?;
    // The per-record list grows with the capture; nothing downstream needs it.
    report.packets = Vec::new();
    let replayable_packets = config.replay_packets.min(report.summary.packets_processed);
    Ok(Analysis {
        report,
        decode_summary: pass.summary,
        flows: pass.engine.finish(),
        replayable_packets,
        fingerprint: pass.fingerprint.value(),
    })
}

/// Second pass: decodes the first `analysis.replayable_packets` packets of
/// `path` again and hands them to `on_batch` in order, at most `batch_size`
/// at a time. `on_batch` returns `false` to stop early.
///
/// The pass is bounded by the packet count. Its time limit is the larger of
/// the configured limit and one hour, because its speed depends on the
/// consumer (for example a database).
pub fn replay_packets(
    path: &Path,
    config: &AnalysisConfig,
    analysis: &Analysis,
    batch_size: usize,
    on_batch: &mut dyn FnMut(Vec<AnalyzedPacket>) -> bool,
) -> Result<Replay, CaptureError> {
    struct SecondPass<'a> {
        link_type: u16,
        engine: FlowEngine,
        batch: Vec<AnalyzedPacket>,
        batch_size: usize,
        on_batch: &'a mut dyn FnMut(Vec<AnalyzedPacket>) -> bool,
        fingerprint: Fingerprint,
        packets: u64,
        stopped: bool,
    }

    impl PacketSink for SecondPass<'_> {
        fn start(&mut self, header: &PcapGlobalHeader) {
            self.link_type = header.link_type.0;
            self.fingerprint.header(header);
        }

        fn packet(&mut self, record: &PacketRecordMetadata, data: &[u8]) {
            if self.stopped {
                return;
            }
            self.fingerprint.record(record, data);
            self.packets = self.packets.saturating_add(1);
            let decoded = decode_packet(self.link_type, data, record.original_length);
            let flow_id = self.engine.process(&FlowPacket {
                index: record.index,
                timestamp: record.timestamp,
                wire_length: record.original_length,
                decoded: &decoded,
            });
            self.batch.push(AnalyzedPacket {
                record: *record,
                decoded,
                flow_id,
            });
            if self.batch.len() >= self.batch_size {
                let full = std::mem::replace(&mut self.batch, Vec::with_capacity(self.batch_size));
                self.stopped = !(self.on_batch)(full);
            }
        }
    }

    let batch_size = batch_size.clamp(1, 10_000);
    let mut pass = SecondPass {
        link_type: 0,
        engine: FlowEngine::new(config.flows),
        batch: Vec::with_capacity(batch_size),
        batch_size,
        on_batch,
        fingerprint: Fingerprint::default(),
        packets: 0,
        stopped: false,
    };
    if analysis.replayable_packets > 0 {
        let limits = CaptureLimits {
            max_packets: analysis.replayable_packets,
            max_duration: config.limits.max_duration.max(Duration::from_secs(
                *CaptureLimits::MAX_DURATION_SECONDS_RANGE.end(),
            )),
            ..config.limits
        };
        inspect_file_with_sink(path, &limits, &MonotonicClock::start(), Some(&mut pass))?;
    } else {
        // Nothing to replay; the header alone must still match.
        let limits = CaptureLimits {
            max_packets: 1,
            ..config.limits
        };
        let mut header_only = HeaderOnly(&mut pass.fingerprint);
        inspect_file_with_sink(
            path,
            &limits,
            &MonotonicClock::start(),
            Some(&mut header_only),
        )?;
    }
    if !pass.stopped && !pass.batch.is_empty() {
        let last = std::mem::take(&mut pass.batch);
        pass.stopped = !(pass.on_batch)(last);
    }
    Ok(Replay {
        packets: pass.packets,
        fingerprint: pass.fingerprint.value(),
        stopped: pass.stopped,
    })
}

/// Fingerprints only the global header.
struct HeaderOnly<'a>(&'a mut Fingerprint);

impl PacketSink for HeaderOnly<'_> {
    fn start(&mut self, header: &PcapGlobalHeader) {
        self.0.header(header);
    }

    fn packet(&mut self, _record: &PacketRecordMetadata, _data: &[u8]) {}
}
