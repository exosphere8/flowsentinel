//! `inspect --decode`: decodes each packet transiently and renders protocol
//! metadata as tables, trees or JSON.
//!
//! The capture is read twice so memory does not grow with packet count.
//! The first pass computes the capture and decode summaries (printed
//! first). The second pass decodes the same packets again and writes each
//! one as soon as it is decoded; nothing per-packet is retained.
//!
//! Each pass fingerprints what it read (the global header and every
//! record's metadata and bytes). If the file changes between the passes the
//! fingerprints differ and the output is reported as inconsistent.

use std::hash::{DefaultHasher, Hasher};
use std::io::{self, Write};

use capture::{
    CaptureLimits, CaptureReport, MonotonicClock, PacketRecordMetadata, PacketSink,
    PcapGlobalHeader, inspect_file_with_sink,
};
use decoder::{DecodeSummary, DecodedPacket, decode_packet};
use serde::Serialize;

use crate::InspectArgs;

/// Running fingerprint of everything one pass read. Not cryptographic: it
/// detects a file that changed between the two passes, not tampering
/// designed to collide. Both passes run in one process, so their hashers are
/// keyed identically.
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

/// First pass: aggregates decode results without keeping them.
#[derive(Debug, Default)]
pub struct SummaryCollector {
    link_type: u16,
    pub summary: DecodeSummary,
    /// Longest source/destination text, for sizing the table columns.
    pub endpoint_width: usize,
    fingerprint: Fingerprint,
}

impl PacketSink for SummaryCollector {
    fn start(&mut self, header: &PcapGlobalHeader) {
        self.link_type = header.link_type.0;
        self.fingerprint.header(header);
    }

    fn packet(&mut self, record: &PacketRecordMetadata, data: &[u8]) {
        self.fingerprint.record(record, data);
        let packet = decode_packet(self.link_type, data, record.original_length);
        if let Some((s, d)) = packet.endpoints() {
            self.endpoint_width = self.endpoint_width.max(s.len()).max(d.len());
        }
        self.summary.add(record.index, &packet);
    }
}

/// How the second pass renders each packet.
#[derive(Debug, Clone, Copy)]
pub enum Style {
    Table { verbose: bool, width: usize },
    Json,
}

/// Whether the second pass saw the same packets as the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOutcome {
    Consistent,
    /// The file changed between the passes (different packets, count or
    /// header), so the packet list does not match the summaries.
    Changed,
}

/// Message for [`StreamOutcome::Changed`].
pub const CHANGED_MESSAGE: &str =
    "the capture changed while it was being read; the packet list does not match the summary";

/// Second pass: writes each decoded packet immediately.
struct Streamer<'w, W: Write> {
    link_type: u16,
    out: &'w mut W,
    style: Style,
    written: u64,
    error: Option<io::Error>,
    fingerprint: Fingerprint,
}

#[derive(Serialize)]
struct PacketOut<'a> {
    #[serde(flatten)]
    record: &'a PacketRecordMetadata,
    decoded: &'a DecodedPacket,
}

impl<W: Write> PacketSink for Streamer<'_, W> {
    fn start(&mut self, header: &PcapGlobalHeader) {
        self.link_type = header.link_type.0;
        self.fingerprint.header(header);
    }

    fn packet(&mut self, record: &PacketRecordMetadata, data: &[u8]) {
        if self.error.is_some() {
            return;
        }
        self.fingerprint.record(record, data);
        let packet = decode_packet(self.link_type, data, record.original_length);
        let result = match self.style {
            Style::Table { verbose, width } => write_row(self.out, record, &packet, verbose, width),
            Style::Json => {
                let separator = if self.written == 0 {
                    Ok(())
                } else {
                    self.out.write_all(b",")
                };
                separator.and_then(|()| {
                    serde_json::to_writer(
                        &mut *self.out,
                        &PacketOut {
                            record,
                            decoded: &packet,
                        },
                    )
                    .map_err(io::Error::from)
                })
            }
        };
        self.written = self.written.saturating_add(1);
        if let Err(err) = result {
            self.error = Some(err);
        }
    }
}

/// Runs the second pass over exactly the packets the first pass read.
/// `Err` is an output error; a changed file is reported as
/// [`StreamOutcome::Changed`].
pub fn stream_packets(
    out: &mut impl Write,
    args: &InspectArgs,
    report: &CaptureReport,
    first: &SummaryCollector,
    style: Style,
) -> io::Result<StreamOutcome> {
    let expected = report.summary.packets_processed;
    if expected == 0 {
        return Ok(StreamOutcome::Consistent);
    }
    // The packet count bounds this pass. The time limit applied to the first
    // pass; this one is capped at an hour instead, because its speed also
    // depends on how fast the output is consumed (for example a pager).
    let limits = CaptureLimits {
        max_packets: expected,
        max_duration: std::time::Duration::from_secs(
            *CaptureLimits::MAX_DURATION_SECONDS_RANGE.end(),
        ),
        ..args.limits()
    };
    let mut streamer = Streamer {
        link_type: 0,
        out,
        style,
        written: 0,
        error: None,
        fingerprint: Fingerprint::default(),
    };
    let second = inspect_file_with_sink(
        &args.capture.pcap,
        &limits,
        &MonotonicClock::start(),
        Some(&mut streamer),
    );
    if let Some(err) = streamer.error {
        return Err(err);
    }
    let same = second.is_ok()
        && streamer.written == expected
        && streamer.fingerprint.value() == first.fingerprint.value();
    Ok(if same {
        StreamOutcome::Consistent
    } else {
        StreamOutcome::Changed
    })
}

/// Writes the JSON report, streaming the `packets` array. If the file
/// changed between the passes the object stays valid JSON and gains an
/// `error` member.
pub fn write_json(
    out: &mut impl Write,
    args: &InspectArgs,
    report: &CaptureReport,
    first: &SummaryCollector,
) -> io::Result<StreamOutcome> {
    out.write_all(b"{\"summary\":")?;
    serde_json::to_writer(&mut *out, &report.summary)?;
    out.write_all(b",\"decode_summary\":")?;
    serde_json::to_writer(&mut *out, &first.summary)?;
    out.write_all(b",\"packets\":[")?;
    let outcome = stream_packets(out, args, report, first, Style::Json)?;
    out.write_all(b"],\"completion_state\":")?;
    serde_json::to_writer(&mut *out, &report.completion_state)?;
    out.write_all(b",\"warnings\":")?;
    serde_json::to_writer(&mut *out, &report.warnings)?;
    if outcome == StreamOutcome::Changed {
        out.write_all(b",\"error\":")?;
        serde_json::to_writer(
            &mut *out,
            &serde_json::json!({
                "code": "capture_changed",
                "category": "io",
                "message": CHANGED_MESSAGE,
            }),
        )?;
    }
    out.write_all(b"}\n")?;
    Ok(outcome)
}

/// Writes the decode summary block.
pub fn write_summary(out: &mut impl Write, summary: &DecodeSummary) -> io::Result<()> {
    writeln!(out, "Decode summary")?;
    writeln!(out, "  Packets decoded    {}", summary.packets_decoded)?;
    let statuses: Vec<String> = summary
        .status_counts
        .iter()
        .map(|(status, count)| format!("{} {count}", status.as_str()))
        .collect();
    writeln!(out, "  Status             {}", join_or_none(&statuses))?;
    let protocols: Vec<String> = summary
        .protocol_counts
        .iter()
        .map(|(protocol, count)| format!("{} {count}", protocol.as_str()))
        .collect();
    writeln!(out, "  Protocols          {}", join_or_none(&protocols))?;

    writeln!(out)?;
    writeln!(out, "Decode warnings")?;
    if summary.warnings.is_empty() {
        writeln!(out, "  none")?;
    }
    for w in &summary.warnings {
        let layer = w.protocol.map_or("link", |p| p.as_str());
        writeln!(
            out,
            "  {} [{layer}] (x{}, first at packet {})",
            w.code.as_str(),
            w.count,
            w.first_packet_index
        )?;
    }
    Ok(())
}

fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(", ")
    }
}

/// Writes the packet table header; rows follow from [`stream_packets`].
pub fn write_table_header(
    out: &mut impl Write,
    report: &CaptureReport,
    width: usize,
) -> io::Result<()> {
    writeln!(out, "Packets")?;
    if report.packets.is_empty() {
        return writeln!(out, "  none");
    }
    writeln!(
        out,
        "  {:>7}  {:<30}  {:<width$}  {:<width$}  {:<8}  {:>6}  Info",
        "#", "Timestamp (UTC)", "Source", "Destination", "Protocol", "Length"
    )
}

/// Column width for source/destination: IPv6 addresses are at most 39
/// characters, MAC addresses 17.
pub fn column_width(longest: usize) -> usize {
    longest.clamp(11, 39)
}

fn write_row(
    out: &mut impl Write,
    record: &PacketRecordMetadata,
    packet: &DecodedPacket,
    verbose: bool,
    width: usize,
) -> io::Result<()> {
    let (source, destination) = packet
        .endpoints()
        .unwrap_or_else(|| ("-".to_owned(), "-".to_owned()));
    let ts = record
        .timestamp
        .map_or_else(|| "invalid".to_owned(), |ts| ts.to_rfc3339());
    let protocol = packet.top_protocol().map_or("-", |p| p.as_str());
    writeln!(
        out,
        "  {:>7}  {:<30}  {:<width$}  {:<width$}  {:<8}  {:>6}  {}",
        record.index,
        ts,
        source,
        destination,
        protocol,
        record.original_length,
        packet.info()
    )?;
    if verbose {
        write_tree(out, record, packet)?;
    }
    Ok(())
}

fn write_tree(
    out: &mut impl Write,
    record: &PacketRecordMetadata,
    packet: &DecodedPacket,
) -> io::Result<()> {
    writeln!(
        out,
        "           Frame: {} bytes captured, {} on the wire, decode {}",
        record.captured_length,
        record.original_length,
        packet.status.as_str()
    )?;
    for layer in &packet.layers {
        writeln!(out, "           {}: {}", layer.name(), layer.describe())?;
    }
    for w in &packet.warnings {
        let layer = w.protocol.map_or("link", |p| p.as_str());
        writeln!(
            out,
            "           ! {} [{layer}]: {}",
            w.code.as_str(),
            w.detail
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use clap::Parser;

    use super::*;
    use crate::{Cli, Command};

    fn args_for(path: &Path) -> InspectArgs {
        let cli = Cli::try_parse_from([
            "flowsentinel",
            "inspect",
            "--decode",
            "--pcap",
            path.to_str().unwrap(),
        ])
        .unwrap();
        match cli.command {
            Some(Command::Inspect(args)) => args,
            _ => unreachable!(),
        }
    }

    fn first_pass(args: &InspectArgs) -> (CaptureReport, SummaryCollector) {
        let mut collector = SummaryCollector::default();
        let report = inspect_file_with_sink(
            &args.capture.pcap,
            &args.limits(),
            &MonotonicClock::start(),
            Some(&mut collector),
        )
        .unwrap();
        (report, collector)
    }

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pcap/decode-ipv4.pcap")
    }

    #[test]
    fn unchanged_files_are_consistent() {
        let args = args_for(&fixture());
        let (report, first) = first_pass(&args);
        let mut out = Vec::new();
        let outcome = stream_packets(&mut out, &args, &report, &first, Style::Json).unwrap();
        assert_eq!(outcome, StreamOutcome::Consistent);
        assert!(!out.is_empty());
    }

    #[test]
    fn a_file_changed_between_passes_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capture.pcap");
        let original = std::fs::read(fixture()).unwrap();
        std::fs::write(&path, &original).unwrap();
        let args = args_for(&path);
        let (report, first) = first_pass(&args);

        // Same size and packet count; one byte of the last packet differs.
        let mut changed = original.clone();
        *changed.last_mut().unwrap() ^= 0xFF;
        std::fs::write(&path, &changed).unwrap();
        let mut out = Vec::new();
        let outcome = stream_packets(&mut out, &args, &report, &first, Style::Json).unwrap();
        assert_eq!(outcome, StreamOutcome::Changed);

        // A JSON report stays a valid object and carries the error.
        let mut out = Vec::new();
        let outcome = write_json(&mut out, &args, &report, &first).unwrap();
        assert_eq!(outcome, StreamOutcome::Changed);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["error"]["code"], "capture_changed");
        assert!(value["packets"].is_array());
    }
}
