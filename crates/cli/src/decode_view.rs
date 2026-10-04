//! `inspect --decode`: decodes each packet transiently while the capture is
//! read, then renders protocol metadata as tables, trees or JSON.

use std::io::{self, Write};

use capture::{CaptureReport, CaptureSummary, PacketRecordMetadata, PacketSink, PcapGlobalHeader};
use decoder::{DecodeSummary, DecodedPacket, decode_packet};
use serde::Serialize;

/// Decode results, one per record in the report, in the same order.
#[derive(Debug, Default)]
pub struct Decoded {
    pub packets: Vec<DecodedPacket>,
    pub summary: DecodeSummary,
}

/// Decodes each packet as it is read. Only the decoded metadata is kept; the
/// packet bytes are borrowed for the duration of one call.
#[derive(Debug, Default)]
pub struct DecodeCollector {
    link_type: u16,
    pub decoded: Decoded,
}

impl PacketSink for DecodeCollector {
    fn start(&mut self, header: &PcapGlobalHeader) {
        self.link_type = header.link_type.0;
    }

    fn packet(&mut self, record: &PacketRecordMetadata, data: &[u8]) {
        let packet = decode_packet(self.link_type, data, record.original_length);
        self.decoded.summary.add(record.index, &packet);
        self.decoded.packets.push(packet);
    }
}

#[derive(Serialize)]
struct PacketOut<'a> {
    #[serde(flatten)]
    record: &'a PacketRecordMetadata,
    decoded: &'a DecodedPacket,
}

#[derive(Serialize)]
struct ReportOut<'a> {
    summary: &'a CaptureSummary,
    decode_summary: &'a DecodeSummary,
    packets: Vec<PacketOut<'a>>,
    completion_state: capture::CompletionState,
    warnings: &'a [capture::CaptureWarning],
}

/// Writes the report with a `decoded` object on every packet and a top-level
/// `decode_summary`. Without `--decode` the M1 shape is used unchanged.
pub fn write_json(
    out: &mut impl Write,
    report: &CaptureReport,
    decoded: &Decoded,
) -> io::Result<()> {
    let packets = report
        .packets
        .iter()
        .zip(&decoded.packets)
        .map(|(record, decoded)| PacketOut { record, decoded })
        .collect();
    let view = ReportOut {
        summary: &report.summary,
        decode_summary: &decoded.summary,
        packets,
        completion_state: report.completion_state,
        warnings: &report.warnings,
    };
    serde_json::to_writer(&mut *out, &view)?;
    writeln!(out)
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

/// Writes the decoded packet table; with `verbose`, each row is followed by
/// its protocol tree and per-packet warnings.
pub fn write_packets(
    out: &mut impl Write,
    report: &CaptureReport,
    decoded: &Decoded,
    verbose: bool,
) -> io::Result<()> {
    writeln!(out, "Packets")?;
    if report.packets.is_empty() {
        writeln!(out, "  none")?;
        return Ok(());
    }

    let endpoints = |p: &DecodedPacket| {
        p.endpoints()
            .unwrap_or_else(|| ("-".to_owned(), "-".to_owned()))
    };
    // First pass sizes the columns without keeping every row's strings.
    // IPv6 addresses are at most 39 characters; MACs 17.
    let width = decoded
        .packets
        .iter()
        .map(|p| {
            let (s, d) = endpoints(p);
            s.len().max(d.len())
        })
        .max()
        .unwrap_or(0)
        .clamp(11, 39);

    writeln!(
        out,
        "  {:>7}  {:<30}  {:<width$}  {:<width$}  {:<8}  {:>6}  Info",
        "#", "Timestamp (UTC)", "Source", "Destination", "Protocol", "Length"
    )?;
    for (record, packet) in report.packets.iter().zip(&decoded.packets) {
        let (source, destination) = endpoints(packet);
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
