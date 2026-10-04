//! `flowsentinel flows`: reconstructs bidirectional flows from a capture.

use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use capture::{
    CaptureReport, MonotonicClock, PacketRecordMetadata, PacketSink, PcapGlobalHeader,
    inspect_file_with_sink,
};
use decoder::decode_packet;
use flow_engine::{FlowEngine, FlowPacket, FlowRecord, FlowReport};
use serde::Serialize;

use crate::inspect::{report_to_stderr, write_json_error};
use crate::{FlowSort, FlowsArgs, exit};

/// Decodes each packet as it is read and feeds it to the flow engine.
struct FlowCollector {
    link_type: u16,
    engine: FlowEngine,
}

impl PacketSink for FlowCollector {
    fn start(&mut self, header: &PcapGlobalHeader) {
        self.link_type = header.link_type.0;
    }

    fn packet(&mut self, record: &PacketRecordMetadata, data: &[u8]) {
        let decoded = decode_packet(self.link_type, data, record.original_length);
        self.engine.process(&FlowPacket {
            index: record.index,
            timestamp: record.timestamp,
            wire_length: record.original_length,
            decoded: &decoded,
        });
    }
}

pub fn run(args: &FlowsArgs) -> ExitCode {
    let mut collector = FlowCollector {
        link_type: 0,
        engine: FlowEngine::new(args.flow_config()),
    };
    let result = inspect_file_with_sink(
        &args.capture.pcap,
        &args.capture.limits(),
        &MonotonicClock::start(),
        Some(&mut collector),
    );
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let (written, code) = match result {
        Ok(report) => {
            let mut flows = collector.engine.finish();
            sort(&mut flows.flows, args.sort);
            let written = if args.json {
                write_json(&mut out, &report, &flows)
            } else {
                write_human(&mut out, &report, &flows)
            };
            (written, ExitCode::SUCCESS)
        }
        Err(err) => {
            let code = exit::for_category(err.category());
            if args.json {
                (write_json_error(&mut out, &err), code)
            } else {
                report_to_stderr(&format!("error: {err}"));
                (Ok(()), code)
            }
        }
    };
    match written.and_then(|()| out.flush()) {
        Ok(()) => code,
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => code,
        Err(err) => {
            report_to_stderr(&format!("error: failed to write output: {err}"));
            ExitCode::from(exit::IO)
        }
    }
}

fn sort(flows: &mut [FlowRecord], order: FlowSort) {
    match order {
        FlowSort::Start => flows.sort_by_key(|f| f.flow_id),
        FlowSort::Bytes => flows.sort_by(|a, b| {
            b.bytes_total
                .cmp(&a.bytes_total)
                .then(a.flow_id.cmp(&b.flow_id))
        }),
        FlowSort::Packets => flows.sort_by(|a, b| {
            b.packets_total
                .cmp(&a.packets_total)
                .then(a.flow_id.cmp(&b.flow_id))
        }),
        FlowSort::Duration => flows.sort_by(|a, b| {
            b.duration_seconds
                .total_cmp(&a.duration_seconds)
                .then(a.flow_id.cmp(&b.flow_id))
        }),
    }
}

#[derive(Serialize)]
struct FlowsOut<'a> {
    capture: &'a capture::CaptureSummary,
    completion_state: capture::CompletionState,
    capture_warnings: &'a [capture::CaptureWarning],
    flow_summary: &'a flow_engine::FlowSummary,
    flows: &'a [FlowRecord],
}

fn write_json(out: &mut impl Write, report: &CaptureReport, flows: &FlowReport) -> io::Result<()> {
    let view = FlowsOut {
        capture: &report.summary,
        completion_state: report.completion_state,
        capture_warnings: &report.warnings,
        flow_summary: &flows.summary,
        flows: &flows.flows,
    };
    serde_json::to_writer(&mut *out, &view)?;
    writeln!(out)
}

fn application_note(flow: &FlowRecord) -> String {
    let app = &flow.application;
    let mut parts = Vec::new();
    if let Some(sni) = app.tls_server_names.first() {
        parts.push(format!("TLS {sni}"));
    }
    if let Some(host) = app.http_hosts.first() {
        parts.push(format!("HTTP {host}"));
    }
    if let Some(name) = app.dns_queries.first() {
        parts.push(format!("DNS {name}"));
    }
    if parts.is_empty() {
        if let Some(name) = app.responder_dns_names.first() {
            parts.push(format!("({name})"));
        }
    }
    if parts.is_empty() {
        for protocol in &app.protocols {
            parts.push(protocol.as_str().to_owned());
        }
    }
    if parts.is_empty() {
        "-".to_owned()
    } else {
        parts.join(", ")
    }
}

fn write_human(out: &mut impl Write, report: &CaptureReport, flows: &FlowReport) -> io::Result<()> {
    let s = &report.summary;
    let f = &flows.summary;
    writeln!(out, "Capture")?;
    writeln!(
        out,
        "  File               {} ({} bytes)",
        s.file_name, s.file_size_bytes
    )?;
    writeln!(out, "  Packets processed  {}", s.packets_processed)?;
    writeln!(
        out,
        "  Completion         {}",
        report.completion_state.as_str()
    )?;
    writeln!(out)?;
    writeln!(out, "Flow summary")?;
    writeln!(
        out,
        "  Packets            {} in flows, {} without an IP layer",
        f.packets_in_flows, f.packets_without_ip
    )?;
    writeln!(
        out,
        "  Flows              {} total, {} listed, {} not retained, peak {} active",
        f.flows_total, f.flows_retained, f.flows_not_retained, f.peak_active_flows
    )?;
    let reasons: Vec<String> = f
        .end_reasons
        .iter()
        .map(|(r, n)| format!("{} {n}", r.as_str()))
        .collect();
    writeln!(
        out,
        "  Ended by           {}",
        if reasons.is_empty() {
            "-".to_owned()
        } else {
            reasons.join(", ")
        }
    )?;
    if f.timestamp_outliers > 0 || f.clock_jumps > 0 {
        writeln!(
            out,
            "  Timestamps         {} outliers ignored, {} clock jumps over a day",
            f.timestamp_outliers, f.clock_jumps
        )?;
    }
    writeln!(
        out,
        "  Limits             {} active, {} retained",
        f.max_active_flows, f.max_retained_flows
    )?;
    if f.flows_not_retained > 0 {
        writeln!(out, "  Note: raise --max-flows to list every flow.")?;
    }
    writeln!(out)?;
    writeln!(out, "Flows")?;
    if flows.flows.is_empty() {
        return writeln!(out, "  none");
    }
    let width = flows
        .flows
        .iter()
        .map(|flow| {
            flow.initiator
                .to_string()
                .len()
                .max(flow.responder.to_string().len())
        })
        .max()
        .unwrap_or(0)
        .clamp(9, 47);
    let proto_name = |flow: &FlowRecord| {
        flow.protocol_name
            .map_or_else(|| flow.protocol.to_string(), str::to_owned)
    };
    let proto_width = flows
        .flows
        .iter()
        .map(|flow| proto_name(flow).len())
        .max()
        .unwrap_or(0)
        .clamp(5, 24);
    writeln!(
        out,
        "  {:>6}  {:<proto_width$}  {:<width$}  {:<width$}  {:>7}  {:>10}  {:>10}  {:<12}  Application",
        "ID", "Proto", "Initiator", "Responder", "Packets", "Bytes", "Duration", "State"
    )?;
    for flow in &flows.flows {
        let state = flow.tcp.as_ref().map_or("-", |t| t.state.as_str());
        writeln!(
            out,
            "  {:>6}  {:<proto_width$}  {:<width$}  {:<width$}  {:>7}  {:>10}  {:>9.3}s  {:<12}  {}",
            flow.flow_id,
            proto_name(flow),
            flow.initiator.to_string(),
            flow.responder.to_string(),
            flow.packets_total,
            flow.bytes_total,
            flow.duration_seconds,
            state,
            application_note(flow)
        )?;
    }
    Ok(())
}
