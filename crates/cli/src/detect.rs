//! `flowsentinel detect`: runs the detection rules over a capture.

use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use analysis::{AnalysisConfig, analyze_file_with_detection};
use capture::{CaptureReport, MonotonicClock};
use detection_engine::{Alert, DetectionConfig, DetectionReport, Detector, NATURE};
use flow_engine::FlowConfig;
use serde::Serialize;

use crate::inspect::{report_to_stderr, write_json_error};
use crate::{DetectArgs, exit};

fn load_config(args: &DetectArgs) -> Result<DetectionConfig, String> {
    let Some(path) = &args.config else {
        return Ok(DetectionConfig::default());
    };
    let name = capture::display_file_name(path);
    DetectionConfig::load(path).map_err(|e| format!("--config {name}: {e}"))
}

pub fn run(args: &DetectArgs) -> ExitCode {
    let detector = match load_config(args).and_then(|c| Detector::new(c).map_err(|e| e.to_string()))
    {
        Ok(detector) => detector,
        Err(message) => {
            report_to_stderr(&format!("error: {message}"));
            return ExitCode::from(exit::USAGE);
        }
    };
    let config = AnalysisConfig {
        limits: args.capture.limits(),
        flows: FlowConfig::default(),
        replay_packets: 0,
    };
    let result = analyze_file_with_detection(
        &args.capture.pcap,
        &config,
        detector,
        &MonotonicClock::start(),
    );
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let (written, code) = match result {
        Ok(analysis) => {
            let empty = DetectionReport {
                summary: Default::default(),
                alerts: Vec::new(),
            };
            let detection = analysis.detection.as_ref().unwrap_or(&empty);
            let written = if args.json {
                write_json(&mut out, &analysis.report, detection)
            } else {
                write_human(&mut out, &analysis.report, detection)
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

#[derive(Serialize)]
struct DetectOut<'a> {
    capture: &'a capture::CaptureSummary,
    completion_state: capture::CompletionState,
    capture_warnings: &'a [capture::CaptureWarning],
    nature: &'static str,
    detection_summary: &'a detection_engine::DetectionSummary,
    alerts: &'a [Alert],
}

fn write_json(
    out: &mut impl Write,
    report: &CaptureReport,
    detection: &DetectionReport,
) -> io::Result<()> {
    let view = DetectOut {
        capture: &report.summary,
        completion_state: report.completion_state,
        capture_warnings: &report.warnings,
        nature: NATURE,
        detection_summary: &detection.summary,
        alerts: &detection.alerts,
    };
    serde_json::to_writer(&mut *out, &view)?;
    writeln!(out)
}

fn time(alert: &Alert) -> String {
    alert
        .first_seen
        .map_or_else(|| "-".to_owned(), |t| t.to_rfc3339())
}

fn endpoints(alert: &Alert) -> String {
    let source = alert
        .source
        .map_or_else(|| "-".to_owned(), |ip| ip.to_string());
    match (alert.destination, alert.destination_port) {
        (Some(ip), Some(port)) => format!("{source} -> {ip} port {port}"),
        (Some(ip), None) => format!("{source} -> {ip}"),
        (None, Some(port)) => format!("{source} -> port {port}"),
        (None, None) => source,
    }
}

fn write_human(
    out: &mut impl Write,
    report: &CaptureReport,
    detection: &DetectionReport,
) -> io::Result<()> {
    let s = &report.summary;
    let d = &detection.summary;
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
    writeln!(out, "Detection summary")?;
    writeln!(out, "  Alerts             {}", d.alerts_total)?;
    let by_severity: Vec<String> = ["high", "medium", "low"]
        .iter()
        .filter_map(|s| d.alerts_by_severity.get(s).map(|n| format!("{s} {n}")))
        .collect();
    if !by_severity.is_empty() {
        writeln!(out, "  By severity        {}", by_severity.join(", "))?;
    }
    writeln!(out, "  Flows evaluated    {}", d.flows_evaluated)?;
    if d.events_not_evaluated > 0 {
        writeln!(
            out,
            "  Not evaluated      {} DNS/ARP events beyond a rule's key or event limit",
            d.events_not_evaluated
        )?;
    }
    if d.keys_evicted > 0 {
        writeln!(
            out,
            "  Keys evicted       {} (DNS/ARP history dropped to make room for new hosts or domains)",
            d.keys_evicted
        )?;
    }
    if !d.rules_at_alert_limit.is_empty() {
        let rules: Vec<&str> = d.rules_at_alert_limit.iter().copied().collect();
        writeln!(
            out,
            "  Alert limit        reached by {} (further alerts not raised)",
            rules.join(", ")
        )?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "Alerts are heuristic indicators: observed patterns to review, not proof of compromise."
    )?;
    if detection.alerts.is_empty() {
        writeln!(out)?;
        return writeln!(out, "No alerts.");
    }
    for alert in &detection.alerts {
        writeln!(out)?;
        writeln!(
            out,
            "[{}] {} ({}), {} severity, {} confidence",
            alert.alert_id,
            alert.rule_name,
            alert.rule_id,
            alert.severity.as_str(),
            alert.confidence.as_str()
        )?;
        writeln!(out, "  When       {}", time(alert))?;
        writeln!(out, "  Endpoints  {}", endpoints(alert))?;
        let evidence: Vec<String> = alert
            .evidence
            .iter()
            .map(|e| format!("{}={}", e.name, e.value))
            .collect();
        writeln!(out, "  Evidence   {}", evidence.join(", "))?;
        writeln!(out, "  Why        {}", alert.explanation)?;
        writeln!(out, "  Caveats    {}", alert.uncertainty)?;
        writeln!(
            out,
            "  Benign causes  {}",
            alert.likely_false_positives.join("; ")
        )?;
        if !alert.related_flow_ids.is_empty() {
            let ids: Vec<String> = alert.related_flow_ids.iter().map(u64::to_string).collect();
            writeln!(out, "  Flows      {}", ids.join(" "))?;
        }
        if !alert.related_packet_indexes.is_empty() {
            let ids: Vec<String> = alert
                .related_packet_indexes
                .iter()
                .map(u64::to_string)
                .collect();
            writeln!(out, "  Packets    {}", ids.join(" "))?;
        }
        writeln!(out, "  ATT&CK context  {}", alert.mitre_attack.join("; "))?;
    }
    Ok(())
}
