//! `flowsentinel inspect`: renders a capture report as tables or JSON.

use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use capture::{
    CaptureError, CaptureReport, CompletionState, MonotonicClock, PacketSink, Timestamp,
    inspect_file_with_sink,
};
use serde::Serialize;

use crate::InspectArgs;
use crate::decode_view::{self, StreamOutcome, Style, SummaryCollector};
use crate::exit;

pub fn run(args: &InspectArgs) -> ExitCode {
    let mut collector = args.decode.then(SummaryCollector::default);
    let result = inspect_file_with_sink(
        &args.pcap,
        &args.limits(),
        &MonotonicClock::start(),
        collector.as_mut().map(|c| c as &mut dyn PacketSink),
    );
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let consistent = |()| StreamOutcome::Consistent;
    let (written, code) = match &result {
        Ok(report) => {
            let written = match (&collector, args.json) {
                (Some(c), true) => decode_view::write_json(&mut out, args, report, c),
                (None, true) => write_json(&mut out, report).map(consistent),
                (Some(c), false) => write_decoded_human(&mut out, args, report, c),
                (None, false) => write_human(&mut out, report).map(consistent),
            };
            (written, ExitCode::SUCCESS)
        }
        Err(err) => {
            let code = exit::for_category(err.category());
            if args.json {
                (write_json_error(&mut out, err).map(consistent), code)
            } else {
                report_to_stderr(&format!("error: {err}"));
                (Ok(StreamOutcome::Consistent), code)
            }
        }
    };

    match written.and_then(|outcome| out.flush().map(|()| outcome)) {
        Ok(StreamOutcome::Consistent) => code,
        // JSON output already carries the error.
        Ok(StreamOutcome::Changed) => {
            if !args.json {
                report_to_stderr(&format!("error: {}", decode_view::CHANGED_MESSAGE));
            }
            ExitCode::from(exit::IO)
        }
        // The reader went away (for example `| head`); nothing left to say.
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => code,
        Err(err) => {
            report_to_stderr(&format!("error: failed to write output: {err}"));
            ExitCode::from(exit::IO)
        }
    }
}

/// Writes one line to stderr. Unlike `eprintln!`, never panics if stderr is
/// closed.
pub fn report_to_stderr(line: &str) {
    let _ = writeln!(io::stderr().lock(), "{line}");
}

fn write_json(out: &mut impl Write, report: &CaptureReport) -> io::Result<()> {
    serde_json::to_writer(&mut *out, report)?;
    writeln!(out)
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'static str,
    category: capture::ErrorCategory,
    message: &'a str,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

fn write_json_error(out: &mut impl Write, err: &CaptureError) -> io::Result<()> {
    let message = err.to_string();
    let envelope = ErrorEnvelope {
        error: ErrorBody {
            code: err.code(),
            category: err.category(),
            message: &message,
        },
    };
    serde_json::to_writer(&mut *out, &envelope)?;
    writeln!(out)
}

fn timestamp_or_dash(ts: Option<Timestamp>) -> String {
    ts.map_or_else(|| "-".to_owned(), |ts| ts.to_rfc3339())
}

fn write_decoded_human(
    out: &mut impl Write,
    args: &InspectArgs,
    report: &CaptureReport,
    collector: &SummaryCollector,
) -> io::Result<StreamOutcome> {
    write_capture_summary(out, report)?;
    writeln!(out)?;
    decode_view::write_summary(out, &collector.summary)?;
    writeln!(out)?;
    let width = decode_view::column_width(collector.endpoint_width);
    decode_view::write_table_header(out, report, width)?;
    let style = Style::Table {
        verbose: args.verbose,
        width,
    };
    decode_view::stream_packets(out, args, report, collector, style)
}

fn write_human(out: &mut impl Write, report: &CaptureReport) -> io::Result<()> {
    write_capture_summary(out, report)?;
    writeln!(out)?;
    write_packet_table(out, report)
}

/// Capture summary and capture warnings.
fn write_capture_summary(out: &mut impl Write, report: &CaptureReport) -> io::Result<()> {
    let s = &report.summary;
    let h = &s.header;
    let link_name = h.link_type_name.unwrap_or("unknown");

    writeln!(out, "Capture summary")?;
    writeln!(
        out,
        "  File               {} ({} bytes)",
        s.file_name, s.file_size_bytes
    )?;
    writeln!(
        out,
        "  Format             {} {}.{}, {}, {} timestamps",
        s.format,
        h.version.major,
        h.version.minor,
        h.endianness.as_str(),
        h.timestamp_resolution.as_str()
    )?;
    writeln!(out, "  Snapshot length    {} bytes", h.snap_length)?;
    writeln!(out, "  Link type          {} ({link_name})", h.link_type.0)?;
    if let Some(fcs) = h.fcs_length_bytes {
        writeln!(out, "  FCS length         {fcs} bytes")?;
    }
    writeln!(out, "  Packets processed  {}", s.packets_processed)?;
    writeln!(
        out,
        "  Captured bytes     {} (original {})",
        s.captured_bytes_total, s.original_bytes_total
    )?;
    writeln!(
        out,
        "  Earliest packet    {}",
        timestamp_or_dash(s.earliest_timestamp)
    )?;
    writeln!(
        out,
        "  Latest packet      {}",
        timestamp_or_dash(s.latest_timestamp)
    )?;
    writeln!(
        out,
        "  Completion         {}",
        report.completion_state.as_str()
    )?;
    writeln!(
        out,
        "  Limits             {} MiB, {} packets, {} s",
        s.limits.max_file_size_bytes / (1024 * 1024),
        s.limits.max_packets,
        s.limits.max_duration_seconds
    )?;
    match report.completion_state {
        CompletionState::Complete => {}
        CompletionState::PacketLimitReached => writeln!(
            out,
            "  Note: stopped after {} packets; raise --max-packets to read more.",
            s.packets_processed
        )?,
        CompletionState::TimeLimitReached => writeln!(
            out,
            "  Note: stopped after {} s; raise --max-duration-seconds to read more.",
            s.limits.max_duration_seconds
        )?,
    }

    writeln!(out)?;
    writeln!(out, "Warnings")?;
    if report.warnings.is_empty() {
        writeln!(out, "  none")?;
    }
    for w in &report.warnings {
        let code = w.code.as_str();
        match w.first_packet_index {
            Some(first) => writeln!(
                out,
                "  {code} (x{}, first at packet {first}): {}",
                w.count, w.message
            )?,
            None => writeln!(out, "  {code}: {}", w.message)?,
        }
    }

    Ok(())
}

fn write_packet_table(out: &mut impl Write, report: &CaptureReport) -> io::Result<()> {
    writeln!(out, "Packets")?;
    if report.packets.is_empty() {
        writeln!(out, "  none")?;
        return Ok(());
    }
    writeln!(
        out,
        "  {:>7}  {:<30}  {:>8}  {:>8}",
        "#", "Timestamp (UTC)", "Captured", "Original"
    )?;
    for p in &report.packets {
        let ts = p
            .timestamp
            .map_or_else(|| "invalid".to_owned(), |ts| ts.to_rfc3339());
        writeln!(
            out,
            "  {:>7}  {:<30}  {:>8}  {:>8}",
            p.index, ts, p.captured_length, p.original_length
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::Duration;

    use capture::{CaptureLimits, Clock, inspect_reader};

    use super::*;

    struct Frozen;
    impl Clock for Frozen {
        fn elapsed(&self) -> Duration {
            Duration::ZERO
        }
    }

    fn report(packets: u32, max_packets: u64) -> CaptureReport {
        let mut bytes = 0xA1B2_C3D4u32.to_le_bytes().to_vec();
        bytes.extend(2u16.to_le_bytes());
        bytes.extend(4u16.to_le_bytes());
        bytes.extend([0u8; 8]);
        bytes.extend(65_535u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        for i in 0..packets {
            for v in [1_767_225_600 + i, 0, 6, 6] {
                bytes.extend(v.to_le_bytes());
            }
            bytes.extend(b"SECRET");
        }
        let limits = CaptureLimits {
            max_packets,
            ..CaptureLimits::default()
        };
        let len = bytes.len() as u64;
        inspect_reader(Cursor::new(bytes), "x.pcap".into(), len, &limits, &Frozen).unwrap()
    }

    fn human(report: &CaptureReport) -> String {
        let mut out = Vec::new();
        write_human(&mut out, report).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn human_output_has_summary_and_table() {
        let text = human(&report(2, 100));
        assert!(text.contains("Capture summary"));
        assert!(text.contains("pcap 2.4, little-endian, microsecond timestamps"));
        assert!(text.contains("Link type          1 (ETHERNET)"));
        assert!(text.contains("Completion         complete"));
        assert!(text.contains("2026-01-01T00:00:01.000000Z"));
        assert!(!text.contains("SECRET"));
    }

    #[test]
    fn human_output_explains_partial_results() {
        let text = human(&report(5, 2));
        assert!(text.contains("partial (packet limit reached)"));
        assert!(text.contains("raise --max-packets"));
    }

    #[test]
    fn json_output_is_one_object() {
        let mut out = Vec::new();
        write_json(&mut out, &report(1, 100)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(value.is_object());
        assert!(!text.contains("SECRET"));
    }

    #[test]
    fn json_errors_have_code_category_and_message() {
        let mut out = Vec::new();
        write_json_error(&mut out, &CaptureError::InvalidMagic).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["error"]["code"], "invalid_magic");
        assert_eq!(value["error"]["category"], "malformed");
        assert!(value["error"]["message"].as_str().unwrap().contains("PCAP"));
    }
}
