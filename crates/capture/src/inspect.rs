//! File validation and the top-level inspection entry points.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

use serde::Serialize;

use crate::error::CaptureError;
use crate::header::PcapGlobalHeader;
use crate::limits::{AppliedLimits, CaptureLimits, Clock, MonotonicClock};
use crate::reader::{PacketRecordMetadata, PcapReader};
use crate::timestamp::Timestamp;
use crate::warning::{CaptureWarning, WarningCode};

/// Longest file name shown in output, in characters.
const MAX_DISPLAY_NAME_CHARS: usize = 128;
/// Read buffer size. Bounded and independent of file contents.
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// Why an inspection stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionState {
    /// Every record in the file was read.
    Complete,
    /// `max_packets` records were read and more remain.
    PacketLimitReached,
    /// `max_duration` elapsed before the end of the file.
    TimeLimitReached,
}

impl CompletionState {
    /// Returns `true` unless every record was read.
    pub fn is_partial(self) -> bool {
        self != Self::Complete
    }

    /// Human-readable description.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::PacketLimitReached => "partial (packet limit reached)",
            Self::TimeLimitReached => "partial (time limit reached)",
        }
    }
}

/// Aggregate facts about an inspected capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureSummary {
    /// File name only, with control and bidirectional-override characters
    /// replaced. Directories are never shown.
    pub file_name: String,
    pub file_size_bytes: u64,
    /// Always `"pcap"` in this version.
    pub format: &'static str,
    pub header: PcapGlobalHeader,
    pub packets_processed: u64,
    pub captured_bytes_total: u64,
    pub original_bytes_total: u64,
    pub earliest_timestamp: Option<Timestamp>,
    pub latest_timestamp: Option<Timestamp>,
    pub limits: AppliedLimits,
}

/// Complete, metadata-only result of an inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureReport {
    pub summary: CaptureSummary,
    pub packets: Vec<PacketRecordMetadata>,
    pub completion_state: CompletionState,
    pub warnings: Vec<CaptureWarning>,
}

/// Receives each packet's captured bytes during an inspection, for transient
/// processing such as protocol decoding.
///
/// `data` is borrowed for the duration of one call and holds at most
/// [`MAX_PACKET_DATA_BYTES`](crate::MAX_PACKET_DATA_BYTES) bytes.
/// Implementations should extract metadata and must not keep copies of the
/// bytes.
pub trait PacketSink {
    /// Called once after the global header is validated, before any packet.
    fn start(&mut self, _header: &PcapGlobalHeader) {}

    /// Called for each complete record, in file order.
    fn packet(&mut self, record: &PacketRecordMetadata, data: &[u8]);
}

/// Validates `path` and inspects it with a wall-clock time limit.
pub fn inspect_file(path: &Path, limits: &CaptureLimits) -> Result<CaptureReport, CaptureError> {
    inspect_file_with_clock(path, limits, &MonotonicClock::start())
}

/// Like [`inspect_file`] with an injected clock.
pub fn inspect_file_with_clock(
    path: &Path,
    limits: &CaptureLimits,
    clock: &dyn Clock,
) -> Result<CaptureReport, CaptureError> {
    inspect_file_with_sink(path, limits, clock, None)
}

/// Like [`inspect_file_with_clock`], additionally passing every packet's
/// bytes to `sink`.
pub fn inspect_file_with_sink(
    path: &Path,
    limits: &CaptureLimits,
    clock: &dyn Clock,
    sink: Option<&mut dyn PacketSink>,
) -> Result<CaptureReport, CaptureError> {
    let limits = limits.clamped();
    let (file, file_name, file_size_bytes) = open_capture(path, &limits)?;
    // Read exactly the bytes whose size was validated, even if the file grows
    // while it is being read.
    let mut source = BufReader::with_capacity(READ_BUFFER_BYTES, file.take(file_size_bytes));
    let mut report = inspect_reader_with_sink(
        &mut source,
        file_name,
        file_size_bytes,
        &limits,
        clock,
        sink,
    )?;

    let size_now = source.get_ref().get_ref().metadata().map(|m| m.len());
    if size_now.is_ok_and(|len| len != file_size_bytes) {
        report.warnings.push(CaptureWarning {
            code: WarningCode::FileSizeChanged,
            message: WarningCode::FileSizeChanged.message(),
            count: 1,
            first_packet_index: None,
        });
    }
    Ok(report)
}

/// Validates a capture path and opens it.
///
/// Checks, in order: the path exists, it is a regular file, its extension is
/// `.pcap` (case-insensitive; `.pcapng` gets its own error), and its size is
/// within the limit. Returns the open file, its sanitized display name and
/// its size.
pub fn open_capture(
    path: &Path,
    limits: &CaptureLimits,
) -> Result<(File, String, u64), CaptureError> {
    let file = display_file_name(path);

    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        // NotADirectory: a parent component of the path is a regular file.
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Err(CaptureError::MissingPath { file });
        }
        Err(err) => return Err(CaptureError::io("reading file metadata")(err)),
    };
    if !metadata.is_file() {
        return Err(CaptureError::NotAFile { file });
    }

    let extension = path
        .extension()
        .map(|ext| ext.to_string_lossy().to_ascii_lowercase());
    match extension.as_deref() {
        Some("pcap") => {}
        Some("pcapng") => return Err(CaptureError::PcapngNotSupported { file }),
        _ => return Err(CaptureError::UnsupportedExtension { file }),
    }

    check_size(&file, metadata.len(), limits)?;
    let handle = open_read_only(path).map_err(CaptureError::io("opening the file"))?;
    // Re-check through the open handle: the path may have been replaced
    // between the checks above and the open.
    let opened = handle
        .metadata()
        .map_err(CaptureError::io("reading file metadata"))?;
    if !opened.is_file() {
        return Err(CaptureError::NotAFile { file });
    }
    check_size(&file, opened.len(), limits)?;
    Ok((handle, file, opened.len()))
}

/// Opens `path` for reading. On Unix the open is non-blocking, so a path
/// swapped for a FIFO after validation cannot hang the open; the handle is
/// re-checked for being a regular file before any read.
fn open_read_only(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

fn check_size(file: &str, size_bytes: u64, limits: &CaptureLimits) -> Result<(), CaptureError> {
    if size_bytes > limits.max_file_size_bytes {
        return Err(CaptureError::FileTooLarge {
            file: file.to_owned(),
            size_bytes,
            limit_bytes: limits.max_file_size_bytes,
        });
    }
    Ok(())
}

/// Inspects an already-open PCAP stream. Limits are clamped to their
/// documented ranges (see [`CaptureLimits::clamped`]).
pub fn inspect_reader<R: BufRead>(
    source: R,
    file_name: String,
    file_size_bytes: u64,
    limits: &CaptureLimits,
    clock: &dyn Clock,
) -> Result<CaptureReport, CaptureError> {
    inspect_reader_with_sink(source, file_name, file_size_bytes, limits, clock, None)
}

/// Like [`inspect_reader`], additionally passing every packet's bytes to
/// `sink`. Without a sink, packet data is skipped rather than copied.
pub fn inspect_reader_with_sink<R: BufRead>(
    source: R,
    file_name: String,
    file_size_bytes: u64,
    limits: &CaptureLimits,
    clock: &dyn Clock,
    mut sink: Option<&mut dyn PacketSink>,
) -> Result<CaptureReport, CaptureError> {
    let limits = &limits.clamped();
    let mut reader = PcapReader::new(source)?;
    if let Some(sink) = sink.as_deref_mut() {
        sink.start(reader.header());
    }
    // Reused for every record; grows at most to MAX_PACKET_DATA_BYTES.
    let mut data = Vec::new();
    let mut packets = Vec::new();
    let mut captured_bytes_total: u64 = 0;
    let mut original_bytes_total: u64 = 0;
    let mut earliest: Option<Timestamp> = None;
    let mut latest: Option<Timestamp> = None;

    let completion_state = loop {
        if reader.at_eof()? {
            break CompletionState::Complete;
        }
        if reader.records_read() >= limits.max_packets {
            break CompletionState::PacketLimitReached;
        }
        if clock.elapsed() >= limits.max_duration {
            break CompletionState::TimeLimitReached;
        }
        let next = match sink.as_deref_mut() {
            Some(sink) => reader.next_packet(&mut data)?.inspect(|record| {
                sink.packet(record, &data);
            }),
            None => reader.next_record()?,
        };
        let Some(record) = next else {
            break CompletionState::Complete;
        };
        captured_bytes_total =
            captured_bytes_total.saturating_add(u64::from(record.captured_length));
        original_bytes_total =
            original_bytes_total.saturating_add(u64::from(record.original_length));
        if let Some(ts) = record.timestamp {
            earliest = Some(earliest.map_or(ts, |e| e.min(ts)));
            latest = Some(latest.map_or(ts, |l| l.max(ts)));
        }
        packets.push(record);
    };

    let summary = CaptureSummary {
        file_name,
        file_size_bytes,
        format: "pcap",
        header: *reader.header(),
        packets_processed: reader.records_read(),
        captured_bytes_total,
        original_bytes_total,
        earliest_timestamp: earliest,
        latest_timestamp: latest,
        limits: AppliedLimits::from(limits),
    };
    Ok(CaptureReport {
        summary,
        packets,
        completion_state,
        warnings: reader.into_warnings(),
    })
}

/// Returns the final path component, safe to print to a terminal or log:
/// control characters and Unicode bidirectional overrides are replaced with
/// `?`, and long names are shortened.
pub fn display_file_name(path: &Path) -> String {
    let Some(name) = path.file_name() else {
        return "<unnamed>".to_owned();
    };
    let lossy = name.to_string_lossy();
    let mut out: String = lossy
        .chars()
        .take(MAX_DISPLAY_NAME_CHARS)
        .map(|c| if is_unsafe_display_char(c) { '?' } else { c })
        .collect();
    if lossy.chars().nth(MAX_DISPLAY_NAME_CHARS).is_some() {
        out.push_str("...");
    }
    out
}

/// Control characters, line/paragraph separators, byte-order marks and
/// Unicode bidirectional formatting characters, which can reorder or hide
/// text in a terminal.
fn is_unsafe_display_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{Cursor, Write};
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::error::ErrorCategory;

    const BASE_TIME: u32 = 1_767_225_600;

    fn capture(packet_count: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(0xA1B2_C3D4u32.to_le_bytes());
        out.extend(2u16.to_le_bytes());
        out.extend(4u16.to_le_bytes());
        out.extend([0u8; 8]);
        out.extend(65_535u32.to_le_bytes());
        out.extend(1u32.to_le_bytes());
        for i in 0..packet_count {
            for value in [BASE_TIME + i, 0, 8, 8] {
                out.extend(value.to_le_bytes());
            }
            out.extend(b"PAYLOAD!");
        }
        out
    }

    /// Clock that advances by `step` every time it is read.
    struct SteppingClock {
        now: Cell<Duration>,
        step: Duration,
    }

    impl Clock for SteppingClock {
        fn elapsed(&self) -> Duration {
            let now = self.now.get();
            self.now.set(now + self.step);
            now
        }
    }

    fn frozen() -> SteppingClock {
        SteppingClock {
            now: Cell::new(Duration::ZERO),
            step: Duration::ZERO,
        }
    }

    fn inspect(bytes: Vec<u8>, limits: &CaptureLimits, clock: &dyn Clock) -> CaptureReport {
        let len = bytes.len() as u64;
        inspect_reader(Cursor::new(bytes), "t.pcap".into(), len, limits, clock).unwrap()
    }

    #[test]
    fn complete_inspection_summarizes_everything() {
        let report = inspect(capture(3), &CaptureLimits::default(), &frozen());
        assert_eq!(report.completion_state, CompletionState::Complete);
        assert_eq!(report.summary.packets_processed, 3);
        assert_eq!(report.packets.len(), 3);
        assert_eq!(report.summary.captured_bytes_total, 24);
        assert_eq!(report.summary.original_bytes_total, 24);
        assert_eq!(
            report.summary.earliest_timestamp.unwrap().unix_seconds(),
            u64::from(BASE_TIME)
        );
        assert_eq!(
            report.summary.latest_timestamp.unwrap().unix_seconds(),
            u64::from(BASE_TIME + 2)
        );
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn packet_limit_is_partial_completion() {
        let limits = CaptureLimits {
            max_packets: 2,
            ..CaptureLimits::default()
        };
        let report = inspect(capture(5), &limits, &frozen());
        assert_eq!(report.completion_state, CompletionState::PacketLimitReached);
        assert_eq!(report.packets.len(), 2);
        assert!(report.completion_state.is_partial());
    }

    #[test]
    fn packet_limit_equal_to_packet_count_is_complete() {
        let limits = CaptureLimits {
            max_packets: 3,
            ..CaptureLimits::default()
        };
        let report = inspect(capture(3), &limits, &frozen());
        assert_eq!(report.completion_state, CompletionState::Complete);
    }

    #[test]
    fn time_limit_is_partial_completion() {
        // Each clock read advances one second; the limit allows two reads.
        let clock = SteppingClock {
            now: Cell::new(Duration::ZERO),
            step: Duration::from_secs(1),
        };
        let limits = CaptureLimits {
            max_duration: Duration::from_secs(2),
            ..CaptureLimits::default()
        };
        let report = inspect(capture(10), &limits, &clock);
        assert_eq!(report.completion_state, CompletionState::TimeLimitReached);
        assert_eq!(report.packets.len(), 2);
    }

    #[test]
    fn expired_clock_on_fully_read_file_is_still_complete() {
        let clock = SteppingClock {
            now: Cell::new(Duration::from_secs(3600)),
            step: Duration::ZERO,
        };
        let report = inspect(capture(0), &CaptureLimits::default(), &clock);
        assert_eq!(report.completion_state, CompletionState::Complete);
        assert!(report.packets.is_empty());
        assert!(report.summary.earliest_timestamp.is_none());
    }

    #[test]
    fn report_json_never_contains_payload_bytes() {
        let report = inspect(capture(3), &CaptureLimits::default(), &frozen());
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("PAYLOAD"));
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["completion_state"], "complete");
        assert_eq!(value["summary"]["header"]["link_type_name"], "ETHERNET");
        assert_eq!(value["packets"][0]["index"], 1);
    }

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn validates_paths_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let limits = CaptureLimits::default();

        let missing = dir.path().join("missing.pcap");
        let err = inspect_file(&missing, &limits).unwrap_err();
        assert_eq!(err.code(), "missing_path");
        assert_eq!(err.category(), ErrorCategory::Input);
        assert!(!err.to_string().contains(&*dir.path().to_string_lossy()));

        let subdir = dir.path().join("folder.pcap");
        fs::create_dir(&subdir).unwrap();
        assert_eq!(
            inspect_file(&subdir, &limits).unwrap_err().code(),
            "not_a_file"
        );

        let txt = write_file(dir.path(), "notes.txt", &capture(1));
        assert_eq!(
            inspect_file(&txt, &limits).unwrap_err().code(),
            "unsupported_extension"
        );
        let bare = write_file(dir.path(), "noextension", &capture(1));
        assert_eq!(
            inspect_file(&bare, &limits).unwrap_err().code(),
            "unsupported_extension"
        );
        let ng = write_file(dir.path(), "trace.PcapNg", &capture(1));
        assert_eq!(
            inspect_file(&ng, &limits).unwrap_err().code(),
            "pcapng_not_supported"
        );

        let upper = write_file(dir.path(), "TRACE.PCAP", &capture(2));
        let report = inspect_file(&upper, &limits).unwrap();
        assert_eq!(report.summary.file_name, "TRACE.PCAP");
        assert_eq!(report.summary.packets_processed, 2);
    }

    #[test]
    fn rejects_files_over_the_size_limit_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        // Not a valid capture: if it were parsed, the error would differ.
        let path = write_file(dir.path(), "big.pcap", &vec![0u8; 2 * 1024 * 1024]);
        let limits = CaptureLimits::from_cli_units(1, 10, 10);
        match inspect_file(&path, &limits) {
            Err(CaptureError::FileTooLarge {
                size_bytes,
                limit_bytes,
                ..
            }) => assert_eq!((size_bytes, limit_bytes), (2 * 1024 * 1024, 1024 * 1024)),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Appends a record to the file the first time it is read, simulating a
    /// capture that is still being written.
    struct GrowingClock {
        path: PathBuf,
        grown: Cell<bool>,
    }

    impl Clock for GrowingClock {
        fn elapsed(&self) -> Duration {
            if !self.grown.replace(true) {
                let mut file = fs::OpenOptions::new()
                    .append(true)
                    .open(&self.path)
                    .unwrap();
                file.write_all(&capture(1)[24..]).unwrap();
            }
            Duration::ZERO
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        link_type: Option<u16>,
        seen: Vec<(u64, usize, bool)>,
    }

    impl PacketSink for RecordingSink {
        fn start(&mut self, header: &PcapGlobalHeader) {
            self.link_type = Some(header.link_type.0);
        }

        fn packet(&mut self, record: &PacketRecordMetadata, data: &[u8]) {
            self.seen
                .push((record.index, data.len(), data == b"PAYLOAD!"));
        }
    }

    #[test]
    fn sinks_see_every_packet_and_the_report_is_unchanged() {
        let limits = CaptureLimits {
            max_packets: 2,
            ..CaptureLimits::default()
        };
        let mut sink = RecordingSink::default();
        let bytes = capture(3);
        let len = bytes.len() as u64;
        let with_sink = inspect_reader_with_sink(
            Cursor::new(bytes.clone()),
            "t.pcap".into(),
            len,
            &limits,
            &frozen(),
            Some(&mut sink),
        )
        .unwrap();
        let without = inspect(bytes, &limits, &frozen());
        assert_eq!(with_sink, without);
        assert_eq!(sink.link_type, Some(1));
        assert_eq!(sink.seen, vec![(1, 8, true), (2, 8, true)]);
    }

    #[test]
    fn growth_during_the_read_is_ignored_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "live.pcap", &capture(2));
        let clock = GrowingClock {
            path: path.clone(),
            grown: Cell::new(false),
        };
        let report = inspect_file_with_clock(&path, &CaptureLimits::default(), &clock).unwrap();
        assert_eq!(report.summary.packets_processed, 2);
        assert_eq!(report.completion_state, CompletionState::Complete);
        let codes: Vec<_> = report.warnings.iter().map(|w| w.code).collect();
        assert_eq!(codes, vec![WarningCode::FileSizeChanged]);
    }

    #[test]
    fn a_file_used_as_a_directory_is_a_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_file(dir.path(), "real.pcap", &capture(1));
        let err = inspect_file(&file.join("inner.pcap"), &CaptureLimits::default()).unwrap_err();
        assert_eq!(err.code(), "missing_path");
    }

    #[cfg(unix)]
    #[test]
    fn fifos_are_rejected_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe.pcap");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !made.is_ok_and(|status| status.success()) {
            eprintln!("mkfifo unavailable; skipping");
            return;
        }
        let err = inspect_file(&fifo, &CaptureLimits::default()).unwrap_err();
        assert_eq!(err.code(), "not_a_file");
    }

    #[test]
    fn library_callers_cannot_exceed_limit_ranges() {
        let limits = CaptureLimits {
            max_packets: u64::MAX,
            ..CaptureLimits::default()
        };
        let report = inspect(capture(1), &limits, &frozen());
        assert_eq!(report.summary.limits.max_packets, 1_000_000);
    }

    #[test]
    fn display_names_are_sanitized() {
        assert_eq!(display_file_name(Path::new("dir/sub/a.pcap")), "a.pcap");
        assert_eq!(
            display_file_name(Path::new("bad\nname\u{1b}.pcap")),
            "bad?name?.pcap"
        );
        assert_eq!(
            display_file_name(Path::new("evil\u{202E}pacp.exe")),
            "evil?pacp.exe"
        );
        assert_eq!(display_file_name(Path::new("/")), "<unnamed>");
        assert_eq!(
            display_file_name(Path::new("a\u{2028}b\u{061C}c\u{FEFF}.pcap")),
            "a?b?c?.pcap"
        );
        let long = "x".repeat(300) + ".pcap";
        let shown = display_file_name(Path::new(&long));
        assert_eq!(shown.chars().count(), MAX_DISPLAY_NAME_CHARS + 3);
        assert!(shown.ends_with("..."));
    }
}
