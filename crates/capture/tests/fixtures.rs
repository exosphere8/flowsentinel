//! Inspects every committed fixture under `fixtures/pcap/` and checks the
//! outcome. Fixtures are produced by `scripts/generate_pcap_fixtures.py`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use capture::{
    CaptureError, CaptureLimits, CompletionState, Endianness, ErrorCategory, TimestampResolution,
    UnsupportedFormat, WarningCode, inspect_file,
};

/// Must match PAYLOAD_MARKER in the fixture generator.
const PAYLOAD_MARKER: &str = "FLOWSENTINEL-SYNTHETIC-PAYLOAD-MARKER";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pcap")
        .join(name)
}

fn inspect(name: &str) -> Result<capture::CaptureReport, CaptureError> {
    inspect_file(&fixture(name), &CaptureLimits::default())
}

#[test]
fn reads_every_magic_and_byte_order_variant() {
    let cases = [
        (
            "le-usec.pcap",
            Endianness::Little,
            TimestampResolution::Microsecond,
            "2026-01-01T00:00:00.250000Z",
        ),
        (
            "be-usec.pcap",
            Endianness::Big,
            TimestampResolution::Microsecond,
            "2026-01-01T00:00:00.250000Z",
        ),
        (
            "le-nsec.pcap",
            Endianness::Little,
            TimestampResolution::Nanosecond,
            "2026-01-01T00:00:00.250000000Z",
        ),
        (
            "be-nsec.pcap",
            Endianness::Big,
            TimestampResolution::Nanosecond,
            "2026-01-01T00:00:00.250000000Z",
        ),
    ];
    for (name, endianness, resolution, second_ts) in cases {
        let report = inspect(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        let header = &report.summary.header;
        assert_eq!(header.endianness, endianness, "{name}");
        assert_eq!(header.timestamp_resolution, resolution, "{name}");
        assert_eq!((header.version.major, header.version.minor), (2, 4));
        assert_eq!(header.snap_length, 65_535);
        assert_eq!(header.link_type_name, Some("ETHERNET"));
        assert_eq!(report.summary.file_name, name);
        assert_eq!(report.summary.file_size_bytes, 309);
        assert_eq!(report.summary.packets_processed, 3);
        assert_eq!(report.summary.captured_bytes_total, 3 * 79);
        assert_eq!(report.completion_state, CompletionState::Complete);
        assert!(report.warnings.is_empty(), "{name}: {:?}", report.warnings);

        let ts = report.packets[1].timestamp.expect("valid timestamp");
        assert_eq!(ts.to_rfc3339(), second_ts, "{name}");
        assert_eq!(report.packets[2].file_offset, 24 + 2 * (16 + 79));
    }
}

#[test]
fn extension_check_is_case_insensitive() {
    let report = inspect("UPPERCASE-EXTENSION.PCAP").unwrap();
    assert_eq!(report.summary.packets_processed, 1);
}

#[test]
fn version_2_2_lengths_are_unswapped() {
    let report = inspect("v2-2-swapped-lengths.pcap").unwrap();
    assert_eq!(report.summary.header.version.minor, 2);
    assert_eq!(report.packets[0].captured_length, 64);
    assert_eq!(report.packets[0].original_length, 79);
    let codes: Vec<_> = report.warnings.iter().map(|w| w.code).collect();
    assert_eq!(codes, vec![WarningCode::UnusualVersionMinor]);
}

#[test]
fn header_only_capture_is_complete_and_empty() {
    let report = inspect("header-only.pcap").unwrap();
    assert_eq!(report.completion_state, CompletionState::Complete);
    assert!(report.packets.is_empty());
    assert_eq!(report.summary.earliest_timestamp, None);
}

#[test]
fn packet_limit_stops_early_without_error() {
    let limits = CaptureLimits::from_cli_units(1, 10, 60);
    let report = inspect_file(&fixture("many-packets.pcap"), &limits).unwrap();
    assert_eq!(report.completion_state, CompletionState::PacketLimitReached);
    assert_eq!(report.summary.packets_processed, 10);
    assert_eq!(report.packets.last().map(|p| p.index), Some(10));
}

#[test]
fn record_oddities_are_reported_as_warnings() {
    let report = inspect("record-warnings.pcap").unwrap();
    assert_eq!(report.summary.packets_processed, 5);
    let codes: Vec<_> = report.warnings.iter().map(|w| (w.code, w.count)).collect();
    assert_eq!(
        codes,
        vec![
            (WarningCode::CapturedLengthExceedsSnapLength, 2),
            (WarningCode::TimestampOutOfOrder, 1),
            (WarningCode::CapturedLengthExceedsOriginalLength, 1),
            (WarningCode::TimestampFractionOutOfRange, 1),
        ]
    );
    assert!(report.packets[3].timestamp.is_none());
}

#[test]
fn container_errors_have_distinct_codes() {
    let cases = [
        (
            "truncated-global-header.pcap",
            "truncated_global_header",
            ErrorCategory::Malformed,
        ),
        (
            "invalid-magic.pcap",
            "invalid_magic",
            ErrorCategory::Malformed,
        ),
        (
            "pcapng-content.pcap",
            "unsupported_format",
            ErrorCategory::Input,
        ),
        (
            "modified-pcap.pcap",
            "unsupported_format",
            ErrorCategory::Input,
        ),
        (
            "bad-version.pcap",
            "invalid_version",
            ErrorCategory::Malformed,
        ),
        (
            "zero-snaplen.pcap",
            "invalid_snap_length",
            ErrorCategory::Malformed,
        ),
        (
            "reserved-linktype-bits.pcap",
            "corrupt_global_header",
            ErrorCategory::Malformed,
        ),
        (
            "truncated-record-header.pcap",
            "truncated_record_header",
            ErrorCategory::Malformed,
        ),
        (
            "truncated-record-data.pcap",
            "truncated_record_data",
            ErrorCategory::Malformed,
        ),
        (
            "huge-captured-length.pcap",
            "unsafe_captured_length",
            ErrorCategory::Malformed,
        ),
        (
            "minimal.pcapng",
            "pcapng_not_supported",
            ErrorCategory::Input,
        ),
        ("does-not-exist.pcap", "missing_path", ErrorCategory::Input),
    ];
    for (name, code, category) in cases {
        let err = inspect(name).expect_err(name);
        assert_eq!(err.code(), code, "{name}: {err}");
        assert_eq!(err.category(), category, "{name}");
    }
}

#[test]
fn pcapng_content_is_named_in_the_error() {
    match inspect("pcapng-content.pcap") {
        Err(CaptureError::UnsupportedFormat { format }) => {
            assert_eq!(format, UnsupportedFormat::Pcapng);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn record_errors_locate_the_failing_packet() {
    match inspect("huge-captured-length.pcap") {
        Err(CaptureError::UnsafeCapturedLength {
            packet_index,
            offset,
            captured_length,
            ..
        }) => {
            assert_eq!(packet_index, 2);
            assert_eq!(offset, 24 + 16 + 79);
            assert_eq!(captured_length, 0xFFFF_FFF0);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn directory_is_not_a_file() {
    let dir = fixture("");
    assert_eq!(
        inspect_file(&dir, &CaptureLimits::default())
            .unwrap_err()
            .code(),
        "not_a_file"
    );
}

#[test]
fn serialized_reports_contain_no_payload() {
    for name in [
        "le-usec.pcap",
        "be-nsec.pcap",
        "many-packets.pcap",
        "record-warnings.pcap",
    ] {
        let report = inspect(name).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(PAYLOAD_MARKER), "{name}");
        // The documentation addresses inside the frames are not decoded yet.
        assert!(!json.contains("192.0.2."), "{name}");
    }
}
