//! Structured, deduplicated warnings.
//!
//! Warnings describe oddities that do not stop processing. Each distinct
//! [`WarningCode`] is reported once, with an occurrence count and the first
//! packet it was seen on, so a hostile file cannot grow the warning list.

use serde::Serialize;

/// Kind of non-fatal problem found in a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    /// The minor version is below 4; records are read with that version's
    /// historical field order.
    UnusualVersionMinor,
    /// The header's time zone field is non-zero; timestamps are shown as written.
    NonzeroTimezoneOffset,
    /// A record's captured length exceeds the file's snapshot length.
    CapturedLengthExceedsSnapLength,
    /// A record's captured length exceeds its original (on-the-wire) length.
    CapturedLengthExceedsOriginalLength,
    /// A record's fractional timestamp is out of range for the resolution.
    TimestampFractionOutOfRange,
    /// A record's timestamp is earlier than the previous record's.
    TimestampOutOfOrder,
    /// The file's size changed while it was read; only the bytes present
    /// when it was validated were read.
    FileSizeChanged,
}

impl WarningCode {
    /// Every code, for exhaustive tests and documentation.
    pub const ALL: [Self; 7] = [
        Self::UnusualVersionMinor,
        Self::NonzeroTimezoneOffset,
        Self::CapturedLengthExceedsSnapLength,
        Self::CapturedLengthExceedsOriginalLength,
        Self::TimestampFractionOutOfRange,
        Self::TimestampOutOfOrder,
        Self::FileSizeChanged,
    ];

    /// Stable snake_case identifier; identical to the serialized form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnusualVersionMinor => "unusual_version_minor",
            Self::NonzeroTimezoneOffset => "nonzero_timezone_offset",
            Self::CapturedLengthExceedsSnapLength => "captured_length_exceeds_snap_length",
            Self::CapturedLengthExceedsOriginalLength => "captured_length_exceeds_original_length",
            Self::TimestampFractionOutOfRange => "timestamp_fraction_out_of_range",
            Self::TimestampOutOfOrder => "timestamp_out_of_order",
            Self::FileSizeChanged => "file_size_changed",
        }
    }

    /// One-sentence explanation shown to users.
    pub fn message(self) -> &'static str {
        match self {
            Self::UnusualVersionMinor => {
                "the PCAP minor version is below 4; record lengths are read in that version's historical order"
            }
            Self::NonzeroTimezoneOffset => {
                "the global header declares a non-zero time zone offset; timestamps are shown as written"
            }
            Self::CapturedLengthExceedsSnapLength => {
                "a record's captured length exceeds the file's snapshot length"
            }
            Self::CapturedLengthExceedsOriginalLength => {
                "a record's captured length exceeds its original length"
            }
            Self::TimestampFractionOutOfRange => {
                "a record's fractional timestamp is out of range; its timestamp is reported as null"
            }
            Self::TimestampOutOfOrder => {
                "a record's timestamp is earlier than the previous record's"
            }
            Self::FileSizeChanged => {
                "the file changed size while it was read; only the bytes present at validation were read"
            }
        }
    }
}

/// A deduplicated warning with its occurrence count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureWarning {
    pub code: WarningCode,
    pub message: &'static str,
    /// How many times this condition occurred.
    pub count: u64,
    /// 1-based index of the first packet that triggered it, if packet-specific.
    pub first_packet_index: Option<u64>,
}

/// Collects warnings, keeping one entry per [`WarningCode`].
#[derive(Debug, Default, Clone)]
pub struct WarningCollector {
    entries: Vec<CaptureWarning>,
}

impl WarningCollector {
    /// Records one occurrence of `code`.
    pub fn add(&mut self, code: WarningCode, packet_index: Option<u64>) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.code == code) {
            entry.count = entry.count.saturating_add(1);
            if entry.first_packet_index.is_none() {
                entry.first_packet_index = packet_index;
            }
        } else {
            self.entries.push(CaptureWarning {
                code,
                message: code.message(),
                count: 1,
                first_packet_index: packet_index,
            });
        }
    }

    /// Warnings in the order they were first seen.
    pub fn as_slice(&self) -> &[CaptureWarning] {
        &self.entries
    }

    /// Consumes the collector and returns its warnings.
    pub fn into_vec(self) -> Vec<CaptureWarning> {
        self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_codes_are_deduplicated_and_counted() {
        let mut collector = WarningCollector::default();
        collector.add(WarningCode::TimestampOutOfOrder, Some(4));
        collector.add(WarningCode::CapturedLengthExceedsSnapLength, Some(5));
        collector.add(WarningCode::TimestampOutOfOrder, Some(9));
        let warnings = collector.into_vec();
        assert_eq!(warnings.len(), 2);
        assert_eq!(warnings[0].code, WarningCode::TimestampOutOfOrder);
        assert_eq!(warnings[0].count, 2);
        assert_eq!(warnings[0].first_packet_index, Some(4));
        assert_eq!(warnings[1].count, 1);
    }

    #[test]
    fn as_str_matches_serialized_form() {
        for code in WarningCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
        }
    }

    #[test]
    fn serializes_as_snake_case() {
        let mut collector = WarningCollector::default();
        collector.add(WarningCode::NonzeroTimezoneOffset, None);
        let json = serde_json::to_string(collector.as_slice()).unwrap();
        assert!(json.contains(r#""code":"nonzero_timezone_offset""#));
        assert!(json.contains(r#""first_packet_index":null"#));
    }
}
