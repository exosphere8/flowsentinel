//! Errors produced while validating and reading a capture file.
//!
//! Error messages identify the file by its sanitized name only and never
//! include bytes read from the file.

use std::io;

use serde::Serialize;

/// Broad class of a [`CaptureError`]. Front ends map each class to a distinct
/// exit code or HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// The input was rejected before or while identifying its format: wrong
    /// path, file type, extension, size or an unsupported capture format.
    Input,
    /// The file claims to be a classic PCAP file but its structure is invalid.
    Malformed,
    /// The operating system reported an I/O failure.
    Io,
}

/// A recognized capture format that FlowSentinel does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedFormat {
    /// pcapng content (Section Header Block magic).
    Pcapng,
    /// The "modified" libpcap format with extended record headers.
    ModifiedPcap,
}

impl UnsupportedFormat {
    fn description(self) -> &'static str {
        match self {
            Self::Pcapng => "the file contains pcapng data, not classic PCAP",
            Self::ModifiedPcap => "the file uses the modified libpcap record format",
        }
    }
}

/// Everything that can stop an inspection.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("file not found: {file}")]
    MissingPath { file: String },

    #[error("not a regular file: {file} (directories and special files are rejected)")]
    NotAFile { file: String },

    #[error("unsupported file extension for {file}: only .pcap files are accepted")]
    UnsupportedExtension { file: String },

    #[error(
        "{file} is a pcapng file, which is not supported yet; \
         convert it to classic PCAP first, for example `editcap -F pcap in.pcapng out.pcap`"
    )]
    PcapngNotSupported { file: String },

    #[error(
        "{file} is {size_bytes} bytes, above the {limit_bytes}-byte limit; \
         raise --max-file-size-mb only for files you trust"
    )]
    FileTooLarge {
        file: String,
        size_bytes: u64,
        limit_bytes: u64,
    },

    #[error("truncated PCAP global header: expected 24 bytes, found {available}")]
    TruncatedGlobalHeader { available: usize },

    #[error("not a classic PCAP file: the file does not start with a known PCAP magic number")]
    InvalidMagic,

    #[error("unsupported capture format: {}", format.description())]
    UnsupportedFormat { format: UnsupportedFormat },

    #[error("corrupt PCAP global header: {reason}")]
    CorruptGlobalHeader { reason: &'static str },

    #[error("unsupported PCAP version {major}.{minor}: only versions 2.0 to 2.4 are supported")]
    InvalidVersion { major: u16, minor: u16 },

    #[error("invalid PCAP global header: the snapshot length is 0")]
    InvalidSnapLength,

    #[error(
        "truncated record header for packet {packet_index} at byte offset {offset}: \
         expected 16 bytes, found {available}"
    )]
    TruncatedRecordHeader {
        packet_index: u64,
        offset: u64,
        available: usize,
    },

    #[error(
        "truncated record data for packet {packet_index} at byte offset {offset}: \
         the record header declares {expected} bytes but only {available} remain"
    )]
    TruncatedRecordData {
        packet_index: u64,
        offset: u64,
        expected: u32,
        available: u64,
    },

    #[error(
        "packet {packet_index} at byte offset {offset} declares a captured length of \
         {captured_length} bytes, above the {limit}-byte safety limit; the file is corrupt"
    )]
    UnsafeCapturedLength {
        packet_index: u64,
        offset: u64,
        captured_length: u32,
        limit: u32,
    },

    #[error("I/O error while {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

impl CaptureError {
    /// Stable, machine-readable identifier, suitable for JSON output and tests.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingPath { .. } => "missing_path",
            Self::NotAFile { .. } => "not_a_file",
            Self::UnsupportedExtension { .. } => "unsupported_extension",
            Self::PcapngNotSupported { .. } => "pcapng_not_supported",
            Self::FileTooLarge { .. } => "file_too_large",
            Self::TruncatedGlobalHeader { .. } => "truncated_global_header",
            Self::InvalidMagic => "invalid_magic",
            Self::UnsupportedFormat { .. } => "unsupported_format",
            Self::CorruptGlobalHeader { .. } => "corrupt_global_header",
            Self::InvalidVersion { .. } => "invalid_version",
            Self::InvalidSnapLength => "invalid_snap_length",
            Self::TruncatedRecordHeader { .. } => "truncated_record_header",
            Self::TruncatedRecordData { .. } => "truncated_record_data",
            Self::UnsafeCapturedLength { .. } => "unsafe_captured_length",
            Self::Io { .. } => "io_error",
        }
    }

    /// Broad class of this error.
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::MissingPath { .. }
            | Self::NotAFile { .. }
            | Self::UnsupportedExtension { .. }
            | Self::PcapngNotSupported { .. }
            | Self::FileTooLarge { .. }
            | Self::UnsupportedFormat { .. } => ErrorCategory::Input,
            Self::TruncatedGlobalHeader { .. }
            | Self::InvalidMagic
            | Self::CorruptGlobalHeader { .. }
            | Self::InvalidVersion { .. }
            | Self::InvalidSnapLength
            | Self::TruncatedRecordHeader { .. }
            | Self::TruncatedRecordData { .. }
            | Self::UnsafeCapturedLength { .. } => ErrorCategory::Malformed,
            Self::Io { .. } => ErrorCategory::Io,
        }
    }

    pub(crate) fn io(operation: &'static str) -> impl FnOnce(io::Error) -> Self {
        move |source| Self::Io { operation, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_categories_are_stable() {
        let cases = [
            (
                CaptureError::MissingPath { file: "a".into() },
                "missing_path",
                ErrorCategory::Input,
            ),
            (
                CaptureError::InvalidMagic,
                "invalid_magic",
                ErrorCategory::Malformed,
            ),
            (
                CaptureError::UnsupportedFormat {
                    format: UnsupportedFormat::Pcapng,
                },
                "unsupported_format",
                ErrorCategory::Input,
            ),
            (
                CaptureError::Io {
                    operation: "reading",
                    source: io::Error::other("boom"),
                },
                "io_error",
                ErrorCategory::Io,
            ),
        ];
        for (err, code, category) in cases {
            assert_eq!(err.code(), code);
            assert_eq!(err.category(), category);
        }
    }

    #[test]
    fn messages_are_actionable() {
        let err = CaptureError::FileTooLarge {
            file: "big.pcap".into(),
            size_bytes: 10,
            limit_bytes: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("big.pcap"));
        assert!(msg.contains("--max-file-size-mb"));
    }
}
