//! Safe, streaming reader for classic libpcap (`.pcap`) capture files.
//!
//! This crate parses only the PCAP container: the 24-byte global header and
//! the 16-byte header in front of each packet record. It never interprets
//! packet contents and never returns packet bytes in its public models.
//!
//! Safety properties:
//!
//! - Files are streamed through a fixed-size buffer; memory use does not
//!   depend on file size.
//! - No allocation is sized from a value read from the file. A record that
//!   declares more than [`MAX_SAFE_CAPTURED_LENGTH`] bytes stops the read.
//! - Every input limit ([`CaptureLimits`]) is checked before the work it
//!   bounds, and the time limit uses an injectable [`Clock`].
//! - Errors and warnings never contain bytes from the file, and file names
//!   are reduced to a sanitized final component.
//!
//! ```no_run
//! use std::path::Path;
//! use capture::{CaptureLimits, inspect_file};
//!
//! let report = inspect_file(Path::new("trace.pcap"), &CaptureLimits::default())?;
//! println!("{} packets", report.summary.packets_processed);
//! # Ok::<(), capture::CaptureError>(())
//! ```

mod error;
mod header;
mod inspect;
mod limits;
mod reader;
mod timestamp;
mod warning;

pub use error::{CaptureError, ErrorCategory, UnsupportedFormat};
pub use header::{
    Endianness, GLOBAL_HEADER_LEN, LinkType, PcapGlobalHeader, PcapVersion, TimestampResolution,
};
pub use inspect::{
    CaptureReport, CaptureSummary, CompletionState, display_file_name, inspect_file,
    inspect_file_with_clock, inspect_reader, open_capture,
};
pub use limits::{AppliedLimits, CaptureLimits, Clock, MonotonicClock};
pub use reader::{MAX_SAFE_CAPTURED_LENGTH, PacketRecordMetadata, PcapReader, RECORD_HEADER_LEN};
pub use timestamp::Timestamp;
pub use warning::{CaptureWarning, WarningCode, WarningCollector};
