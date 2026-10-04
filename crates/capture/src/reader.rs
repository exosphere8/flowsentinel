//! Streaming reader for classic PCAP record headers.
//!
//! The reader pulls bytes from any [`BufRead`] source, so memory use does not
//! depend on file size. [`PcapReader::next_record`] reads past packet data and
//! discards it. [`PcapReader::next_packet`] copies at most
//! [`MAX_PACKET_DATA_BYTES`] of it into a caller-owned, reusable buffer so a
//! decoder can examine it transiently; nothing is retained by the reader.

use std::io::{self, BufRead, Read};

use serde::Serialize;

use crate::error::CaptureError;
use crate::header::{GLOBAL_HEADER_LEN, LengthFieldOrder, LinkType, PcapGlobalHeader, field};
use crate::timestamp::Timestamp;
use crate::warning::{CaptureWarning, WarningCode, WarningCollector};

/// Size of a record header in bytes.
pub const RECORD_HEADER_LEN: usize = 16;

/// Largest captured length a record may declare for most link types. This is
/// libpcap's own maximum snapshot length; anything larger indicates
/// corruption, so the reader stops instead of trusting the length. A few link
/// types allow more; see [`LinkType::max_captured_length`].
pub const MAX_SAFE_CAPTURED_LENGTH: u32 = LinkType::DEFAULT_MAX_CAPTURED_LENGTH;

/// Most bytes of one record that [`PcapReader::next_packet`] hands out. Any
/// remainder (possible only for link types with larger maximums) is skipped.
pub const MAX_PACKET_DATA_BYTES: u32 = LinkType::DEFAULT_MAX_CAPTURED_LENGTH;

/// Metadata of one packet record. Contains no packet bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PacketRecordMetadata {
    /// 1-based position in the file, matching Wireshark's frame numbers.
    pub index: u64,
    /// Byte offset of the record header from the start of the file.
    pub file_offset: u64,
    /// `None` when the record's fractional timestamp is out of range.
    pub timestamp: Option<Timestamp>,
    /// Bytes of the packet saved in the file.
    pub captured_length: u32,
    /// Length of the packet on the wire.
    pub original_length: u32,
}

/// Reads a classic PCAP stream one record at a time.
#[derive(Debug)]
pub struct PcapReader<R> {
    source: R,
    header: PcapGlobalHeader,
    /// Bytes consumed from the start of the stream.
    offset: u64,
    records_read: u64,
    previous_timestamp: Option<Timestamp>,
    warnings: WarningCollector,
}

impl<R: BufRead> PcapReader<R> {
    /// Reads and validates the global header.
    pub fn new(mut source: R) -> Result<Self, CaptureError> {
        let mut buf = [0u8; GLOBAL_HEADER_LEN];
        let available = read_up_to(&mut source, &mut buf)
            .map_err(CaptureError::io("reading the PCAP global header"))?;
        let (header, header_warnings) =
            PcapGlobalHeader::parse(buf.get(..available).unwrap_or(&[]))?;

        let mut warnings = WarningCollector::default();
        for code in header_warnings {
            warnings.add(code, None);
        }
        Ok(Self {
            source,
            header,
            offset: GLOBAL_HEADER_LEN as u64,
            records_read: 0,
            previous_timestamp: None,
            warnings,
        })
    }

    /// The validated global header.
    pub fn header(&self) -> &PcapGlobalHeader {
        &self.header
    }

    /// Warnings collected so far.
    pub fn warnings(&self) -> &[CaptureWarning] {
        self.warnings.as_slice()
    }

    /// Consumes the reader and returns its warnings.
    pub fn into_warnings(self) -> Vec<CaptureWarning> {
        self.warnings.into_vec()
    }

    /// Number of complete records read.
    pub fn records_read(&self) -> u64 {
        self.records_read
    }

    /// Returns `true` if no bytes remain. Does not consume anything, which
    /// lets callers tell "stopped at a limit" apart from "reached the end".
    pub fn at_eof(&mut self) -> Result<bool, CaptureError> {
        loop {
            match self.source.fill_buf() {
                Ok(buf) => return Ok(buf.is_empty()),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(CaptureError::io("reading the capture")(err)),
            }
        }
    }

    /// Reads the next record header and skips its packet data.
    ///
    /// Returns `Ok(None)` at a clean end of file (no bytes after the previous
    /// record).
    pub fn next_record(&mut self) -> Result<Option<PacketRecordMetadata>, CaptureError> {
        self.read_record(None)
    }

    /// Reads the next record and replaces the contents of `data` with its
    /// captured bytes, up to [`MAX_PACKET_DATA_BYTES`]. Reusing one buffer
    /// across calls keeps allocation bounded by the largest record seen.
    ///
    /// On error, `data` holds an unspecified partial record.
    pub fn next_packet(
        &mut self,
        data: &mut Vec<u8>,
    ) -> Result<Option<PacketRecordMetadata>, CaptureError> {
        self.read_record(Some(data))
    }

    fn read_record(
        &mut self,
        data: Option<&mut Vec<u8>>,
    ) -> Result<Option<PacketRecordMetadata>, CaptureError> {
        let index = self.records_read.saturating_add(1);
        let file_offset = self.offset;

        let mut raw = [0u8; RECORD_HEADER_LEN];
        let available = read_up_to(&mut self.source, &mut raw)
            .map_err(CaptureError::io("reading a record header"))?;
        if available == 0 {
            return Ok(None);
        }
        if available < RECORD_HEADER_LEN {
            return Err(CaptureError::TruncatedRecordHeader {
                packet_index: index,
                offset: file_offset,
                available,
            });
        }
        self.offset = self.offset.saturating_add(RECORD_HEADER_LEN as u64);

        let endianness = self.header.endianness;
        let u32_at = |offset| field(&raw, offset).map(|b| endianness.u32(b)).unwrap_or(0);
        let (ts_seconds, ts_fraction) = (u32_at(0), u32_at(4));
        let (mut captured_length, mut original_length) = (u32_at(8), u32_at(12));
        let swap = match self.header.length_field_order() {
            LengthFieldOrder::Normal => false,
            LengthFieldOrder::Swapped => true,
            LengthFieldOrder::MaybeSwapped => captured_length > original_length,
        };
        if swap {
            std::mem::swap(&mut captured_length, &mut original_length);
        }

        // Validate the length before acting on it; never trust it for allocation.
        let limit = self.header.link_type.max_captured_length();
        if captured_length > limit {
            return Err(CaptureError::UnsafeCapturedLength {
                packet_index: index,
                offset: file_offset,
                captured_length,
                limit,
            });
        }

        let expected = u64::from(captured_length);
        let consumed = self
            .consume_data(expected, data)
            .map_err(CaptureError::io("reading packet data"))?;
        self.offset = self.offset.saturating_add(consumed);
        if consumed < expected {
            return Err(CaptureError::TruncatedRecordData {
                packet_index: index,
                offset: file_offset,
                expected: captured_length,
                available: consumed,
            });
        }

        if captured_length > self.header.snap_length {
            self.warnings
                .add(WarningCode::CapturedLengthExceedsSnapLength, Some(index));
        }
        if captured_length > original_length {
            self.warnings.add(
                WarningCode::CapturedLengthExceedsOriginalLength,
                Some(index),
            );
        }
        let timestamp =
            Timestamp::from_record(ts_seconds, ts_fraction, self.header.timestamp_resolution);
        match timestamp {
            None => self
                .warnings
                .add(WarningCode::TimestampFractionOutOfRange, Some(index)),
            Some(ts) => {
                if self.previous_timestamp.is_some_and(|prev| ts < prev) {
                    self.warnings
                        .add(WarningCode::TimestampOutOfOrder, Some(index));
                }
                self.previous_timestamp = Some(ts);
            }
        }

        self.records_read = index;
        Ok(Some(PacketRecordMetadata {
            index,
            file_offset,
            timestamp,
            captured_length,
            original_length,
        }))
    }

    /// Consumes `len` bytes of packet data, copying up to
    /// [`MAX_PACKET_DATA_BYTES`] of them into `keep` if given. Returns the
    /// number of bytes consumed, which is less than `len` only at end of input.
    fn consume_data(&mut self, len: u64, keep: Option<&mut Vec<u8>>) -> io::Result<u64> {
        let mut consumed = 0;
        if let Some(buf) = keep {
            buf.clear();
            let wanted = len.min(u64::from(MAX_PACKET_DATA_BYTES));
            let kept = (&mut self.source).take(wanted).read_to_end(buf)?;
            consumed = u64::try_from(kept).unwrap_or(u64::MAX);
            if consumed < wanted {
                return Ok(consumed);
            }
        }
        let rest = len.saturating_sub(consumed);
        let skipped = io::copy(&mut (&mut self.source).take(rest), &mut io::sink())?;
        Ok(consumed.saturating_add(skipped))
    }
}

/// Fills `buf` as far as the source allows. Returns the number of bytes read,
/// which is less than `buf.len()` only at end of input.
fn read_up_to<R: Read>(source: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while let Some(rest) = buf.get_mut(filled..) {
        if rest.is_empty() {
            break;
        }
        match source.read(rest) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::header::{Endianness, TimestampResolution};

    fn global_header(big: bool, nanos: bool, snap: u32) -> Vec<u8> {
        let magic: u32 = if nanos { 0xA1B2_3C4D } else { 0xA1B2_C3D4 };
        let u32b = |v: u32| {
            if big {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let u16b = |v: u16| {
            if big {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut out = Vec::new();
        out.extend(u32b(magic));
        out.extend(u16b(2));
        out.extend(u16b(4));
        out.extend(u32b(0));
        out.extend(u32b(0));
        out.extend(u32b(snap));
        out.extend(u32b(1));
        out
    }

    fn record(big: bool, sec: u32, frac: u32, data_len: u32, orig: u32) -> Vec<u8> {
        let mut out = Vec::new();
        for value in [sec, frac, data_len, orig] {
            out.extend(if big {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            });
        }
        out.extend(std::iter::repeat_n(0xAB, data_len as usize));
        out
    }

    fn reader(bytes: Vec<u8>) -> PcapReader<Cursor<Vec<u8>>> {
        PcapReader::new(Cursor::new(bytes)).unwrap()
    }

    #[test]
    fn record_metadata_stays_compact() {
        // Documented as 40 bytes per retained record.
        assert!(std::mem::size_of::<PacketRecordMetadata>() <= 40);
    }

    #[test]
    fn reads_records_in_both_byte_orders() {
        for big in [false, true] {
            let mut bytes = global_header(big, false, 65535);
            bytes.extend(record(big, 100, 5, 60, 60));
            bytes.extend(record(big, 101, 0, 10, 1500));
            let mut r = reader(bytes);
            assert_eq!(
                r.header().endianness,
                if big {
                    Endianness::Big
                } else {
                    Endianness::Little
                }
            );

            let first = r.next_record().unwrap().unwrap();
            assert_eq!(first.index, 1);
            assert_eq!(first.file_offset, 24);
            assert_eq!(first.captured_length, 60);
            assert_eq!(first.timestamp.unwrap().nanos(), 5_000);

            let second = r.next_record().unwrap().unwrap();
            assert_eq!(second.index, 2);
            assert_eq!(second.file_offset, 24 + 16 + 60);
            assert_eq!(second.original_length, 1500);

            assert!(r.next_record().unwrap().is_none());
            assert_eq!(r.records_read(), 2);
            assert!(r.warnings().is_empty());
        }
    }

    #[test]
    fn next_packet_hands_out_record_bytes() {
        let mut bytes = global_header(false, false, 65535);
        bytes.extend(record(false, 1, 0, 6, 6));
        bytes.extend(record(false, 2, 0, 3, 3));
        let mut r = reader(bytes);
        let mut data = Vec::new();
        let first = r.next_packet(&mut data).unwrap().unwrap();
        assert_eq!(first.captured_length, 6);
        assert_eq!(data, vec![0xAB; 6]);
        r.next_packet(&mut data).unwrap().unwrap();
        assert_eq!(data, vec![0xAB; 3], "buffer is replaced, not appended");
        assert!(r.next_packet(&mut data).unwrap().is_none());
    }

    #[test]
    fn next_packet_caps_handed_out_bytes_and_skips_the_rest() {
        let len = MAX_PACKET_DATA_BYTES + 1000;
        let mut bytes = global_header(false, false, 65535);
        bytes[20..24].copy_from_slice(&u32::from(LinkType::USBPCAP.0).to_le_bytes());
        bytes.extend(record(false, 1, 0, len, len));
        bytes.extend(record(false, 2, 0, 4, 4));
        let mut r = reader(bytes);
        let mut data = Vec::new();
        assert_eq!(
            r.next_packet(&mut data).unwrap().unwrap().captured_length,
            len
        );
        assert_eq!(data.len(), MAX_PACKET_DATA_BYTES as usize);
        let second = r.next_packet(&mut data).unwrap().unwrap();
        assert_eq!(second.file_offset, 24 + 16 + u64::from(len));
        assert_eq!(data.len(), 4);
    }

    #[test]
    fn next_packet_reports_truncated_data() {
        let mut bytes = global_header(false, false, 65535);
        let mut rec = record(false, 1, 0, 100, 100);
        rec.truncate(16 + 30);
        bytes.extend(rec);
        let mut data = Vec::new();
        assert!(matches!(
            reader(bytes).next_packet(&mut data),
            Err(CaptureError::TruncatedRecordData { available: 30, .. })
        ));
    }

    #[test]
    fn nanosecond_files_keep_nanosecond_fractions() {
        let mut bytes = global_header(false, true, 65535);
        bytes.extend(record(false, 7, 123_456_789, 4, 4));
        let mut r = reader(bytes);
        assert_eq!(
            r.header().timestamp_resolution,
            TimestampResolution::Nanosecond
        );
        let ts = r.next_record().unwrap().unwrap().timestamp.unwrap();
        assert_eq!(ts.nanos(), 123_456_789);
    }

    #[test]
    fn eof_probe_does_not_consume() {
        let mut bytes = global_header(false, false, 65535);
        bytes.extend(record(false, 1, 0, 4, 4));
        let mut r = reader(bytes);
        assert!(!r.at_eof().unwrap());
        assert!(!r.at_eof().unwrap());
        assert!(r.next_record().unwrap().is_some());
        assert!(r.at_eof().unwrap());
    }

    #[test]
    fn partial_record_header_is_an_error() {
        let mut bytes = global_header(false, false, 65535);
        bytes.extend(record(false, 1, 0, 4, 4));
        bytes.extend([1, 2, 3, 4, 5]);
        let mut r = reader(bytes);
        r.next_record().unwrap();
        match r.next_record() {
            Err(CaptureError::TruncatedRecordHeader {
                packet_index,
                offset,
                available,
            }) => {
                assert_eq!((packet_index, offset, available), (2, 44, 5));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn short_record_data_is_an_error() {
        let mut bytes = global_header(false, false, 65535);
        let mut rec = record(false, 1, 0, 100, 100);
        rec.truncate(16 + 30);
        bytes.extend(rec);
        let mut r = reader(bytes);
        match r.next_record() {
            Err(CaptureError::TruncatedRecordData {
                expected,
                available,
                ..
            }) => assert_eq!((expected, available), (100, 30)),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn huge_length_claim_is_rejected_without_reading_or_allocating() {
        for claim in [MAX_SAFE_CAPTURED_LENGTH + 1, u32::MAX] {
            let mut bytes = global_header(true, false, 65535);
            bytes.extend(record(true, 1, 0, 0, 0));
            // Patch the captured length of the (empty) record.
            bytes[24 + 8..24 + 12].copy_from_slice(&claim.to_be_bytes());
            let mut r = reader(bytes);
            match r.next_record() {
                Err(CaptureError::UnsafeCapturedLength {
                    captured_length, ..
                }) => assert_eq!(captured_length, claim),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    fn header_with(minor: u16, link_type: u32) -> Vec<u8> {
        let mut bytes = global_header(false, false, 65535);
        bytes[6..8].copy_from_slice(&minor.to_le_bytes());
        bytes[20..24].copy_from_slice(&link_type.to_le_bytes());
        bytes
    }

    #[test]
    fn versions_before_2_3_have_swapped_length_fields() {
        // On disk: "captured" field holds 1500 (original), "original" holds 8.
        let mut bytes = header_with(2, 1);
        for value in [1u32, 0, 1500, 8] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend([0u8; 8]);
        let mut r = reader(bytes);
        let rec = r.next_record().unwrap().unwrap();
        assert_eq!((rec.captured_length, rec.original_length), (8, 1500));
        assert!(r.next_record().unwrap().is_none());
    }

    #[test]
    fn version_2_3_swaps_only_when_lengths_are_inverted() {
        let mut bytes = header_with(3, 1);
        // Already in normal order: captured 8 <= original 1500.
        for value in [1u32, 0, 8, 1500] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend([0u8; 8]);
        // Inverted: captured field 1500 > original field 4, so swap.
        for value in [2u32, 0, 1500, 4] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend([0u8; 4]);
        let mut r = reader(bytes);
        let first = r.next_record().unwrap().unwrap();
        assert_eq!((first.captured_length, first.original_length), (8, 1500));
        let second = r.next_record().unwrap().unwrap();
        assert_eq!((second.captured_length, second.original_length), (4, 1500));
    }

    #[test]
    fn larger_captures_are_allowed_for_link_types_that_need_them() {
        let len = 300_000u32;
        let mut ethernet = header_with(4, 1);
        ethernet.extend(record(false, 1, 0, len, len));
        assert!(matches!(
            reader(ethernet).next_record(),
            Err(CaptureError::UnsafeCapturedLength { limit: 262_144, .. })
        ));

        let mut usb = header_with(4, u32::from(LinkType::USBPCAP.0));
        usb.extend(record(false, 1, 0, len, len));
        assert_eq!(
            reader(usb).next_record().unwrap().unwrap().captured_length,
            len
        );
    }

    #[test]
    fn largest_safe_length_is_accepted() {
        let mut bytes = global_header(false, false, MAX_SAFE_CAPTURED_LENGTH);
        bytes.extend(record(
            false,
            1,
            0,
            MAX_SAFE_CAPTURED_LENGTH,
            MAX_SAFE_CAPTURED_LENGTH,
        ));
        let mut r = reader(bytes);
        let rec = r.next_record().unwrap().unwrap();
        assert_eq!(rec.captured_length, MAX_SAFE_CAPTURED_LENGTH);
        assert!(r.warnings().is_empty());
    }

    #[test]
    fn record_oddities_become_deduplicated_warnings() {
        let mut bytes = global_header(false, false, 50);
        bytes.extend(record(false, 10, 0, 60, 60)); // > snaplen
        bytes.extend(record(false, 5, 0, 40, 30)); // out of order, > original
        bytes.extend(record(false, 11, 1_000_000, 4, 4)); // bad fraction
        bytes.extend(record(false, 12, 0, 70, 70)); // > snaplen again
        let mut r = reader(bytes);
        let mut records = Vec::new();
        while let Some(rec) = r.next_record().unwrap() {
            records.push(rec);
        }
        assert_eq!(records.len(), 4);
        assert!(records[2].timestamp.is_none());

        let warnings = r.into_warnings();
        let summary: Vec<_> = warnings
            .iter()
            .map(|w| (w.code, w.count, w.first_packet_index))
            .collect();
        assert_eq!(
            summary,
            vec![
                (WarningCode::CapturedLengthExceedsSnapLength, 2, Some(1)),
                (WarningCode::CapturedLengthExceedsOriginalLength, 1, Some(2)),
                (WarningCode::TimestampOutOfOrder, 1, Some(2)),
                (WarningCode::TimestampFractionOutOfRange, 1, Some(3)),
            ]
        );
    }

    #[test]
    fn interrupted_reads_are_retried() {
        struct Flaky {
            inner: Cursor<Vec<u8>>,
            interrupt_next: bool,
        }
        impl Read for Flaky {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.interrupt_next = !self.interrupt_next;
                if self.interrupt_next {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                // Return at most 3 bytes per call to exercise short reads.
                let len = buf.len().min(3);
                self.inner.read(&mut buf[..len])
            }
        }
        let mut bytes = global_header(false, false, 65535);
        bytes.extend(record(false, 1, 0, 9, 9));
        let flaky = Flaky {
            inner: Cursor::new(bytes),
            interrupt_next: false,
        };
        let mut r = PcapReader::new(io::BufReader::with_capacity(4, flaky)).unwrap();
        assert_eq!(r.next_record().unwrap().unwrap().captured_length, 9);
        assert!(r.next_record().unwrap().is_none());
    }
}
