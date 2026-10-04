//! Writes a classic pcap file (microsecond timestamps, little endian) and
//! computes its SHA-256 on the way.

use std::io::{self, Write};

use sha2::{Digest, Sha256};

use crate::source::SourcePacket;

/// Bytes of the file header.
pub const FILE_HEADER_LEN: u64 = 24;
/// Bytes of each record header.
pub const RECORD_HEADER_LEN: u64 = 16;

/// A pcap file being written.
pub struct PcapWriter<W: Write> {
    out: W,
    hasher: Sha256,
    bytes: u64,
    packets: u64,
}

impl<W: Write> PcapWriter<W> {
    /// Writes the file header.
    pub fn new(out: W, link_type: u32, snaplen: u32) -> io::Result<Self> {
        let mut writer = Self {
            out,
            hasher: Sha256::new(),
            bytes: 0,
            packets: 0,
        };
        let mut header = Vec::with_capacity(24);
        header.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        header.extend_from_slice(&2u16.to_le_bytes());
        header.extend_from_slice(&4u16.to_le_bytes());
        header.extend_from_slice(&0i32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&snaplen.to_le_bytes());
        header.extend_from_slice(&link_type.to_le_bytes());
        writer.put(&header)?;
        Ok(writer)
    }

    fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.out.write_all(bytes)?;
        self.hasher.update(bytes);
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    /// Bytes a record for `packet` takes.
    pub fn record_len(packet: &SourcePacket) -> u64 {
        RECORD_HEADER_LEN.saturating_add(u64::try_from(packet.data.len()).unwrap_or(u64::MAX))
    }

    /// Appends one record.
    pub fn write_packet(&mut self, packet: &SourcePacket) -> io::Result<()> {
        let captured = u32::try_from(packet.data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
        let mut header = Vec::with_capacity(16);
        header.extend_from_slice(&packet.ts_seconds.to_le_bytes());
        header.extend_from_slice(&packet.ts_micros.min(999_999).to_le_bytes());
        header.extend_from_slice(&captured.to_le_bytes());
        header.extend_from_slice(&packet.original_length.max(captured).to_le_bytes());
        self.put(&header)?;
        self.put(&packet.data)?;
        self.packets = self.packets.saturating_add(1);
        Ok(())
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn packets(&self) -> u64 {
        self.packets
    }

    /// Flushes and returns the lowercase hex SHA-256 of everything written.
    pub fn finish(mut self) -> io::Result<String> {
        self.out.flush()?;
        let digest = self.hasher.finalize();
        let mut text = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
        }
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_have_the_classic_header_and_records() {
        let mut out = Vec::new();
        let mut writer = PcapWriter::new(&mut out, 1, 65_535).unwrap();
        let packet = SourcePacket {
            ts_seconds: 1_767_225_600,
            ts_micros: 250_000,
            original_length: 60,
            data: vec![0xab; 42],
        };
        writer.write_packet(&packet).unwrap();
        assert_eq!(writer.bytes(), 24 + 16 + 42);
        assert_eq!(writer.packets(), 1);
        let sha = writer.finish().unwrap();
        assert_eq!(sha.len(), 64);
        assert_eq!(&out[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(&out[20..24], &1u32.to_le_bytes());
        assert_eq!(&out[32..36], &42u32.to_le_bytes());
        assert_eq!(&out[36..40], &60u32.to_le_bytes());
        assert_eq!(PcapWriter::<Vec<u8>>::record_len(&packet), 58);
    }
}
