//! The 24-byte classic PCAP global header.
//!
//! Layout (all fields in the byte order announced by the magic number):
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 4 | magic number |
//! | 4 | 2 | major version |
//! | 6 | 2 | minor version |
//! | 8 | 4 | time zone offset (`thiszone`, normally 0) |
//! | 12 | 4 | timestamp accuracy (`sigfigs`, normally 0) |
//! | 16 | 4 | snapshot length |
//! | 20 | 4 | link-layer type plus FCS information |

use serde::Serialize;

use crate::error::{CaptureError, UnsupportedFormat};
use crate::warning::WarningCode;

/// Size of the global header in bytes.
pub const GLOBAL_HEADER_LEN: usize = 24;

const MAGIC_MICROS: u32 = 0xA1B2_C3D4;
const MAGIC_NANOS: u32 = 0xA1B2_3C4D;
const MAGIC_MODIFIED: u32 = 0xA1B2_CD34;
/// pcapng Section Header Block type. It reads the same in both byte orders.
const MAGIC_PCAPNG: u32 = 0x0A0D_0D0A;

// Link-type field layout, as defined by libpcap (`pcap-common.h`).
const LINK_TYPE_MASK: u32 = 0x0000_FFFF;
const LINK_TYPE_RESERVED_MASK: u32 = 0x03FF_0000;
const FCS_PRESENT_FLAG: u32 = 0x0400_0000;
const FCS_LENGTH_SHIFT: u32 = 28;

/// Byte order of every multi-byte field in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    Little,
    Big,
}

impl Endianness {
    pub(crate) fn u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }

    pub(crate) fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }

    /// Human-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Little => "little-endian",
            Self::Big => "big-endian",
        }
    }
}

/// Unit of the fractional part of each record timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampResolution {
    Microsecond,
    Nanosecond,
}

impl TimestampResolution {
    /// Number of fractional units in one second.
    pub fn units_per_second(self) -> u32 {
        match self {
            Self::Microsecond => 1_000_000,
            Self::Nanosecond => 1_000_000_000,
        }
    }

    /// Human-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Microsecond => "microsecond",
            Self::Nanosecond => "nanosecond",
        }
    }
}

/// PCAP format version from the global header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PcapVersion {
    pub major: u16,
    pub minor: u16,
}

/// Link-layer header type (a LINKTYPE_* value from tcpdump.org).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct LinkType(pub u16);

impl LinkType {
    pub const NULL: Self = Self(0);
    pub const ETHERNET: Self = Self(1);
    pub const RAW: Self = Self(101);
    pub const IEEE802_11: Self = Self(105);
    pub const LOOP: Self = Self(108);
    pub const LINUX_SLL: Self = Self(113);
    pub const IEEE802_11_RADIOTAP: Self = Self(127);
    pub const LINUX_SLL2: Self = Self(276);

    pub const DBUS: Self = Self(231);
    pub const USBPCAP: Self = Self(249);
    pub const EBHSCR: Self = Self(279);

    /// Default largest captured length a record may declare: libpcap's
    /// `MAXIMUM_SNAPLEN`.
    pub const DEFAULT_MAX_CAPTURED_LENGTH: u32 = 262_144;

    /// Largest captured length a record of this link type may declare,
    /// mirroring libpcap's `max_snaplen_for_dlt`. Larger claims indicate a
    /// corrupt file.
    pub fn max_captured_length(self) -> u32 {
        match self {
            Self::DBUS => 128 * 1024 * 1024,
            Self::EBHSCR => 8 * 1024 * 1024,
            Self::USBPCAP => 1024 * 1024,
            _ => Self::DEFAULT_MAX_CAPTURED_LENGTH,
        }
    }

    /// The LINKTYPE_* name, when the value is one FlowSentinel recognizes.
    pub fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::NULL => "NULL",
            Self::ETHERNET => "ETHERNET",
            Self::RAW => "RAW",
            Self::IEEE802_11 => "IEEE802_11",
            Self::LOOP => "LOOP",
            Self::LINUX_SLL => "LINUX_SLL",
            Self::IEEE802_11_RADIOTAP => "IEEE802_11_RADIOTAP",
            Self::LINUX_SLL2 => "LINUX_SLL2",
            Self::DBUS => "DBUS",
            Self::USBPCAP => "USBPCAP",
            Self::EBHSCR => "EBHSCR",
            _ => return None,
        })
    }
}

/// Parsed and validated PCAP global header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PcapGlobalHeader {
    pub version: PcapVersion,
    pub endianness: Endianness,
    pub timestamp_resolution: TimestampResolution,
    /// Offset of record timestamps from UTC in seconds. Almost always 0;
    /// FlowSentinel reports timestamps as written and warns otherwise.
    pub timezone_offset_seconds: i32,
    /// Maximum number of bytes the capturing tool saved per packet.
    pub snap_length: u32,
    pub link_type: LinkType,
    /// Name of `link_type`, if recognized.
    pub link_type_name: Option<&'static str>,
    /// Length of the frame check sequence at the end of each packet, when the
    /// header declares one.
    pub fcs_length_bytes: Option<u8>,
}

/// How the captured-length and original-length record fields are ordered.
///
/// Writers of format versions before 2.3 stored them swapped; version 2.3
/// files exist in both orders. This mirrors libpcap's `sf-pcap.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LengthFieldOrder {
    Normal,
    Swapped,
    /// Swapped when the captured length exceeds the original length.
    MaybeSwapped,
}

impl PcapGlobalHeader {
    /// Highest supported minor version.
    pub const MAX_VERSION_MINOR: u16 = 4;

    pub(crate) fn length_field_order(&self) -> LengthFieldOrder {
        match self.version.minor {
            0..=2 => LengthFieldOrder::Swapped,
            3 => LengthFieldOrder::MaybeSwapped,
            _ => LengthFieldOrder::Normal,
        }
    }

    /// Parses a global header from the first bytes of a file.
    ///
    /// `bytes` holds whatever could be read, up to [`GLOBAL_HEADER_LEN`]. As
    /// soon as 4 bytes are available the magic number is checked before the
    /// length, so a short non-PCAP file reports "not a PCAP file" rather than
    /// "truncated".
    pub fn parse(bytes: &[u8]) -> Result<(Self, Vec<WarningCode>), CaptureError> {
        let too_short = || CaptureError::TruncatedGlobalHeader {
            available: bytes.len(),
        };
        let magic: [u8; 4] = field(bytes, 0).ok_or_else(too_short)?;
        let (endianness, timestamp_resolution) = identify_magic(magic)?;
        if bytes.len() < GLOBAL_HEADER_LEN {
            return Err(too_short());
        }

        let u16_at = |offset| field(bytes, offset).map(|b| endianness.u16(b));
        let u32_at = |offset| field(bytes, offset).map(|b| endianness.u32(b));
        let (Some(major), Some(minor), Some(thiszone), Some(snap_length), Some(link_field)) =
            (u16_at(4), u16_at(6), u32_at(8), u32_at(16), u32_at(20))
        else {
            return Err(too_short());
        };

        if major != 2 || minor > Self::MAX_VERSION_MINOR {
            return Err(CaptureError::InvalidVersion { major, minor });
        }
        if snap_length == 0 {
            return Err(CaptureError::InvalidSnapLength);
        }
        if link_field & LINK_TYPE_RESERVED_MASK != 0 {
            return Err(CaptureError::CorruptGlobalHeader {
                reason: "reserved bits in the link-type field are set",
            });
        }

        // The mask keeps only the low 16 bits, so the conversion cannot fail.
        let link_type = LinkType(u16::try_from(link_field & LINK_TYPE_MASK).unwrap_or(u16::MAX));
        let fcs_length_bytes = (link_field & FCS_PRESENT_FLAG != 0).then(|| {
            // The FCS length is stored in 16-bit units in the top four bits.
            let words = u8::try_from(link_field >> FCS_LENGTH_SHIFT).unwrap_or(0);
            words.saturating_mul(2)
        });
        // Reinterpret the two's-complement bits of the signed `thiszone` field.
        let timezone_offset_seconds = i32::from_ne_bytes(thiszone.to_ne_bytes());

        let mut warnings = Vec::new();
        if minor != 4 {
            warnings.push(WarningCode::UnusualVersionMinor);
        }
        if timezone_offset_seconds != 0 {
            warnings.push(WarningCode::NonzeroTimezoneOffset);
        }

        let header = Self {
            version: PcapVersion { major, minor },
            endianness,
            timestamp_resolution,
            timezone_offset_seconds,
            snap_length,
            link_type,
            link_type_name: link_type.name(),
            fcs_length_bytes,
        };
        Ok((header, warnings))
    }
}

fn identify_magic(magic: [u8; 4]) -> Result<(Endianness, TimestampResolution), CaptureError> {
    let le = u32::from_le_bytes(magic);
    let be = u32::from_be_bytes(magic);
    for (value, endianness) in [(le, Endianness::Little), (be, Endianness::Big)] {
        match value {
            MAGIC_MICROS => return Ok((endianness, TimestampResolution::Microsecond)),
            MAGIC_NANOS => return Ok((endianness, TimestampResolution::Nanosecond)),
            MAGIC_MODIFIED => {
                return Err(CaptureError::UnsupportedFormat {
                    format: UnsupportedFormat::ModifiedPcap,
                });
            }
            MAGIC_PCAPNG => {
                return Err(CaptureError::UnsupportedFormat {
                    format: UnsupportedFormat::Pcapng,
                });
            }
            _ => {}
        }
    }
    Err(CaptureError::InvalidMagic)
}

/// Copies `N` bytes starting at `offset`, or returns `None` if out of bounds.
pub(crate) fn field<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    bytes.get(offset..end)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(
        magic: u32,
        big: bool,
        major: u16,
        minor: u16,
        zone: i32,
        snap: u32,
        link: u32,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        if big {
            out.extend(magic.to_be_bytes());
            out.extend(major.to_be_bytes());
            out.extend(minor.to_be_bytes());
            out.extend(zone.to_be_bytes());
            out.extend(0u32.to_be_bytes());
            out.extend(snap.to_be_bytes());
            out.extend(link.to_be_bytes());
        } else {
            out.extend(magic.to_le_bytes());
            out.extend(major.to_le_bytes());
            out.extend(minor.to_le_bytes());
            out.extend(zone.to_le_bytes());
            out.extend(0u32.to_le_bytes());
            out.extend(snap.to_le_bytes());
            out.extend(link.to_le_bytes());
        }
        out
    }

    fn standard(magic: u32, big: bool) -> Vec<u8> {
        header(magic, big, 2, 4, 0, 65535, 1)
    }

    #[test]
    fn parses_all_supported_magic_variants() {
        let cases = [
            (
                MAGIC_MICROS,
                false,
                Endianness::Little,
                TimestampResolution::Microsecond,
            ),
            (
                MAGIC_MICROS,
                true,
                Endianness::Big,
                TimestampResolution::Microsecond,
            ),
            (
                MAGIC_NANOS,
                false,
                Endianness::Little,
                TimestampResolution::Nanosecond,
            ),
            (
                MAGIC_NANOS,
                true,
                Endianness::Big,
                TimestampResolution::Nanosecond,
            ),
        ];
        for (magic, big, endianness, resolution) in cases {
            let (parsed, warnings) = PcapGlobalHeader::parse(&standard(magic, big)).unwrap();
            assert_eq!(parsed.endianness, endianness);
            assert_eq!(parsed.timestamp_resolution, resolution);
            assert_eq!(parsed.version, PcapVersion { major: 2, minor: 4 });
            assert_eq!(parsed.snap_length, 65535);
            assert_eq!(parsed.link_type, LinkType::ETHERNET);
            assert_eq!(parsed.link_type_name, Some("ETHERNET"));
            assert_eq!(parsed.fcs_length_bytes, None);
            assert!(warnings.is_empty());
        }
    }

    #[test]
    fn rejects_unknown_magic() {
        let mut bytes = standard(MAGIC_MICROS, false);
        bytes[..4].copy_from_slice(b"NOTA");
        assert!(matches!(
            PcapGlobalHeader::parse(&bytes),
            Err(CaptureError::InvalidMagic)
        ));
    }

    #[test]
    fn short_non_pcap_input_reports_invalid_magic() {
        assert!(matches!(
            PcapGlobalHeader::parse(b"hello"),
            Err(CaptureError::InvalidMagic)
        ));
        // Fewer than 4 bytes cannot be identified at all.
        assert!(matches!(
            PcapGlobalHeader::parse(b"abc"),
            Err(CaptureError::TruncatedGlobalHeader { available: 3 })
        ));
    }

    #[test]
    fn identifies_pcapng_and_modified_formats() {
        for big in [false, true] {
            assert!(matches!(
                PcapGlobalHeader::parse(&standard(MAGIC_PCAPNG, big)),
                Err(CaptureError::UnsupportedFormat {
                    format: UnsupportedFormat::Pcapng
                })
            ));
            assert!(matches!(
                PcapGlobalHeader::parse(&standard(MAGIC_MODIFIED, big)),
                Err(CaptureError::UnsupportedFormat {
                    format: UnsupportedFormat::ModifiedPcap
                })
            ));
        }
    }

    #[test]
    fn truncated_header_reports_available_bytes() {
        let bytes = standard(MAGIC_MICROS, false);
        for len in [0, 3, 4, 23] {
            match PcapGlobalHeader::parse(&bytes[..len]) {
                Err(CaptureError::TruncatedGlobalHeader { available }) => {
                    assert_eq!(available, len)
                }
                other => panic!("length {len}: unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_wrong_major_version() {
        let bytes = header(MAGIC_MICROS, false, 3, 0, 0, 65535, 1);
        assert!(matches!(
            PcapGlobalHeader::parse(&bytes),
            Err(CaptureError::InvalidVersion { major: 3, minor: 0 })
        ));
    }

    #[test]
    fn rejects_minor_versions_above_four() {
        let bytes = header(MAGIC_MICROS, false, 2, 5, 0, 65535, 1);
        assert!(matches!(
            PcapGlobalHeader::parse(&bytes),
            Err(CaptureError::InvalidVersion { major: 2, minor: 5 })
        ));
    }

    #[test]
    fn old_minor_versions_select_the_historical_length_order() {
        for (minor, order) in [
            (0, LengthFieldOrder::Swapped),
            (2, LengthFieldOrder::Swapped),
            (3, LengthFieldOrder::MaybeSwapped),
            (4, LengthFieldOrder::Normal),
        ] {
            let bytes = header(MAGIC_MICROS, false, 2, minor, 0, 65535, 1);
            let (parsed, warnings) = PcapGlobalHeader::parse(&bytes).unwrap();
            assert_eq!(parsed.length_field_order(), order, "2.{minor}");
            assert_eq!(warnings.is_empty(), minor == 4);
        }
    }

    #[test]
    fn link_type_length_caps_follow_libpcap() {
        assert_eq!(LinkType::ETHERNET.max_captured_length(), 262_144);
        assert_eq!(LinkType::USBPCAP.max_captured_length(), 1024 * 1024);
        assert_eq!(LinkType::EBHSCR.max_captured_length(), 8 * 1024 * 1024);
        assert_eq!(LinkType::DBUS.max_captured_length(), 128 * 1024 * 1024);
    }

    #[test]
    fn rejects_zero_snap_length() {
        let bytes = header(MAGIC_MICROS, true, 2, 4, 0, 0, 1);
        assert!(matches!(
            PcapGlobalHeader::parse(&bytes),
            Err(CaptureError::InvalidSnapLength)
        ));
    }

    #[test]
    fn rejects_reserved_link_type_bits() {
        let bytes = header(MAGIC_MICROS, false, 2, 4, 0, 65535, 0x0001_0001);
        assert!(matches!(
            PcapGlobalHeader::parse(&bytes),
            Err(CaptureError::CorruptGlobalHeader { .. })
        ));
    }

    #[test]
    fn decodes_fcs_length() {
        // FCS present, length 2 x 16-bit words = 4 bytes, Ethernet.
        let bytes = header(MAGIC_MICROS, false, 2, 4, 0, 65535, 0x2400_0001);
        let (parsed, _) = PcapGlobalHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.link_type, LinkType::ETHERNET);
        assert_eq!(parsed.fcs_length_bytes, Some(4));
    }

    #[test]
    fn warns_about_unusual_minor_version_and_time_zone() {
        let bytes = header(MAGIC_MICROS, false, 2, 2, -3600, 65535, 101);
        let (parsed, warnings) = PcapGlobalHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.timezone_offset_seconds, -3600);
        assert_eq!(parsed.link_type_name, Some("RAW"));
        assert_eq!(
            warnings,
            vec![
                WarningCode::UnusualVersionMinor,
                WarningCode::NonzeroTimezoneOffset
            ]
        );
    }

    #[test]
    fn unknown_link_types_have_no_name() {
        let bytes = header(MAGIC_MICROS, false, 2, 4, 0, 65535, 4242);
        let (parsed, _) = PcapGlobalHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.link_type, LinkType(4242));
        assert_eq!(parsed.link_type_name, None);
    }
}
