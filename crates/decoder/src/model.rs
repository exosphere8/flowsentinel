//! Public, metadata-only decode results.
//!
//! None of these types can hold packet payload bytes. Lengths of payloads are
//! reported; their contents are not.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Serialize, Serializer};

/// Protocols this crate recognizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Ethernet,
    Arp,
    Ipv4,
    Ipv6,
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
}

impl Protocol {
    /// Display name, as shown in tables.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ethernet => "Ethernet",
            Self::Arp => "ARP",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Icmp => "ICMP",
            Self::Icmpv6 => "ICMPv6",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

/// A 48-bit IEEE MAC address. Serializes as `"02:00:00:00:00:01"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// `ff:ff:ff:ff:ff:ff`.
    pub fn is_broadcast(self) -> bool {
        self.0 == [0xFF; 6]
    }

    /// Group (multicast or broadcast) address: low bit of the first octet set.
    pub fn is_multicast(self) -> bool {
        let [first, ..] = self.0;
        first & 0x01 != 0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// How far decoding got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeStatus {
    /// Every header present was decoded, down to the transport layer, ARP, or
    /// an IP layer whose transport header is legitimately absent (a
    /// non-initial fragment, or IPv6 "no next header").
    Complete,
    /// Decoding stopped at a link type, EtherType or IP protocol that this
    /// version does not decode. The layers before it are valid.
    Unsupported,
    /// The captured bytes ended inside a header (usually a short snapshot length).
    Truncated,
    /// A header field is invalid. The layers before it are valid.
    Malformed,
}

impl DecodeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Unsupported => "unsupported",
            Self::Truncated => "truncated",
            Self::Malformed => "malformed",
        }
    }
}

/// Kind of decode problem or notable condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeWarningCode {
    /// The capture's link-layer type is not Ethernet.
    UnsupportedLinkType,
    /// The EtherType (or 802.3 length/LLC frame) is not decoded.
    UnsupportedEthertype,
    /// The IP protocol / IPv6 next header is not decoded.
    UnsupportedIpProtocol,
    /// The ARP hardware/protocol combination is not Ethernet/IPv4.
    UnsupportedArpFormat,
    /// The captured bytes end inside this protocol's header.
    TruncatedHeader,
    /// A header field has an invalid value.
    InvalidHeaderField,
    /// A declared length disagrees with the enclosing layer or captured data.
    LengthMismatch,
    /// More than two stacked VLAN tags.
    TooManyVlanTags,
    /// The packet is an IPv4/IPv6 fragment.
    Fragment,
    /// The IPv6 extension-header chain exceeded the traversal limit.
    ExtensionHeaderLimit,
    /// IPv6 payload is ESP-encrypted; the upper layer cannot be identified.
    EncryptedPayload,
    /// The IPv4 header checksum does not match.
    BadIpv4Checksum,
}

impl DecodeWarningCode {
    /// Every code, for exhaustive tests.
    pub const ALL: [Self; 12] = [
        Self::UnsupportedLinkType,
        Self::UnsupportedEthertype,
        Self::UnsupportedIpProtocol,
        Self::UnsupportedArpFormat,
        Self::TruncatedHeader,
        Self::InvalidHeaderField,
        Self::LengthMismatch,
        Self::TooManyVlanTags,
        Self::Fragment,
        Self::ExtensionHeaderLimit,
        Self::EncryptedPayload,
        Self::BadIpv4Checksum,
    ];

    /// Stable snake_case identifier; identical to the serialized form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedLinkType => "unsupported_link_type",
            Self::UnsupportedEthertype => "unsupported_ethertype",
            Self::UnsupportedIpProtocol => "unsupported_ip_protocol",
            Self::UnsupportedArpFormat => "unsupported_arp_format",
            Self::TruncatedHeader => "truncated_header",
            Self::InvalidHeaderField => "invalid_header_field",
            Self::LengthMismatch => "length_mismatch",
            Self::TooManyVlanTags => "too_many_vlan_tags",
            Self::Fragment => "fragment",
            Self::ExtensionHeaderLimit => "extension_header_limit",
            Self::EncryptedPayload => "encrypted_payload",
            Self::BadIpv4Checksum => "bad_ipv4_checksum",
        }
    }
}

/// One decode warning attached to a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DecodeWarning {
    pub code: DecodeWarningCode,
    /// Layer the warning applies to; `None` for link-type problems.
    pub protocol: Option<Protocol>,
    /// Fixed explanation. Never contains packet bytes.
    pub detail: &'static str,
}

/// An IEEE 802.1Q / 802.1ad VLAN tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VlanTag {
    /// Tag protocol identifier: 0x8100 (802.1Q), 0x88A8 (802.1ad) or 0x9100.
    pub tpid: u16,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EthernetHeader {
    pub destination: MacAddr,
    pub source: MacAddr,
    /// Up to two VLAN tags, outermost first.
    pub vlan_tags: Vec<VlanTag>,
    /// EtherType of the encapsulated protocol (after any VLAN tags), or the
    /// 802.3 length field when below 0x0600.
    pub ethertype: u16,
    pub ethertype_name: Option<&'static str>,
    /// Bytes of Ethernet and VLAN headers.
    pub header_length: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ArpPacket {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_address_length: u8,
    pub protocol_address_length: u8,
    pub operation: u16,
    pub operation_name: Option<&'static str>,
    /// Present only for Ethernet/IPv4 ARP.
    pub sender_mac: Option<MacAddr>,
    pub sender_ip: Option<Ipv4Addr>,
    pub target_mac: Option<MacAddr>,
    pub target_ip: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Ipv4Header {
    pub header_length: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// Fragment offset in bytes.
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub protocol_name: Option<&'static str>,
    pub checksum_valid: bool,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options_length: u8,
    /// Declared payload length: `total_length - header_length`.
    pub payload_length: u16,
}

/// One IPv6 extension header in the traversed chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Ipv6ExtensionHeader {
    pub header_type: u8,
    pub name: &'static str,
    pub length: u16,
}

/// Information from an IPv6 Fragment extension header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Ipv6Fragment {
    /// Fragment offset in bytes.
    pub offset: u16,
    pub more_fragments: bool,
    pub identification: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: u32,
    /// Declared length of everything after the 40-byte fixed header.
    pub payload_length: u16,
    /// Next Header field of the fixed header.
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub extension_headers: Vec<Ipv6ExtensionHeader>,
    pub fragment: Option<Ipv6Fragment>,
    /// Protocol after the extension headers, when the chain was fully traversed.
    pub upper_layer_protocol: Option<u8>,
    pub upper_layer_name: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub type_name: Option<&'static str>,
    /// Echo identifier, for echo request/reply only.
    pub identifier: Option<u16>,
    /// Echo sequence number, for echo request/reply only.
    pub sequence: Option<u16>,
    /// Declared bytes after the 8-byte ICMP header.
    pub payload_length: u16,
}

/// TCP control flags. Serializes as `{"bits": 18, "names": ["SYN", "ACK"]}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TcpFlags(pub u16);

impl TcpFlags {
    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const PSH: u16 = 0x008;
    pub const ACK: u16 = 0x010;
    pub const URG: u16 = 0x020;
    pub const ECE: u16 = 0x040;
    pub const CWR: u16 = 0x080;
    pub const AE: u16 = 0x100;

    const NAMES: [(u16, &'static str); 9] = [
        (Self::AE, "AE"),
        (Self::CWR, "CWR"),
        (Self::ECE, "ECE"),
        (Self::URG, "URG"),
        (Self::ACK, "ACK"),
        (Self::PSH, "PSH"),
        (Self::RST, "RST"),
        (Self::SYN, "SYN"),
        (Self::FIN, "FIN"),
    ];

    pub fn contains(self, flag: u16) -> bool {
        self.0 & flag == flag
    }

    /// Names of the set flags, in conventional order (SYN, ACK, ...).
    pub fn names(self) -> Vec<&'static str> {
        let mut names: Vec<_> = Self::NAMES
            .iter()
            .filter(|(bit, _)| self.0 & bit != 0)
            .map(|&(_, name)| name)
            .collect();
        names.reverse();
        names
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.names();
        if names.is_empty() {
            f.write_str("none")
        } else {
            f.write_str(&names.join(","))
        }
    }
}

impl Serialize for TcpFlags {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("TcpFlags", 2)?;
        state.serialize_field("bits", &self.0)?;
        state.serialize_field("names", &self.names())?;
        state.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub header_length: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub urgent_pointer: u16,
    pub options_length: u8,
    /// Declared segment payload length, from the IP length fields.
    pub payload_length: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    /// UDP length field (header plus payload).
    pub length: u16,
    pub payload_length: u16,
}

/// One decoded protocol layer. Serialized with a `"layer"` tag, for example
/// `{"layer": "udp", "source_port": 53, ...}`. (Not `"protocol"`, which is
/// an IPv4 header field.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "layer", rename_all = "snake_case")]
pub enum Layer {
    Ethernet(EthernetHeader),
    Arp(ArpPacket),
    Ipv4(Ipv4Header),
    Ipv6(Box<Ipv6Header>),
    Icmp(IcmpHeader),
    Icmpv6(IcmpHeader),
    Tcp(TcpHeader),
    Udp(UdpHeader),
}

impl Layer {
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::Ethernet(_) => Protocol::Ethernet,
            Self::Arp(_) => Protocol::Arp,
            Self::Ipv4(_) => Protocol::Ipv4,
            Self::Ipv6(_) => Protocol::Ipv6,
            Self::Icmp(_) => Protocol::Icmp,
            Self::Icmpv6(_) => Protocol::Icmpv6,
            Self::Tcp(_) => Protocol::Tcp,
            Self::Udp(_) => Protocol::Udp,
        }
    }
}

/// The protocol tree of one packet, outermost layer first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecodedPacket {
    pub status: DecodeStatus,
    pub layers: Vec<Layer>,
    pub warnings: Vec<DecodeWarning>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_addresses_format_as_lowercase_hex() {
        let mac = MacAddr([0x02, 0x00, 0x5E, 0x10, 0xAB, 0xFF]);
        assert_eq!(mac.to_string(), "02:00:5e:10:ab:ff");
        assert_eq!(
            serde_json::to_string(&mac).unwrap(),
            r#""02:00:5e:10:ab:ff""#
        );
        assert!(MacAddr([0xFF; 6]).is_broadcast());
        assert!(MacAddr([0x01, 0, 0x5E, 0, 0, 1]).is_multicast());
        assert!(!mac.is_multicast());
    }

    #[test]
    fn tcp_flags_list_in_conventional_order() {
        let flags = TcpFlags(TcpFlags::SYN | TcpFlags::ACK);
        assert_eq!(flags.to_string(), "SYN,ACK");
        assert_eq!(
            serde_json::to_string(&flags).unwrap(),
            r#"{"bits":18,"names":["SYN","ACK"]}"#
        );
        assert_eq!(TcpFlags(0).to_string(), "none");
        assert_eq!(TcpFlags(0x1FF).names().len(), 9);
    }

    #[test]
    fn warning_codes_serialize_as_their_str() {
        for code in DecodeWarningCode::ALL {
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{}\"", code.as_str())
            );
        }
    }

    #[test]
    fn layers_are_tagged_by_protocol() {
        let layer = Layer::Udp(UdpHeader {
            source_port: 1,
            destination_port: 2,
            length: 8,
            payload_length: 0,
        });
        let json = serde_json::to_value(&layer).unwrap();
        assert_eq!(json["layer"], "udp");
        assert_eq!(layer.protocol(), Protocol::Udp);
    }
}
