//! Bounds-checked, metadata-only protocol decoding.
//!
//! [`decode_packet`] turns the captured bytes of one packet into a
//! [`DecodedPacket`]: a protocol tree of typed headers plus a status and
//! warnings. Supported: Ethernet II (with up to two VLAN tags), ARP, IPv4,
//! IPv6 (with bounded extension-header traversal), ICMP, ICMPv6, TCP and UDP.
//!
//! Safety properties:
//!
//! - Packet bytes are borrowed only for the duration of the call. No public
//!   type stores payload bytes; payloads are reported by length only.
//! - Every field read is bounds-checked; malformed or truncated input yields
//!   a status and warning, never a panic.
//! - No allocation is sized from a packet field. Loops (VLAN tags, IPv6
//!   extension headers) have fixed iteration limits.
//! - One packet's result never depends on another's, so a malformed packet
//!   cannot affect later packets.

mod bytes;
mod context;
mod describe;
mod link;
mod model;
mod names;
mod network;
mod summary;
mod transport;

pub use model::{
    ArpPacket, DecodeStatus, DecodeWarning, DecodeWarningCode, DecodedPacket, EthernetHeader,
    IcmpHeader, Ipv4Header, Ipv6ExtensionHeader, Ipv6Fragment, Ipv6Header, Layer, MacAddr,
    Protocol, TcpFlags, TcpHeader, UdpHeader, VlanTag,
};
pub use names::{ethertype_name, ip_protocol_name};
pub use network::MAX_IPV6_EXTENSION_HEADERS;
pub use summary::{DecodeSummary, DecodeWarningSummary};

use context::Context;

/// `LINKTYPE_ETHERNET`, the only link type decoded in this version.
pub const LINKTYPE_ETHERNET: u16 = 1;

/// Decodes one packet captured with link-layer type `link_type`.
///
/// `data` is the captured portion of the packet and `wire_length` its
/// original length. When `data` is shorter (a snapshot length cut the
/// packet), running out of bytes is reported as `truncated`; when the frame
/// is complete, a header that declares more bytes than exist is reported as
/// a `length_mismatch`. The function never panics, whatever its input.
pub fn decode_packet(link_type: u16, data: &[u8], wire_length: u32) -> DecodedPacket {
    let captured = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let mut ctx = Context::new(captured < wire_length);
    if link_type == LINKTYPE_ETHERNET {
        link::decode_ethernet(&mut ctx, data);
    } else {
        ctx.stop(
            DecodeStatus::Unsupported,
            DecodeWarningCode::UnsupportedLinkType,
            None,
            "only Ethernet (LINKTYPE_ETHERNET) captures are decoded",
        );
    }
    ctx.finish()
}
