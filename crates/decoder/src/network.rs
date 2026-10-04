//! IPv4 and IPv6, including bounded IPv6 extension-header traversal.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bytes::{array, rest, slice, u8_at, u16_at, u32_at};
use crate::context::Context;
use crate::model::{
    DecodeStatus, DecodeWarningCode, Ipv4Header, Ipv6ExtensionHeader, Ipv6Fragment, Ipv6Header,
    Layer, Protocol,
};
use crate::names::{IP_PROTO_ICMP, IP_PROTO_ICMPV6, IP_PROTO_TCP, IP_PROTO_UDP, ip_protocol_name};
use crate::transport::{self, Encapsulation};

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
/// Longest IPv6 extension-header chain that is traversed.
pub const MAX_IPV6_EXTENSION_HEADERS: usize = 8;

pub(crate) fn decode_ipv4(ctx: &mut Context, data: &[u8]) {
    let Some(first) = u8_at(data, 0) else {
        ctx.truncated(Protocol::Ipv4, "packet ends before the IPv4 header");
        return;
    };
    if first >> 4 != 4 {
        ctx.malformed(Protocol::Ipv4, "IPv4 version field is not 4");
        return;
    }
    let header_len = usize::from(first & 0x0F).saturating_mul(4);
    if header_len < IPV4_MIN_HEADER {
        ctx.malformed(Protocol::Ipv4, "IPv4 header length (IHL) is below 5");
        return;
    }
    let Some(header) = slice(data, 0, header_len) else {
        ctx.truncated(Protocol::Ipv4, "packet ends inside the IPv4 header");
        return;
    };
    let (
        Some(tos),
        Some(total_length),
        Some(identification),
        Some(flags_fragment),
        Some(ttl),
        Some(protocol),
        Some(source),
        Some(destination),
    ) = (
        u8_at(header, 1),
        u16_at(header, 2),
        u16_at(header, 4),
        u16_at(header, 6),
        u8_at(header, 8),
        u8_at(header, 9),
        array::<4>(header, 12),
        array::<4>(header, 16),
    )
    else {
        ctx.truncated(Protocol::Ipv4, "packet ends inside the IPv4 header");
        return;
    };

    let Some(payload_length) = usize::from(total_length).checked_sub(header_len) else {
        ctx.malformed(
            Protocol::Ipv4,
            "IPv4 total length is smaller than its header (0 usually means segmentation offload)",
        );
        return;
    };
    let fragment_offset_units = flags_fragment & 0x1FFF;
    let more_fragments = flags_fragment & 0x2000 != 0;
    let checksum_valid = internet_checksum(header) == 0;

    ctx.push(Layer::Ipv4(Ipv4Header {
        // header_len <= 60 and payload_length <= total_length, so both fit.
        header_length: u8::try_from(header_len).unwrap_or(u8::MAX),
        dscp: tos >> 2,
        ecn: tos & 0x03,
        total_length,
        identification,
        dont_fragment: flags_fragment & 0x4000 != 0,
        more_fragments,
        fragment_offset: fragment_offset_units.saturating_mul(8),
        ttl,
        protocol,
        protocol_name: ip_protocol_name(protocol),
        checksum_valid,
        source: Ipv4Addr::from(source),
        destination: Ipv4Addr::from(destination),
        options_length: u8::try_from(header_len.saturating_sub(IPV4_MIN_HEADER)).unwrap_or(u8::MAX),
        payload_length: u16::try_from(payload_length).unwrap_or(u16::MAX),
    }));

    if flags_fragment & 0x8000 != 0 {
        ctx.warn(
            DecodeWarningCode::InvalidHeaderField,
            Some(Protocol::Ipv4),
            "reserved IPv4 flag bit is set",
        );
    }
    if !checksum_valid {
        ctx.warn(
            DecodeWarningCode::BadIpv4Checksum,
            Some(Protocol::Ipv4),
            "IPv4 header checksum does not match (common with checksum offload)",
        );
    }
    let fragmented = more_fragments || fragment_offset_units != 0;
    if fragmented {
        ctx.warn(
            DecodeWarningCode::Fragment,
            Some(Protocol::Ipv4),
            "IPv4 fragment; transport length checks are skipped",
        );
    }
    if usize::from(total_length) > data.len() && !ctx.snapped() {
        ctx.stop(
            DecodeStatus::Malformed,
            DecodeWarningCode::LengthMismatch,
            Some(Protocol::Ipv4),
            "IPv4 total length exceeds the captured frame, which was not truncated",
        );
        return;
    }
    if fragment_offset_units != 0 {
        // Non-initial fragments carry no transport header.
        return;
    }

    // Ignore Ethernet padding beyond the declared total length.
    let end = usize::from(total_length).min(data.len());
    let payload = data.get(header_len..end).unwrap_or(&[]);
    let encapsulation = Encapsulation {
        declared_length: payload_length,
        fragmented,
        capture_cut: payload.len() < payload_length,
    };
    dispatch(ctx, protocol, payload, encapsulation, Protocol::Ipv4);
}

pub(crate) fn decode_ipv6(ctx: &mut Context, data: &[u8]) {
    let Some(fixed) = slice(data, 0, IPV6_HEADER) else {
        ctx.truncated(Protocol::Ipv6, "packet ends inside the 40-byte IPv6 header");
        return;
    };
    let (Some(word0), Some(payload_length), Some(next_header), Some(hop_limit)) = (
        u32_at(fixed, 0),
        u16_at(fixed, 4),
        u8_at(fixed, 6),
        u8_at(fixed, 7),
    ) else {
        ctx.truncated(Protocol::Ipv6, "packet ends inside the 40-byte IPv6 header");
        return;
    };
    let (Some(source), Some(destination)) = (array::<16>(fixed, 8), array::<16>(fixed, 24)) else {
        ctx.truncated(Protocol::Ipv6, "packet ends inside the 40-byte IPv6 header");
        return;
    };
    if word0 >> 28 != 6 {
        ctx.malformed(Protocol::Ipv6, "IPv6 version field is not 6");
        return;
    }

    let mut header = Ipv6Header {
        traffic_class: u8::try_from((word0 >> 20) & 0xFF).unwrap_or(0),
        flow_label: word0 & 0x000F_FFFF,
        payload_length,
        next_header,
        hop_limit,
        source: Ipv6Addr::from(source),
        destination: Ipv6Addr::from(destination),
        extension_headers: Vec::new(),
        fragment: None,
        upper_layer_protocol: None,
        upper_layer_name: None,
    };

    if payload_length == 0 && next_header == HOP_BY_HOP {
        ctx.push(Layer::Ipv6(Box::new(header)));
        ctx.stop(
            DecodeStatus::Unsupported,
            DecodeWarningCode::LengthMismatch,
            Some(Protocol::Ipv6),
            "IPv6 payload length is 0 with Hop-by-Hop options (jumbograms are not decoded)",
        );
        return;
    }
    if payload_length == 0 && next_header != NO_NEXT_HEADER {
        ctx.push(Layer::Ipv6(Box::new(header)));
        ctx.stop(
            DecodeStatus::Malformed,
            DecodeWarningCode::LengthMismatch,
            Some(Protocol::Ipv6),
            "IPv6 payload length is 0 but the next header expects data",
        );
        return;
    }
    let declared_end = IPV6_HEADER.saturating_add(usize::from(payload_length));
    if declared_end > data.len() && !ctx.snapped() {
        ctx.push(Layer::Ipv6(Box::new(header)));
        ctx.stop(
            DecodeStatus::Malformed,
            DecodeWarningCode::LengthMismatch,
            Some(Protocol::Ipv6),
            "IPv6 payload length exceeds the captured frame, which was not truncated",
        );
        return;
    }

    let payload = data
        .get(IPV6_HEADER..declared_end.min(data.len()))
        .unwrap_or(&[]);
    let capture_cut = payload.len() < usize::from(payload_length);
    let outcome = walk_extension_headers(payload, next_header, &mut header);
    let upper_offset = match outcome {
        Walk::Upper { protocol, offset } => {
            header.upper_layer_protocol = Some(protocol);
            header.upper_layer_name = ip_protocol_name(protocol);
            offset
        }
        Walk::NonInitialFragment { next } => {
            header.upper_layer_protocol = Some(next);
            header.upper_layer_name = ip_protocol_name(next);
            0
        }
        _ => 0,
    };
    let fragment = header.fragment;
    ctx.push(Layer::Ipv6(Box::new(header)));

    if fragment.is_some() {
        ctx.warn(
            DecodeWarningCode::Fragment,
            Some(Protocol::Ipv6),
            "IPv6 fragment; transport length checks are skipped",
        );
    }

    match outcome {
        // Non-initial fragments carry continuation data, not headers.
        Walk::NoNextHeader | Walk::NonInitialFragment { .. } => {}
        Walk::Truncated if capture_cut => ctx.truncated(
            Protocol::Ipv6,
            "packet ends inside an IPv6 extension header",
        ),
        Walk::Truncated => ctx.stop(
            DecodeStatus::Malformed,
            DecodeWarningCode::LengthMismatch,
            Some(Protocol::Ipv6),
            "IPv6 extension header extends past the declared payload length",
        ),
        Walk::HopByHopNotFirst => ctx.malformed(
            Protocol::Ipv6,
            "Hop-by-Hop Options header appears after the first position",
        ),
        Walk::LimitExceeded => ctx.stop(
            DecodeStatus::Unsupported,
            DecodeWarningCode::ExtensionHeaderLimit,
            Some(Protocol::Ipv6),
            "IPv6 extension-header chain is longer than the traversal limit",
        ),
        Walk::Encrypted => ctx.stop(
            DecodeStatus::Unsupported,
            DecodeWarningCode::EncryptedPayload,
            Some(Protocol::Ipv6),
            "IPv6 payload is ESP-encrypted; the upper layer is not visible",
        ),
        Walk::Upper { protocol, offset } => {
            let Some(declared_length) = usize::from(payload_length).checked_sub(offset) else {
                ctx.stop(
                    DecodeStatus::Malformed,
                    DecodeWarningCode::LengthMismatch,
                    Some(Protocol::Ipv6),
                    "IPv6 extension headers exceed the declared payload length",
                );
                return;
            };
            let transport = rest(payload, upper_offset);
            let encapsulation = Encapsulation {
                declared_length,
                fragmented: fragment.is_some(),
                capture_cut: transport.len() < declared_length,
            };
            dispatch(ctx, protocol, transport, encapsulation, Protocol::Ipv6);
        }
    }
}

const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const ESP: u8 = 50;
const AUTH_HEADER: u8 = 51;
const NO_NEXT_HEADER: u8 = 59;
const DESTINATION_OPTIONS: u8 = 60;
const MOBILITY: u8 = 135;
const HIP: u8 = 139;
const SHIM6: u8 = 140;

enum Walk {
    /// The chain ended at an upper-layer protocol starting at `offset`.
    Upper {
        protocol: u8,
        offset: usize,
    },
    /// A Fragment header with a non-zero offset: everything after it is
    /// continuation data and must not be parsed.
    NonInitialFragment {
        next: u8,
    },
    NoNextHeader,
    Truncated,
    HopByHopNotFirst,
    LimitExceeded,
    Encrypted,
}

/// Follows the extension-header chain. Each step must advance by the
/// header's validated length, and at most [`MAX_IPV6_EXTENSION_HEADERS`]
/// steps are taken, so the walk always terminates.
fn walk_extension_headers(payload: &[u8], first: u8, header: &mut Ipv6Header) -> Walk {
    let mut next = first;
    let mut offset: usize = 0;
    loop {
        let length = match next {
            HOP_BY_HOP | ROUTING | DESTINATION_OPTIONS | MOBILITY | HIP | SHIM6 => {
                // Hdr Ext Len counts 8-octet units after the first 8 octets.
                u8_at(payload, offset.saturating_add(1)).map(|units| (usize::from(units) + 1) * 8)
            }
            // Payload Len counts 4-octet units, minus 2.
            AUTH_HEADER => {
                u8_at(payload, offset.saturating_add(1)).map(|units| (usize::from(units) + 2) * 4)
            }
            FRAGMENT => Some(8),
            ESP => return Walk::Encrypted,
            NO_NEXT_HEADER => return Walk::NoNextHeader,
            protocol => return Walk::Upper { protocol, offset },
        };
        if next == HOP_BY_HOP && !header.extension_headers.is_empty() {
            return Walk::HopByHopNotFirst;
        }
        if header.extension_headers.len() == MAX_IPV6_EXTENSION_HEADERS {
            return Walk::LimitExceeded;
        }
        let Some(length) = length else {
            return Walk::Truncated;
        };
        let (Some(ext), Some(following)) = (slice(payload, offset, length), u8_at(payload, offset))
        else {
            return Walk::Truncated;
        };
        if next == FRAGMENT {
            let (Some(offset_flags), Some(identification)) = (u16_at(ext, 2), u32_at(ext, 4))
            else {
                return Walk::Truncated;
            };
            let fragment = Ipv6Fragment {
                offset: (offset_flags >> 3).saturating_mul(8),
                more_fragments: offset_flags & 0x0001 != 0,
                identification,
            };
            header.fragment = Some(fragment);
            if fragment.offset != 0 {
                header.extension_headers.push(extension(next, length));
                return Walk::NonInitialFragment { next: following };
            }
        }
        header.extension_headers.push(extension(next, length));
        offset = offset.saturating_add(length);
        next = following;
    }
}

fn extension(header_type: u8, length: usize) -> Ipv6ExtensionHeader {
    Ipv6ExtensionHeader {
        header_type,
        name: ip_protocol_name(header_type).unwrap_or("IPv6 extension"),
        // length <= (255 + 2) * 8 = 2056.
        length: u16::try_from(length).unwrap_or(u16::MAX),
    }
}

fn dispatch(
    ctx: &mut Context,
    protocol: u8,
    payload: &[u8],
    encapsulation: Encapsulation,
    network: Protocol,
) {
    match (protocol, network) {
        (IP_PROTO_TCP, _) => transport::decode_tcp(ctx, payload, encapsulation),
        (IP_PROTO_UDP, _) => transport::decode_udp(ctx, payload, encapsulation),
        (IP_PROTO_ICMP, Protocol::Ipv4) => {
            transport::decode_icmp(ctx, payload, encapsulation, Protocol::Icmp);
        }
        (IP_PROTO_ICMPV6, Protocol::Ipv6) => {
            transport::decode_icmp(ctx, payload, encapsulation, Protocol::Icmpv6);
        }
        _ => ctx.stop(
            DecodeStatus::Unsupported,
            DecodeWarningCode::UnsupportedIpProtocol,
            Some(network),
            "IP protocol is not decoded",
        ),
    }
}

/// RFC 1071 Internet checksum over `data`; 0 means a header that includes
/// its checksum field is valid.
fn internet_checksum(data: &[u8]) -> u16 {
    // Folding after every addition keeps `sum` below 0x1_FFFF, so it can
    // never overflow whatever the input length.
    let fold = |sum: u32| (sum & 0xFFFF) + (sum >> 16);
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        if let [hi, lo] = pair {
            sum = fold(sum + u32::from(u16::from_be_bytes([*hi, *lo])));
        }
    }
    if let [last] = chunks.remainder() {
        sum = fold(sum + (u32::from(*last) << 8));
    }
    !u16::try_from(fold(sum)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_valid_header_is_zero() {
        // Example header from RFC 1071 discussions: 192.0.2.10 -> 198.51.100.20, UDP.
        let mut header = [
            0x45, 0x00, 0x00, 0x41, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 0, 2, 10,
            198, 51, 100, 20,
        ];
        let checksum = internet_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(internet_checksum(&header), 0);
        header[8] = 63;
        assert_ne!(internet_checksum(&header), 0);
    }
}
