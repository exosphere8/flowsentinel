//! TCP, UDP, ICMP and ICMPv6 headers.

use crate::app::{self, AppTransport, Payload};
use crate::bytes::{rest, slice, u8_at, u16_at, u32_at};
use crate::context::Context;
use crate::model::{
    DecodeStatus, DecodeWarningCode, IcmpHeader, Layer, Protocol, TcpFlags, TcpHeader, UdpHeader,
};
use crate::names::{icmp_type_name, icmpv6_type_name};

/// What the network layer says about the transport segment it carries.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Encapsulation {
    /// Payload length declared by the IP header(s). The slice handed to a
    /// transport parser never extends beyond it.
    pub declared_length: usize,
    /// The IP packet is a fragment, so length cross-checks are skipped.
    pub fragmented: bool,
    /// Fewer bytes were captured than declared because the capture's
    /// snapshot length cut the frame short.
    pub capture_cut: bool,
}

const TCP_MIN_HEADER: usize = 20;
const UDP_HEADER: usize = 8;
const ICMP_HEADER: usize = 8;

fn clamp_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

/// Reports a transport header that does not fit in the available bytes: a
/// capture truncation if the snapshot length cut the packet, otherwise a
/// length mismatch (the IP header declares too little payload).
fn short_header(
    ctx: &mut Context,
    enc: Encapsulation,
    protocol: Protocol,
    truncated: &'static str,
    mismatch: &'static str,
) {
    if enc.capture_cut {
        ctx.truncated(protocol, truncated);
    } else {
        ctx.stop(
            DecodeStatus::Malformed,
            DecodeWarningCode::LengthMismatch,
            Some(protocol),
            mismatch,
        );
    }
}

pub(crate) fn decode_tcp(ctx: &mut Context, data: &[u8], enc: Encapsulation) {
    let Some(offset_byte) = u8_at(data, 12) else {
        short_header(
            ctx,
            enc,
            Protocol::Tcp,
            "segment ends inside the 20-byte TCP header",
            "IP payload is shorter than the 20-byte TCP header",
        );
        return;
    };
    let header_len = usize::from(offset_byte >> 4).saturating_mul(4);
    if header_len < TCP_MIN_HEADER {
        ctx.malformed(Protocol::Tcp, "TCP data offset is below 5");
        return;
    }
    let Some(header) = slice(data, 0, header_len) else {
        short_header(
            ctx,
            enc,
            Protocol::Tcp,
            "segment ends inside the TCP header or options",
            "IP payload is shorter than the TCP header and options",
        );
        return;
    };
    let (
        Some(source_port),
        Some(destination_port),
        Some(sequence_number),
        Some(acknowledgment_number),
        Some(flag_byte),
        Some(window),
        Some(urgent_pointer),
    ) = (
        u16_at(header, 0),
        u16_at(header, 2),
        u32_at(header, 4),
        u32_at(header, 8),
        u8_at(header, 13),
        u16_at(header, 14),
        u16_at(header, 18),
    )
    else {
        ctx.truncated(Protocol::Tcp, "segment ends inside the 20-byte TCP header");
        return;
    };

    // The header fits in the declared length (checked above), so this
    // cannot underflow.
    let payload_length = enc.declared_length.saturating_sub(header_len);
    ctx.push(Layer::Tcp(TcpHeader {
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        header_length: u8::try_from(header_len).unwrap_or(u8::MAX),
        flags: TcpFlags((u16::from(offset_byte & 0x01) << 8) | u16::from(flag_byte)),
        window,
        urgent_pointer,
        options_length: u8::try_from(header_len.saturating_sub(TCP_MIN_HEADER)).unwrap_or(u8::MAX),
        payload_length: clamp_u16(payload_length),
    }));

    // Fragments carry only part of the segment; their payload is not
    // examined for application messages.
    if !enc.fragmented {
        app::decode(
            ctx,
            Payload {
                transport: AppTransport::Tcp,
                source_port,
                destination_port,
                bytes: rest(data, header_len),
                declared_length: payload_length,
            },
        );
    }
}

pub(crate) fn decode_udp(ctx: &mut Context, data: &[u8], enc: Encapsulation) {
    let (Some(source_port), Some(destination_port), Some(length), Some(_checksum)) = (
        u16_at(data, 0),
        u16_at(data, 2),
        u16_at(data, 4),
        u16_at(data, 6),
    ) else {
        short_header(
            ctx,
            enc,
            Protocol::Udp,
            "datagram ends inside the 8-byte UDP header",
            "IP payload is shorter than the 8-byte UDP header",
        );
        return;
    };
    let declared = usize::from(length);
    ctx.push(Layer::Udp(UdpHeader {
        source_port,
        destination_port,
        length,
        payload_length: clamp_u16(declared.saturating_sub(UDP_HEADER)),
    }));

    if declared < UDP_HEADER {
        ctx.malformed(Protocol::Udp, "UDP length is below the 8-byte header size");
        return;
    }
    if enc.fragmented {
        return;
    }
    if declared > enc.declared_length {
        ctx.stop(
            DecodeStatus::Malformed,
            DecodeWarningCode::LengthMismatch,
            Some(Protocol::Udp),
            "UDP length exceeds the IP payload length",
        );
        return;
    }
    if declared < enc.declared_length {
        ctx.warn(
            DecodeWarningCode::LengthMismatch,
            Some(Protocol::Udp),
            "UDP length is shorter than the IP payload length",
        );
    }
    let payload = data
        .get(UDP_HEADER..declared.min(data.len()))
        .unwrap_or(&[]);
    app::decode(
        ctx,
        Payload {
            transport: AppTransport::Udp,
            source_port,
            destination_port,
            bytes: payload,
            declared_length: declared.saturating_sub(UDP_HEADER),
        },
    );
}

pub(crate) fn decode_icmp(ctx: &mut Context, data: &[u8], enc: Encapsulation, protocol: Protocol) {
    let (Some(icmp_type), Some(code), Some(identifier), Some(sequence)) = (
        u8_at(data, 0),
        u8_at(data, 1),
        u16_at(data, 4),
        u16_at(data, 6),
    ) else {
        short_header(
            ctx,
            enc,
            protocol,
            "message ends inside the 8-byte ICMP header",
            "IP payload is shorter than the 8-byte ICMP header",
        );
        return;
    };
    let (type_name, is_echo) = if protocol == Protocol::Icmpv6 {
        (icmpv6_type_name(icmp_type), matches!(icmp_type, 128 | 129))
    } else {
        (icmp_type_name(icmp_type), matches!(icmp_type, 0 | 8))
    };
    let header = IcmpHeader {
        icmp_type,
        code,
        type_name,
        identifier: is_echo.then_some(identifier),
        sequence: is_echo.then_some(sequence),
        payload_length: clamp_u16(enc.declared_length.saturating_sub(ICMP_HEADER)),
    };
    ctx.push(if protocol == Protocol::Icmpv6 {
        Layer::Icmpv6(header)
    } else {
        Layer::Icmp(header)
    });
}
