//! Ethernet II (with VLAN tags) and ARP.

use std::net::Ipv4Addr;

use crate::bytes::{array, rest, slice, u8_at, u16_at};
use crate::context::Context;
use crate::model::{
    ArpPacket, DecodeStatus, DecodeWarningCode, EthernetHeader, Layer, MacAddr, Protocol, VlanTag,
};
use crate::names::{
    ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_QINQ, ETHERTYPE_QINQ_LEGACY,
    ETHERTYPE_VLAN, arp_operation_name, ethertype_name,
};
use crate::network;

/// At most this many stacked VLAN tags are traversed (802.1ad QinQ uses two).
const MAX_VLAN_TAGS: usize = 2;
/// Values up to this are IEEE 802.3 length fields, not EtherTypes.
const MAX_8023_LENGTH: u16 = 1500;
/// Smallest EtherType value.
const MIN_ETHERTYPE: u16 = 0x0600;

pub(crate) fn decode_ethernet(ctx: &mut Context, data: &[u8]) {
    let (Some(destination), Some(source)) = (array::<6>(data, 0), array::<6>(data, 6)) else {
        ctx.truncated(
            Protocol::Ethernet,
            "frame is shorter than the 14-byte Ethernet header",
        );
        return;
    };

    let mut offset: usize = 12;
    let mut vlan_tags = Vec::new();
    let ethertype = loop {
        let Some(value) = u16_at(data, offset) else {
            ctx.truncated(Protocol::Ethernet, "frame ends inside the Ethernet header");
            return;
        };
        if !matches!(
            value,
            ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_QINQ_LEGACY
        ) {
            offset = offset.saturating_add(2);
            break value;
        }
        if vlan_tags.len() == MAX_VLAN_TAGS {
            // Keep what was decoded: addresses and the first two tags.
            ctx.push(Layer::Ethernet(EthernetHeader {
                destination: MacAddr(destination),
                source: MacAddr(source),
                vlan_tags,
                ethertype: value,
                ethertype_name: ethertype_name(value),
                header_length: u16::try_from(offset).unwrap_or(u16::MAX),
            }));
            ctx.stop(
                DecodeStatus::Unsupported,
                DecodeWarningCode::TooManyVlanTags,
                Some(Protocol::Ethernet),
                "more than two stacked VLAN tags",
            );
            return;
        }
        let Some(tci) = u16_at(data, offset.saturating_add(2)) else {
            ctx.truncated(Protocol::Ethernet, "frame ends inside a VLAN tag");
            return;
        };
        vlan_tags.push(VlanTag {
            tpid: value,
            priority: u8::try_from(tci >> 13).unwrap_or(0),
            drop_eligible: tci & 0x1000 != 0,
            vlan_id: tci & 0x0FFF,
        });
        offset = offset.saturating_add(4);
    };

    ctx.push(Layer::Ethernet(EthernetHeader {
        destination: MacAddr(destination),
        source: MacAddr(source),
        vlan_tags,
        ethertype,
        ethertype_name: ethertype_name(ethertype),
        // offset is at most 12 + 2 * 4 + 2 = 22.
        header_length: u16::try_from(offset).unwrap_or(u16::MAX),
    }));

    let payload = rest(data, offset);
    match ethertype {
        ETHERTYPE_IPV4 => network::decode_ipv4(ctx, payload),
        ETHERTYPE_IPV6 => network::decode_ipv6(ctx, payload),
        ETHERTYPE_ARP => decode_arp(ctx, payload),
        len if len <= MAX_8023_LENGTH => {
            if usize::from(len) > payload.len() {
                ctx.warn(
                    DecodeWarningCode::LengthMismatch,
                    Some(Protocol::Ethernet),
                    "802.3 length field exceeds the captured frame",
                );
            }
            ctx.stop(
                DecodeStatus::Unsupported,
                DecodeWarningCode::UnsupportedEthertype,
                Some(Protocol::Ethernet),
                "IEEE 802.3 length-field frame; LLC/SNAP is not decoded",
            );
        }
        value if value < MIN_ETHERTYPE => {
            ctx.malformed(
                Protocol::Ethernet,
                "type/length field is neither a valid length nor an EtherType",
            );
        }
        _ => ctx.stop(
            DecodeStatus::Unsupported,
            DecodeWarningCode::UnsupportedEthertype,
            Some(Protocol::Ethernet),
            "EtherType is not decoded",
        ),
    }
}

const ARP_FIXED_LEN: usize = 8;
const ARP_HTYPE_ETHERNET: u16 = 1;

pub(crate) fn decode_arp(ctx: &mut Context, data: &[u8]) {
    let (Some(hardware_type), Some(protocol_type), Some(hlen), Some(plen), Some(operation)) = (
        u16_at(data, 0),
        u16_at(data, 2),
        u8_at(data, 4),
        u8_at(data, 5),
        u16_at(data, 6),
    ) else {
        ctx.truncated(
            Protocol::Arp,
            "packet is shorter than the 8-byte ARP header",
        );
        return;
    };

    let mut arp = ArpPacket {
        hardware_type,
        protocol_type,
        hardware_address_length: hlen,
        protocol_address_length: plen,
        operation,
        operation_name: arp_operation_name(operation),
        sender_mac: None,
        sender_ip: None,
        target_mac: None,
        target_ip: None,
    };

    if hardware_type == ARP_HTYPE_ETHERNET && hlen != 6 {
        ctx.push(Layer::Arp(arp));
        ctx.malformed(
            Protocol::Arp,
            "Ethernet ARP must use 6-byte hardware addresses",
        );
        return;
    }
    if protocol_type == ETHERTYPE_IPV4 && plen != 4 {
        ctx.push(Layer::Arp(arp));
        ctx.malformed(Protocol::Arp, "IPv4 ARP must use 4-byte protocol addresses");
        return;
    }

    // hlen and plen are single bytes, so this cannot overflow.
    let body_len = 2 * (usize::from(hlen) + usize::from(plen));
    let Some(body) = slice(data, ARP_FIXED_LEN, body_len) else {
        ctx.push(Layer::Arp(arp));
        ctx.truncated(Protocol::Arp, "packet ends inside the ARP addresses");
        return;
    };

    if hardware_type != ARP_HTYPE_ETHERNET || protocol_type != ETHERTYPE_IPV4 {
        ctx.push(Layer::Arp(arp));
        ctx.stop(
            DecodeStatus::Unsupported,
            DecodeWarningCode::UnsupportedArpFormat,
            Some(Protocol::Arp),
            "only Ethernet/IPv4 ARP addresses are decoded",
        );
        return;
    }

    // Layout: sender MAC (6), sender IP (4), target MAC (6), target IP (4).
    arp.sender_mac = array::<6>(body, 0).map(MacAddr);
    arp.sender_ip = array::<4>(body, 6).map(Ipv4Addr::from);
    arp.target_mac = array::<6>(body, 10).map(MacAddr);
    arp.target_ip = array::<4>(body, 16).map(Ipv4Addr::from);
    ctx.push(Layer::Arp(arp));
}
