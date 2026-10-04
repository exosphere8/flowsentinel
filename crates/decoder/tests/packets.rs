//! Decodes synthetic packets built byte by byte and checks every layer.

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use common::*;
use decoder::{
    DecodeStatus, DecodeWarningCode, DecodedPacket, LINKTYPE_ETHERNET, Layer, Protocol, TcpFlags,
    decode_packet,
};

/// Decodes a fully captured frame.
fn decode(frame: &[u8]) -> DecodedPacket {
    decode_packet(LINKTYPE_ETHERNET, frame, frame.len() as u32)
}

/// Decodes the first `captured` bytes of a frame, as a short snapshot
/// length would.
fn decode_snapped(frame: &[u8], captured: usize) -> DecodedPacket {
    decode_packet(LINKTYPE_ETHERNET, &frame[..captured], frame.len() as u32)
}

fn protocols(packet: &DecodedPacket) -> Vec<Protocol> {
    packet.layers.iter().map(Layer::protocol).collect()
}

fn codes(packet: &DecodedPacket) -> Vec<DecodeWarningCode> {
    packet.warnings.iter().map(|w| w.code).collect()
}

fn udp_frame() -> Vec<u8> {
    ethernet(0x0800, &ipv4(&Ipv4::default(), &udp(40000, 9, MARKER)))
}

#[test]
fn ethernet_ipv4_udp() {
    let packet = decode(&udp_frame());
    assert_eq!(packet.status, DecodeStatus::Complete);
    assert_eq!(
        protocols(&packet),
        [Protocol::Ethernet, Protocol::Ipv4, Protocol::Udp]
    );
    assert!(packet.warnings.is_empty(), "{:?}", packet.warnings);

    let Layer::Ethernet(eth) = &packet.layers[0] else {
        panic!()
    };
    assert_eq!(eth.source.to_string(), "02:00:00:00:00:01");
    assert_eq!(eth.destination.to_string(), "02:00:00:00:00:02");
    assert_eq!(eth.ethertype, 0x0800);
    assert_eq!(eth.ethertype_name, Some("IPv4"));
    assert_eq!(eth.header_length, 14);
    assert!(eth.vlan_tags.is_empty());

    let Layer::Ipv4(ip) = &packet.layers[1] else {
        panic!()
    };
    assert_eq!(ip.source, Ipv4Addr::new(192, 0, 2, 10));
    assert_eq!(ip.destination, Ipv4Addr::new(198, 51, 100, 20));
    assert_eq!(ip.header_length, 20);
    assert_eq!(ip.total_length, 20 + 8 + MARKER.len() as u16);
    assert_eq!(ip.ttl, 64);
    assert_eq!(ip.protocol, 17);
    assert_eq!(ip.protocol_name, Some("UDP"));
    assert!(ip.dont_fragment);
    assert!(!ip.more_fragments);
    assert!(ip.checksum_valid);
    assert_eq!(ip.identification, 0x1234);
    assert_eq!(ip.payload_length, 8 + MARKER.len() as u16);

    let Layer::Udp(u) = &packet.layers[2] else {
        panic!()
    };
    assert_eq!((u.source_port, u.destination_port), (40000, 9));
    assert_eq!(u.length, 8 + MARKER.len() as u16);
    assert_eq!(u.payload_length, MARKER.len() as u16);

    assert_eq!(packet.top_protocol(), Some(Protocol::Udp));
    assert_eq!(
        packet.endpoints(),
        Some(("192.0.2.10".into(), "198.51.100.20".into()))
    );
    assert_eq!(packet.info(), format!("40000 -> 9 len={}", MARKER.len()));
}

#[test]
fn tcp_with_options_and_flags() {
    let options = [2, 4, 0x05, 0xB4, 1, 1, 4, 2]; // MSS, NOP, NOP, SACK-permitted
    let segment = tcp(
        51000,
        443,
        TcpFlags::SYN | TcpFlags::ECE | TcpFlags::CWR,
        &options,
        &[],
    );
    let frame = ethernet(
        0x0800,
        &ipv4(
            &Ipv4 {
                protocol: 6,
                ..Ipv4::default()
            },
            &segment,
        ),
    );
    let packet = decode(&frame);
    assert_eq!(packet.status, DecodeStatus::Complete);
    let Layer::Tcp(t) = &packet.layers[2] else {
        panic!()
    };
    assert_eq!((t.source_port, t.destination_port), (51000, 443));
    assert_eq!((t.sequence_number, t.acknowledgment_number), (1000, 2000));
    assert_eq!(t.header_length, 28);
    assert_eq!(t.options_length, 8);
    assert_eq!(t.flags.names(), ["SYN", "ECE", "CWR"]);
    assert_eq!(t.window, 64240);
    assert_eq!(t.payload_length, 0);
    assert_eq!(
        packet.info(),
        "51000 -> 443 [SYN,ECE,CWR] seq=1000 win=64240 len=0"
    );
}

#[test]
fn tcp_payload_length_comes_from_ip_lengths() {
    let segment = tcp(
        443,
        51000,
        TcpFlags::PSH | TcpFlags::ACK | 0x100,
        &[],
        MARKER,
    );
    let frame = ethernet(
        0x0800,
        &ipv4(
            &Ipv4 {
                protocol: 6,
                ..Ipv4::default()
            },
            &segment,
        ),
    );
    let packet = decode(&frame);
    let Layer::Tcp(t) = &packet.layers[2] else {
        panic!()
    };
    assert_eq!(t.payload_length, MARKER.len() as u16);
    assert!(t.flags.contains(TcpFlags::AE));
    assert!(packet.info().contains("ack=2000"));
}

#[test]
fn icmp_echo_exposes_identifier_and_sequence_only() {
    let frame = ethernet(
        0x0800,
        &ipv4(
            &Ipv4 {
                protocol: 1,
                ..Ipv4::default()
            },
            &icmp_echo(8, 7, 3, MARKER),
        ),
    );
    let packet = decode(&frame);
    assert_eq!(packet.status, DecodeStatus::Complete);
    let Layer::Icmp(i) = &packet.layers[2] else {
        panic!()
    };
    assert_eq!((i.icmp_type, i.code), (8, 0));
    assert_eq!(i.type_name, Some("echo request"));
    assert_eq!((i.identifier, i.sequence), (Some(7), Some(3)));
    assert_eq!(i.payload_length, MARKER.len() as u16);
    assert_eq!(packet.info(), "echo request code=0 id=7 seq=3");

    // Non-echo messages carry no identifier/sequence.
    let unreachable = ethernet(
        0x0800,
        &ipv4(
            &Ipv4 {
                protocol: 1,
                ..Ipv4::default()
            },
            &icmp_echo(3, 0, 0, &[0; 28]),
        ),
    );
    let Layer::Icmp(i) = &decode(&unreachable).layers[2] else {
        panic!()
    };
    assert_eq!(i.type_name, Some("destination unreachable"));
    assert_eq!(i.identifier, None);
}

#[test]
fn arp_request_and_reply() {
    let request = decode(&ethernet(0x0806, &arp(1, IP4_A, [192, 0, 2, 1])));
    assert_eq!(request.status, DecodeStatus::Complete);
    assert_eq!(protocols(&request), [Protocol::Ethernet, Protocol::Arp]);
    let Layer::Arp(a) = &request.layers[1] else {
        panic!()
    };
    assert_eq!(a.operation_name, Some("request"));
    assert_eq!(a.sender_ip, Some(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(a.target_ip, Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(
        a.sender_mac.map(|m| m.to_string()).as_deref(),
        Some("02:00:00:00:00:01")
    );
    assert_eq!(request.info(), "who-has 192.0.2.1 tell 192.0.2.10");
    // ARP has no IP layer, so endpoints fall back to MAC addresses.
    assert_eq!(
        request.endpoints(),
        Some(("02:00:00:00:00:01".into(), "02:00:00:00:00:02".into()))
    );

    let reply = decode(&ethernet(0x0806, &arp(2, IP4_A, [192, 0, 2, 1])));
    assert_eq!(reply.info(), "192.0.2.10 is-at 02:00:00:00:00:01");
}

#[test]
fn arp_with_wrong_address_lengths_is_malformed() {
    let mut body = arp(1, IP4_A, IP4_B);
    body[4] = 8; // hardware address length
    let packet = decode(&ethernet(0x0806, &body));
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(protocols(&packet), [Protocol::Ethernet, Protocol::Arp]);

    let mut body = arp(1, IP4_A, IP4_B);
    body[0..2].copy_from_slice(&6u16.to_be_bytes()); // IEEE 802 hardware type
    let packet = decode(&ethernet(0x0806, &body));
    assert_eq!(packet.status, DecodeStatus::Unsupported);
    assert_eq!(codes(&packet), [DecodeWarningCode::UnsupportedArpFormat]);

    let packet = decode(&ethernet(0x0806, &arp(1, IP4_A, IP4_B)[..20]));
    assert_eq!(packet.status, DecodeStatus::Truncated);
}

#[test]
fn ipv6_tcp_udp_and_icmpv6() {
    let packet = decode(&ethernet(0x86DD, &ipv6(17, &udp(40005, 9, MARKER))));
    assert_eq!(packet.status, DecodeStatus::Complete);
    assert_eq!(
        protocols(&packet),
        [Protocol::Ethernet, Protocol::Ipv6, Protocol::Udp]
    );
    let Layer::Ipv6(ip) = &packet.layers[1] else {
        panic!()
    };
    assert_eq!(ip.source, "2001:db8::a".parse::<Ipv6Addr>().unwrap());
    assert_eq!(ip.destination, "2001:db8::14".parse::<Ipv6Addr>().unwrap());
    assert_eq!(ip.traffic_class, 0x2E);
    assert_eq!(ip.flow_label, 0x12345);
    assert_eq!(ip.hop_limit, 64);
    assert_eq!(ip.upper_layer_protocol, Some(17));
    assert!(ip.extension_headers.is_empty());
    assert_eq!(
        packet.endpoints(),
        Some(("2001:db8::a".into(), "2001:db8::14".into()))
    );

    let packet = decode(&ethernet(
        0x86DD,
        &ipv6(6, &tcp(1, 2, TcpFlags::RST, &[], &[])),
    ));
    assert_eq!(packet.top_protocol(), Some(Protocol::Tcp));
    assert_eq!(packet.status, DecodeStatus::Complete);

    let packet = decode(&ethernet(0x86DD, &ipv6(58, &icmp_echo(128, 1, 9, MARKER))));
    let Layer::Icmpv6(i) = &packet.layers[2] else {
        panic!()
    };
    assert_eq!(i.type_name, Some("echo request"));
    assert_eq!((i.identifier, i.sequence), (Some(1), Some(9)));

    let packet = decode(&ethernet(
        0x86DD,
        &ipv6(58, &icmp_echo(135, 0, 0, &[0; 16])),
    ));
    let Layer::Icmpv6(i) = &packet.layers[2] else {
        panic!()
    };
    assert_eq!(i.type_name, Some("neighbor solicitation"));
    assert_eq!(i.identifier, None);
}

#[test]
fn icmp_numbers_are_not_mixed_between_ip_versions() {
    // ICMPv6 (58) inside IPv4 and ICMP (1) inside IPv6 are not decoded.
    let packet = decode(&ethernet(
        0x0800,
        &ipv4(
            &Ipv4 {
                protocol: 58,
                ..Ipv4::default()
            },
            &[0; 8],
        ),
    ));
    assert_eq!(packet.status, DecodeStatus::Unsupported);
    let packet = decode(&ethernet(0x86DD, &ipv6(1, &[0; 8])));
    assert_eq!(packet.status, DecodeStatus::Unsupported);
    assert_eq!(codes(&packet), [DecodeWarningCode::UnsupportedIpProtocol]);
}

#[test]
fn ipv6_extension_headers_are_traversed() {
    let mut payload = ext_header(60, 0); // Hop-by-Hop -> Destination Options
    payload.extend(ext_header(43, 1)); // Destination Options (16 bytes) -> Routing
    payload.extend(ext_header(17, 0)); // Routing -> UDP
    payload.extend(udp(1000, 2000, MARKER));
    let packet = decode(&ethernet(0x86DD, &ipv6(0, &payload)));
    assert_eq!(
        packet.status,
        DecodeStatus::Complete,
        "{:?}",
        packet.warnings
    );
    let Layer::Ipv6(ip) = &packet.layers[1] else {
        panic!()
    };
    let chain: Vec<_> = ip
        .extension_headers
        .iter()
        .map(|h| (h.header_type, h.length))
        .collect();
    assert_eq!(chain, [(0, 8), (60, 16), (43, 8)]);
    assert_eq!(ip.upper_layer_protocol, Some(17));
    let Layer::Udp(u) = &packet.layers[2] else {
        panic!()
    };
    assert_eq!(u.payload_length, MARKER.len() as u16);
}

#[test]
fn ipv6_extension_header_problems() {
    // Hop-by-Hop after another header.
    let mut payload = ext_header(0, 0);
    payload.extend(ext_header(17, 0));
    let packet = decode(&ethernet(0x86DD, &ipv6(60, &payload)));
    assert_eq!(packet.status, DecodeStatus::Malformed);

    // Chain longer than the traversal limit.
    let mut payload = Vec::new();
    for _ in 0..=decoder::MAX_IPV6_EXTENSION_HEADERS {
        payload.extend(ext_header(60, 0));
    }
    let packet = decode(&ethernet(0x86DD, &ipv6(60, &payload)));
    assert_eq!(packet.status, DecodeStatus::Unsupported);
    assert_eq!(codes(&packet), [DecodeWarningCode::ExtensionHeaderLimit]);

    // Header claims more bytes than the declared payload length holds.
    let packet = decode(&ethernet(0x86DD, &ipv6(60, &[17, 4, 0, 0])));
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(codes(&packet), [DecodeWarningCode::LengthMismatch]);

    // The same header cut by a short snapshot length is a truncation.
    let mut full = ext_header(17, 4);
    full.extend(udp(1, 2, &[]));
    let frame = ethernet(0x86DD, &ipv6(60, &full));
    let packet = decode_snapped(&frame, 14 + 40 + 8);
    assert_eq!(packet.status, DecodeStatus::Truncated);

    // ESP hides everything after it.
    let packet = decode(&ethernet(0x86DD, &ipv6(50, &[0; 32])));
    assert_eq!(packet.status, DecodeStatus::Unsupported);
    assert_eq!(codes(&packet), [DecodeWarningCode::EncryptedPayload]);

    // No Next Header ends the packet cleanly.
    let packet = decode(&ethernet(0x86DD, &ipv6(59, &[])));
    assert_eq!(packet.status, DecodeStatus::Complete);
    assert_eq!(protocols(&packet), [Protocol::Ethernet, Protocol::Ipv6]);

    // Extension headers longer than the declared payload length.
    let mut payload = ext_header(17, 1);
    payload.extend(udp(1, 2, &[]));
    let frame = ethernet(0x86DD, &ipv6_with_length(60, 8, &payload));
    let packet = decode(&frame);
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(codes(&packet), [DecodeWarningCode::LengthMismatch]);
}

#[test]
fn ipv6_fragments() {
    let mut first = fragment_header(17, 0, true, 0xAABBCCDD);
    first.extend(udp(1000, 2000, &[0; 64]));
    let packet = decode(&ethernet(0x86DD, &ipv6(44, &first)));
    assert_eq!(packet.top_protocol(), Some(Protocol::Udp));
    assert_eq!(codes(&packet), [DecodeWarningCode::Fragment]);
    let Layer::Ipv6(ip) = &packet.layers[1] else {
        panic!()
    };
    let fragment = ip.fragment.unwrap();
    assert_eq!((fragment.offset, fragment.more_fragments), (0, true));
    assert_eq!(fragment.identification, 0xAABBCCDD);

    let mut later = fragment_header(17, 1448, false, 0xAABBCCDD);
    later.extend([0u8; 32]);
    let packet = decode(&ethernet(0x86DD, &ipv6(44, &later)));
    assert_eq!(packet.status, DecodeStatus::Complete);
    assert_eq!(protocols(&packet), [Protocol::Ethernet, Protocol::Ipv6]);
    assert!(packet.info().contains("fragment offset=1448"));
}

#[test]
fn ipv4_fragments_skip_transport_on_non_initial_fragments() {
    // First fragment: MF set, offset 0. The UDP header is decoded, but its
    // length covers the whole datagram, so no length mismatch is reported.
    let first = ipv4(
        &Ipv4 {
            flags_fragment: 0x2000,
            ..Ipv4::default()
        },
        &udp_with_length(1000, 2000, 1480, &[0; 16]),
    );
    let packet = decode(&ethernet(0x0800, &first));
    assert_eq!(packet.status, DecodeStatus::Complete);
    assert_eq!(packet.top_protocol(), Some(Protocol::Udp));
    assert_eq!(codes(&packet), [DecodeWarningCode::Fragment]);

    // Later fragment: offset 185 * 8 = 1480 bytes; bytes after the IP header
    // must not be read as UDP.
    let later = ipv4(
        &Ipv4 {
            flags_fragment: 185,
            ..Ipv4::default()
        },
        &[0xFF; 40],
    );
    let packet = decode(&ethernet(0x0800, &later));
    assert_eq!(packet.status, DecodeStatus::Complete);
    assert_eq!(protocols(&packet), [Protocol::Ethernet, Protocol::Ipv4]);
    let Layer::Ipv4(ip) = &packet.layers[1] else {
        panic!()
    };
    assert_eq!(ip.fragment_offset, 1480);
    assert!(packet.info().starts_with("fragment offset=1480"));
}

#[test]
fn vlan_tags_are_decoded_up_to_two() {
    let payload = ipv4(&Ipv4::default(), &udp(1, 2, &[]));
    let single = decode(&vlan_ethernet(&[(0x8100, 0xA00A)], 0x0800, &payload));
    assert_eq!(single.status, DecodeStatus::Complete);
    let Layer::Ethernet(eth) = &single.layers[0] else {
        panic!()
    };
    assert_eq!(eth.vlan_tags.len(), 1);
    let tag = eth.vlan_tags[0];
    assert_eq!(
        (tag.tpid, tag.priority, tag.drop_eligible, tag.vlan_id),
        (0x8100, 5, false, 10)
    );
    assert_eq!(eth.header_length, 18);
    assert_eq!(single.top_protocol(), Some(Protocol::Udp));

    let double = decode(&vlan_ethernet(
        &[(0x88A8, 100), (0x8100, 0x1014)],
        0x0800,
        &payload,
    ));
    let Layer::Ethernet(eth) = &double.layers[0] else {
        panic!()
    };
    assert_eq!(eth.vlan_tags.len(), 2);
    assert!(eth.vlan_tags[1].drop_eligible);
    assert_eq!(eth.header_length, 22);

    let triple = decode(&vlan_ethernet(
        &[(0x88A8, 1), (0x8100, 2), (0x8100, 3)],
        0x0800,
        &payload,
    ));
    assert_eq!(triple.status, DecodeStatus::Unsupported);
    assert_eq!(codes(&triple), [DecodeWarningCode::TooManyVlanTags]);
    let Layer::Ethernet(eth) = &triple.layers[0] else {
        panic!()
    };
    assert_eq!(eth.vlan_tags.len(), 2);
    assert_eq!(eth.ethertype, 0x8100);
    assert!(triple.endpoints().is_some());
}

#[test]
fn unsupported_link_types_and_ethertypes() {
    let raw_bytes = ipv4(&Ipv4::default(), &udp(1, 2, &[]));
    let raw = decode_packet(101, &raw_bytes, raw_bytes.len() as u32);
    assert_eq!(raw.status, DecodeStatus::Unsupported);
    assert!(raw.layers.is_empty());
    assert_eq!(codes(&raw), [DecodeWarningCode::UnsupportedLinkType]);
    assert_eq!(raw.warnings[0].protocol, None);

    let lldp = decode(&ethernet(0x88CC, &[0; 32]));
    assert_eq!(lldp.status, DecodeStatus::Unsupported);
    assert_eq!(protocols(&lldp), [Protocol::Ethernet]);
    assert_eq!(
        lldp.info(),
        "EtherType 0x88cc (LLDP) [unsupported: EtherType is not decoded]"
    );

    let llc = decode(&ethernet(46, &[0xAA; 46]));
    assert_eq!(llc.status, DecodeStatus::Unsupported);
    assert!(
        llc.info()
            .starts_with("IEEE 802.3 frame, length 46 [unsupported")
    );
    assert_eq!(codes(&llc), [DecodeWarningCode::UnsupportedEthertype]);

    let llc_short = decode(&ethernet(100, &[0xAA; 46]));
    assert!(codes(&llc_short).contains(&DecodeWarningCode::LengthMismatch));

    let invalid = decode(&ethernet(0x05FF, &[0; 46]));
    assert_eq!(invalid.status, DecodeStatus::Malformed);
}

#[test]
fn malformed_ipv4_headers() {
    let base = Ipv4::default();
    let cases = [
        (
            Ipv4 {
                version_ihl: Some(0x55),
                ..Ipv4::default()
            },
            "version",
        ),
        (
            Ipv4 {
                version_ihl: Some(0x44),
                ..Ipv4::default()
            },
            "IHL",
        ),
        (
            Ipv4 {
                total_length: Some(19),
                ..Ipv4::default()
            },
            "total length",
        ),
    ];
    let _ = base;
    for (opts, what) in cases {
        let packet = decode(&ethernet(0x0800, &ipv4(&opts, &udp(1, 2, &[]))));
        assert_eq!(packet.status, DecodeStatus::Malformed, "{what}");
        assert_eq!(protocols(&packet), [Protocol::Ethernet], "{what}");
        assert_eq!(
            codes(&packet),
            [DecodeWarningCode::InvalidHeaderField],
            "{what}"
        );
    }
}

#[test]
fn ipv4_options_and_bad_checksum() {
    let opts = Ipv4 {
        options: vec![1, 1, 1, 0], // NOP, NOP, NOP, EOL
        break_checksum: true,
        ..Ipv4::default()
    };
    let packet = decode(&ethernet(0x0800, &ipv4(&opts, &udp(1, 2, &[]))));
    assert_eq!(packet.status, DecodeStatus::Complete);
    let Layer::Ipv4(ip) = &packet.layers[1] else {
        panic!()
    };
    assert_eq!((ip.header_length, ip.options_length), (24, 4));
    assert!(!ip.checksum_valid);
    assert_eq!(codes(&packet), [DecodeWarningCode::BadIpv4Checksum]);
}

#[test]
fn malformed_transport_headers() {
    let tcp_opts = Ipv4 {
        protocol: 6,
        ..Ipv4::default()
    };
    let mut short_offset = tcp(1, 2, TcpFlags::ACK, &[], &[]);
    short_offset[12] = 0x40; // data offset 4
    let packet = decode(&ethernet(0x0800, &ipv4(&tcp_opts, &short_offset)));
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(packet.top_protocol(), Some(Protocol::Ipv4));

    let packet = decode(&ethernet(
        0x0800,
        &ipv4(&Ipv4::default(), &udp_with_length(1, 2, 4, &[])),
    ));
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(packet.top_protocol(), Some(Protocol::Udp));

    let packet = decode(&ethernet(
        0x0800,
        &ipv4(&Ipv4::default(), &udp_with_length(1, 2, 500, &[0; 8])),
    ));
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(codes(&packet), [DecodeWarningCode::LengthMismatch]);

    // A UDP length shorter than the IP payload is suspicious but decodable.
    let packet = decode(&ethernet(
        0x0800,
        &ipv4(&Ipv4::default(), &udp_with_length(1, 2, 8, &[0; 8])),
    ));
    assert_eq!(packet.status, DecodeStatus::Complete);
    assert_eq!(codes(&packet), [DecodeWarningCode::LengthMismatch]);
}

#[test]
fn malformed_ipv6_version() {
    let mut packet_bytes = ipv6(17, &udp(1, 2, &[]));
    packet_bytes[0] = 0x45;
    let packet = decode(&ethernet(0x86DD, &packet_bytes));
    assert_eq!(packet.status, DecodeStatus::Malformed);
}

#[test]
fn truncation_at_every_layer_is_reported_not_panicked() {
    let frame = ethernet(
        0x0800,
        &ipv4(
            &Ipv4 {
                protocol: 6,
                ..Ipv4::default()
            },
            &tcp(1, 2, TcpFlags::SYN, &[1, 1, 1, 1], &[]),
        ),
    );
    let mut seen_statuses = std::collections::BTreeSet::new();
    for len in 0..frame.len() {
        let packet = decode_snapped(&frame, len);
        seen_statuses.insert(packet.status);
        assert!(
            matches!(packet.status, DecodeStatus::Truncated),
            "length {len}: {:?}",
            packet.status
        );
    }
    assert_eq!(decode(&frame).status, DecodeStatus::Complete);
    assert_eq!(seen_statuses.len(), 1);
}

#[test]
fn ethernet_padding_is_ignored() {
    // A 42-byte frame padded to the 60-byte Ethernet minimum.
    let mut frame = ethernet(0x0800, &ipv4(&Ipv4::default(), &udp(1, 2, &[])));
    frame.resize(60, 0);
    let packet = decode(&frame);
    assert_eq!(packet.status, DecodeStatus::Complete);
    assert!(packet.warnings.is_empty(), "{:?}", packet.warnings);
}

#[test]
fn snaplen_truncated_payload_still_decodes_headers() {
    // The capture stopped after the UDP header; declared lengths are larger.
    let frame = udp_frame();
    let packet = decode_snapped(&frame, 14 + 20 + 8);
    assert_eq!(packet.status, DecodeStatus::Complete);
    let Layer::Udp(u) = &packet.layers[2] else {
        panic!()
    };
    assert_eq!(u.payload_length, MARKER.len() as u16);
}

#[test]
fn serialized_output_contains_no_payload() {
    let frames = [
        udp_frame(),
        ethernet(
            0x0800,
            &ipv4(
                &Ipv4 {
                    protocol: 6,
                    ..Ipv4::default()
                },
                &tcp(1, 2, TcpFlags::PSH, &[], MARKER),
            ),
        ),
        ethernet(0x86DD, &ipv6(58, &icmp_echo(128, 1, 1, MARKER))),
        ethernet(
            0x0800,
            &ipv4(
                &Ipv4 {
                    protocol: 1,
                    ..Ipv4::default()
                },
                &icmp_echo(0, 1, 1, MARKER),
            ),
        ),
    ];
    let marker = std::str::from_utf8(MARKER).unwrap();
    for frame in frames {
        let packet = decode(&frame);
        let json = serde_json::to_string(&packet).unwrap();
        assert!(!json.contains(marker));
        assert!(!packet.info().contains(marker));
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["status"], "complete");
        assert!(value["layers"][0]["layer"] == "ethernet");
    }
}

#[test]
fn json_shape_is_tagged_by_protocol() {
    let value = serde_json::to_value(decode(&udp_frame())).unwrap();
    assert_eq!(value["layers"][1]["layer"], "ipv4");
    assert_eq!(value["layers"][1]["protocol"], 17);
    assert_eq!(value["layers"][1]["source"], "192.0.2.10");
    assert_eq!(value["layers"][2]["layer"], "udp");
    assert_eq!(value["layers"][2]["destination_port"], 9);
    assert_eq!(value["warnings"], serde_json::json!([]));
}

#[test]
fn summary_counts_statuses_protocols_and_warnings() {
    let mut summary = decoder::DecodeSummary::default();
    summary.add(1, &decode(&udp_frame()));
    summary.add(2, &decode_snapped(&udp_frame(), 20));
    summary.add(3, &decode_packet(101, &[], 0));
    summary.add(4, &decode_packet(101, &[], 0));
    assert_eq!(summary.packets_decoded, 4);
    assert_eq!(summary.status_counts[&DecodeStatus::Complete], 1);
    assert_eq!(summary.status_counts[&DecodeStatus::Truncated], 1);
    assert_eq!(summary.status_counts[&DecodeStatus::Unsupported], 2);
    assert_eq!(summary.protocol_counts[&Protocol::Ethernet], 2);
    assert_eq!(summary.protocol_counts[&Protocol::Udp], 1);
    let link = summary
        .warnings
        .iter()
        .find(|w| w.code == DecodeWarningCode::UnsupportedLinkType)
        .unwrap();
    assert_eq!((link.count, link.first_packet_index), (2, 3));
    let json = serde_json::to_value(&summary).unwrap();
    assert_eq!(json["status_counts"]["unsupported"], 2);
    assert_eq!(json["protocol_counts"]["ipv4"], 1);
}

#[test]
fn non_initial_ipv6_fragments_never_parse_payload_as_headers() {
    // Fragment header (offset 24) says the next header is Destination
    // Options, but the bytes after it are continuation data that happen to
    // look like an extension header followed by TCP.
    let mut payload = fragment_header(60, 24, false, 7);
    payload.extend([6, 0, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41]);
    payload.extend(tcp(1, 2, TcpFlags::SYN, &[], &[]));
    let packet = decode(&ethernet(0x86DD, &ipv6(44, &payload)));
    assert_eq!(packet.status, DecodeStatus::Complete);
    assert_eq!(protocols(&packet), [Protocol::Ethernet, Protocol::Ipv6]);
    let Layer::Ipv6(ip) = &packet.layers[1] else {
        panic!()
    };
    let chain: Vec<u8> = ip.extension_headers.iter().map(|h| h.header_type).collect();
    assert_eq!(chain, [44], "only the fragment header itself is listed");
    // The fragment header's own next-header field is metadata.
    assert_eq!(ip.upper_layer_protocol, Some(60));
    assert!(packet.info().starts_with("fragment offset=24"));
}

#[test]
fn declared_lengths_that_are_too_small_are_length_mismatches() {
    // IPv4 total length leaves room for only 16 bytes of TCP.
    let opts = Ipv4 {
        protocol: 6,
        total_length: Some(36),
        ..Ipv4::default()
    };
    let packet = decode(&ethernet(
        0x0800,
        &ipv4(&opts, &tcp(1, 2, TcpFlags::ACK, &[], &[])),
    ));
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(codes(&packet), [DecodeWarningCode::LengthMismatch]);

    // IPv4 total length leaves room for only 6 bytes of ICMP.
    let opts = Ipv4 {
        protocol: 1,
        total_length: Some(26),
        ..Ipv4::default()
    };
    let packet = decode(&ethernet(0x0800, &ipv4(&opts, &icmp_echo(8, 1, 1, &[]))));
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(codes(&packet), [DecodeWarningCode::LengthMismatch]);

    // IPv6 payload length 10 cannot hold a TCP header.
    let frame = ethernet(
        0x86DD,
        &ipv6_with_length(6, 10, &tcp(1, 2, TcpFlags::ACK, &[], &[])),
    );
    let packet = decode(&frame);
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(codes(&packet), [DecodeWarningCode::LengthMismatch]);
}

#[test]
fn declared_lengths_beyond_a_complete_frame_are_length_mismatches() {
    // A 46-byte frame whose IPv4 header claims 1500 bytes.
    let opts = Ipv4 {
        total_length: Some(1500),
        ..Ipv4::default()
    };
    let frame = ethernet(0x0800, &ipv4(&opts, &udp_with_length(1, 2, 1480, &[0; 4])));
    let packet = decode(&frame);
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(codes(&packet), [DecodeWarningCode::LengthMismatch]);
    assert_eq!(
        packet.top_protocol(),
        Some(Protocol::Ipv4),
        "no inflated UDP layer"
    );

    // The same bytes from a capture whose snapshot length cut the frame.
    let packet = decode_packet(LINKTYPE_ETHERNET, &frame, 1514);
    assert_eq!(packet.status, DecodeStatus::Complete);
    assert_eq!(packet.top_protocol(), Some(Protocol::Udp));

    // IPv6 payload length beyond a complete frame.
    let frame = ethernet(0x86DD, &ipv6_with_length(17, 1000, &udp(1, 2, &[])));
    let packet = decode(&frame);
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(codes(&packet), [DecodeWarningCode::LengthMismatch]);
}

#[test]
fn zero_ipv6_payload_lengths() {
    let jumbo = decode(&ethernet(
        0x86DD,
        &ipv6_with_length(0, 0, &ext_header(17, 0)),
    ));
    assert_eq!(jumbo.status, DecodeStatus::Unsupported);
    let empty_tcp = decode(&ethernet(0x86DD, &ipv6_with_length(6, 0, &[])));
    assert_eq!(empty_tcp.status, DecodeStatus::Malformed);
    assert_eq!(codes(&empty_tcp), [DecodeWarningCode::LengthMismatch]);
}
