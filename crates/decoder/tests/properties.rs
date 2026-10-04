//! Property tests: decoding arbitrary bytes never panics, and structured
//! random headers never produce inconsistent results.

mod common;

use common::*;
use decoder::{DecodeStatus, LINKTYPE_ETHERNET, Layer, decode_packet};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn arbitrary_bytes_never_panic(link_type in prop_oneof![Just(1u16), any::<u16>()],
                                   data in proptest::collection::vec(any::<u8>(), 0..1600),
                                   extra_wire_bytes in prop_oneof![Just(0u32), any::<u32>()]) {
        let wire_length = (data.len() as u32).saturating_add(extra_wire_bytes);
        let packet = decode_packet(link_type, &data, wire_length);
        // Results always serialize, and warnings stay bounded.
        prop_assert!(serde_json::to_string(&packet).is_ok());
        prop_assert!(packet.warnings.len() <= 8);
        prop_assert!(packet.layers.len() <= 4);
    }

    /// Valid Ethernet + IPv4 headers followed by arbitrary transport bytes.
    #[test]
    fn arbitrary_ipv4_transport_never_panics(protocol in prop_oneof![Just(1u8), Just(6u8), Just(17u8), any::<u8>()],
                                            flags_fragment in any::<u16>(),
                                            body in proptest::collection::vec(any::<u8>(), 0..256)) {
        let opts = Ipv4 { protocol, flags_fragment, ..Ipv4::default() };
        let frame = ethernet(0x0800, &ipv4(&opts, &body));
        let packet = decode_packet(LINKTYPE_ETHERNET, &frame, frame.len() as u32);
        prop_assert!(matches!(packet.layers.get(1), Some(Layer::Ipv4(_))));
        // Non-initial fragments never decode a transport layer.
        if flags_fragment & 0x1FFF != 0 {
            prop_assert_eq!(packet.layers.len(), 2);
        }
    }

    /// Valid IPv6 header followed by an arbitrary extension-header chain.
    #[test]
    fn arbitrary_ipv6_chains_never_panic(next_header in prop_oneof![Just(0u8), Just(43u8), Just(44u8), Just(51u8), Just(60u8), any::<u8>()],
                                         body in proptest::collection::vec(any::<u8>(), 0..512)) {
        let frame = ethernet(0x86DD, &ipv6(next_header, &body));
        let packet = decode_packet(LINKTYPE_ETHERNET, &frame, frame.len() as u32);
        prop_assert!(matches!(packet.layers.get(1), Some(Layer::Ipv6(_))));
        if let Some(Layer::Ipv6(ip)) = packet.layers.get(1) {
            prop_assert!(ip.extension_headers.len() <= decoder::MAX_IPV6_EXTENSION_HEADERS);
            // Nothing after a non-initial fragment header is parsed.
            if ip.fragment.is_some_and(|f| f.offset != 0) {
                prop_assert_eq!(packet.layers.len(), 2);
                prop_assert_eq!(ip.extension_headers.last().map(|h| h.header_type), Some(44));
            }
        }
    }

    /// Well-formed UDP datagrams decode completely with exact lengths.
    #[test]
    fn well_formed_udp_round_trips(sport in any::<u16>(), dport in any::<u16>(),
                                   payload in proptest::collection::vec(any::<u8>(), 0..1400),
                                   v6 in any::<bool>()) {
        let datagram = udp(sport, dport, &payload);
        let frame = if v6 {
            ethernet(0x86DD, &ipv6(17, &datagram))
        } else {
            ethernet(0x0800, &ipv4(&Ipv4::default(), &datagram))
        };
        let packet = decode_packet(LINKTYPE_ETHERNET, &frame, frame.len() as u32);
        prop_assert_eq!(packet.status, DecodeStatus::Complete);
        let Some(Layer::Udp(u)) = packet.layers.get(2) else {
            return Err(TestCaseError::fail("missing UDP layer"));
        };
        prop_assert_eq!((u.source_port, u.destination_port), (sport, dport));
        prop_assert_eq!(usize::from(u.payload_length), payload.len());
    }
}
