//! Extracts what the flow engine needs from a decoded packet.

use std::net::IpAddr;

use decoder::{DecodedPacket, Layer, TcpFlags};

use crate::key::{Endpoint, FlowKey};

/// TCP fields used for state tracking and duplicate detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpView {
    pub flags: TcpFlags,
    pub sequence: u32,
    pub payload_length: u16,
}

/// The flow-relevant facts of one IP packet.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Observation<'a> {
    pub key: FlowKey,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub tcp: Option<TcpView>,
    pub payload_bytes: u64,
    /// A non-initial fragment, which carries no ports.
    pub portless_fragment: bool,
    /// A TCP or UDP packet whose transport header is missing (cut by the
    /// snapshot length or malformed), so its ports are unknown.
    pub missing_transport: bool,
    /// The application layer, if one was decoded.
    pub application: Option<&'a Layer>,
}

/// Returns `None` for packets without an IP layer (ARP, unsupported or
/// malformed link layers), which do not belong to any flow.
pub(crate) fn observe(packet: &DecodedPacket) -> Option<Observation<'_>> {
    let (ip_index, source_ip, destination_ip, protocol, ip_payload, fragment_offset) = packet
        .layers
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, layer)| match layer {
            Layer::Ipv4(h) => Some((
                i,
                IpAddr::V4(h.source),
                IpAddr::V4(h.destination),
                h.protocol,
                u64::from(h.payload_length),
                h.fragment_offset,
            )),
            Layer::Ipv6(h) => Some((
                i,
                IpAddr::V6(h.source),
                IpAddr::V6(h.destination),
                h.upper_layer_protocol.unwrap_or(h.next_header),
                u64::from(h.payload_length),
                h.fragment.map_or(0, |f| f.offset),
            )),
            _ => None,
        })?;

    let mut source_port = 0;
    let mut destination_port = 0;
    let mut has_transport = false;
    let mut tcp = None;
    let mut payload_bytes = ip_payload;
    let mut application = None;
    for layer in packet.layers.iter().skip(ip_index + 1) {
        match layer {
            Layer::Tcp(h) => {
                has_transport = true;
                (source_port, destination_port) = (h.source_port, h.destination_port);
                payload_bytes = u64::from(h.payload_length);
                tcp = Some(TcpView {
                    flags: h.flags,
                    sequence: h.sequence_number,
                    payload_length: h.payload_length,
                });
            }
            Layer::Udp(h) => {
                has_transport = true;
                (source_port, destination_port) = (h.source_port, h.destination_port);
                payload_bytes = u64::from(h.payload_length);
            }
            Layer::Icmp(h) | Layer::Icmpv6(h) => payload_bytes = u64::from(h.payload_length),
            Layer::Dns(_) | Layer::Dhcp(_) | Layer::Http(_) | Layer::Tls(_) => {
                application = Some(layer);
            }
            _ => {}
        }
    }

    let source = Endpoint {
        ip: source_ip,
        port: source_port,
    };
    let destination = Endpoint {
        ip: destination_ip,
        port: destination_port,
    };
    Some(Observation {
        key: FlowKey::new(protocol, source, destination),
        source,
        destination,
        tcp,
        payload_bytes,
        portless_fragment: fragment_offset != 0,
        missing_transport: matches!(protocol, 6 | 17) && fragment_offset == 0 && !has_transport,
        application,
    })
}
