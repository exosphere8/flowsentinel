//! One-line summaries of decoded packets for tables.

use std::fmt::Write as _;

use crate::model::{DecodeStatus, DecodedPacket, Layer, Protocol, TcpFlags};

impl DecodedPacket {
    /// Innermost decoded protocol.
    pub fn top_protocol(&self) -> Option<Protocol> {
        self.layers.last().map(Layer::protocol)
    }

    /// Whether any layer is `protocol`.
    pub fn contains(&self, protocol: Protocol) -> bool {
        self.layers.iter().any(|l| l.protocol() == protocol)
    }

    /// Source and destination of the innermost addressing layer: IP addresses
    /// when present, otherwise MAC addresses.
    pub fn endpoints(&self) -> Option<(String, String)> {
        let ip = self.layers.iter().rev().find_map(|layer| match layer {
            Layer::Ipv4(h) => Some((h.source.to_string(), h.destination.to_string())),
            Layer::Ipv6(h) => Some((h.source.to_string(), h.destination.to_string())),
            _ => None,
        });
        ip.or_else(|| {
            self.layers.iter().find_map(|layer| match layer {
                Layer::Ethernet(h) => Some((h.source.to_string(), h.destination.to_string())),
                _ => None,
            })
        })
    }

    /// Short human-readable description, similar to Wireshark's Info column.
    /// Contains header metadata only.
    pub fn info(&self) -> String {
        let mut out = match self.layers.last() {
            None => String::new(),
            Some(Layer::Ethernet(h)) if h.ethertype <= 1500 => {
                format!("IEEE 802.3 frame, length {}", h.ethertype)
            }
            Some(Layer::Ethernet(h)) => match h.ethertype_name {
                Some(name) => format!("EtherType 0x{:04x} ({name})", h.ethertype),
                None => format!("EtherType 0x{:04x}", h.ethertype),
            },
            Some(Layer::Arp(a)) => match (a.operation, a.sender_ip, a.target_ip, a.sender_mac) {
                (1, Some(sender), Some(target), _) => format!("who-has {target} tell {sender}"),
                (2, Some(sender), _, Some(mac)) => format!("{sender} is-at {mac}"),
                _ => format!("ARP {}", a.operation_name.unwrap_or("operation")),
            },
            Some(Layer::Ipv4(h)) => {
                let proto = h.protocol_name.unwrap_or("unknown");
                if h.fragment_offset != 0 {
                    format!(
                        "fragment offset={} protocol={proto} ({})",
                        h.fragment_offset, h.protocol
                    )
                } else {
                    format!("protocol={proto} ({})", h.protocol)
                }
            }
            Some(Layer::Ipv6(h)) => match (h.fragment, h.upper_layer_protocol) {
                (Some(f), Some(_)) if f.offset != 0 => format!(
                    "fragment offset={} next={}",
                    f.offset,
                    h.upper_layer_name.unwrap_or("unknown")
                ),
                (_, Some(p)) => {
                    format!("next={} ({p})", h.upper_layer_name.unwrap_or("unknown"))
                }
                _ => format!("next header {}", h.next_header),
            },
            Some(Layer::Icmp(h) | Layer::Icmpv6(h)) => {
                let mut text = match h.type_name {
                    Some(name) => name.to_owned(),
                    None => format!("type {}", h.icmp_type),
                };
                let _ = write!(text, " code={}", h.code);
                if let (Some(id), Some(seq)) = (h.identifier, h.sequence) {
                    let _ = write!(text, " id={id} seq={seq}");
                }
                text
            }
            Some(Layer::Tcp(h)) => {
                let mut text = format!(
                    "{} -> {} [{}] seq={}",
                    h.source_port, h.destination_port, h.flags, h.sequence_number
                );
                if h.flags.contains(TcpFlags::ACK) {
                    let _ = write!(text, " ack={}", h.acknowledgment_number);
                }
                let _ = write!(text, " win={} len={}", h.window, h.payload_length);
                text
            }
            Some(Layer::Udp(h)) => format!(
                "{} -> {} len={}",
                h.source_port, h.destination_port, h.payload_length
            ),
        };
        if self.status != DecodeStatus::Complete {
            if !out.is_empty() {
                out.push(' ');
            }
            // Decoding returns right after recording why it stopped, so the
            // last warning is the reason.
            match self.warnings.last() {
                Some(reason) => {
                    let _ = write!(out, "[{}: {}]", self.status.as_str(), reason.detail);
                }
                None => {
                    let _ = write!(out, "[{}]", self.status.as_str());
                }
            }
        }
        out
    }
}

impl Layer {
    /// One-line description of this layer's header fields, for protocol-tree
    /// views. Contains header metadata only.
    pub fn describe(&self) -> String {
        match self {
            Self::Ethernet(h) => {
                let mut text = format!("{} -> {}", h.source, h.destination);
                for tag in &h.vlan_tags {
                    let _ = write!(
                        text,
                        ", VLAN {} (TPID 0x{:04x}, priority {}{})",
                        tag.vlan_id,
                        tag.tpid,
                        tag.priority,
                        if tag.drop_eligible {
                            ", drop eligible"
                        } else {
                            ""
                        }
                    );
                }
                if h.ethertype <= 1500 {
                    let _ = write!(text, ", 802.3 length {}", h.ethertype);
                } else {
                    let _ = write!(text, ", type 0x{:04x}", h.ethertype);
                    if let Some(name) = h.ethertype_name {
                        let _ = write!(text, " ({name})");
                    }
                }
                let _ = write!(text, ", header {} bytes", h.header_length);
                text
            }
            Self::Arp(a) => {
                let mut text = format!(
                    "{} (operation {}), hardware type {}, protocol type 0x{:04x}",
                    a.operation_name.unwrap_or("unknown"),
                    a.operation,
                    a.hardware_type,
                    a.protocol_type
                );
                if let (Some(smac), Some(sip), Some(tmac), Some(tip)) =
                    (a.sender_mac, a.sender_ip, a.target_mac, a.target_ip)
                {
                    let _ = write!(text, ", sender {smac} {sip}, target {tmac} {tip}");
                }
                text
            }
            Self::Ipv4(h) => {
                let mut text = format!(
                    "{} -> {}, ttl {}, id 0x{:04x}",
                    h.source, h.destination, h.ttl, h.identification
                );
                if h.dont_fragment {
                    text.push_str(", DF");
                }
                if h.more_fragments {
                    text.push_str(", MF");
                }
                if h.fragment_offset != 0 {
                    let _ = write!(text, ", fragment offset {}", h.fragment_offset);
                }
                let _ = write!(
                    text,
                    ", dscp {}, ecn {}, header {} bytes (options {}), total {}, payload {}, protocol {} ({}), checksum {}",
                    h.dscp,
                    h.ecn,
                    h.header_length,
                    h.options_length,
                    h.total_length,
                    h.payload_length,
                    h.protocol_name.unwrap_or("unknown"),
                    h.protocol,
                    if h.checksum_valid { "ok" } else { "bad" }
                );
                text
            }
            Self::Ipv6(h) => {
                let mut text = format!(
                    "{} -> {}, hop limit {}, traffic class 0x{:02x}, flow label 0x{:05x}, payload {}",
                    h.source,
                    h.destination,
                    h.hop_limit,
                    h.traffic_class,
                    h.flow_label,
                    h.payload_length
                );
                if !h.extension_headers.is_empty() {
                    let chain: Vec<String> = h
                        .extension_headers
                        .iter()
                        .map(|e| format!("{} ({} bytes)", e.name, e.length))
                        .collect();
                    let _ = write!(text, ", extension headers: {}", chain.join(", "));
                }
                if let Some(f) = h.fragment {
                    let _ = write!(
                        text,
                        ", fragment offset {}{} id 0x{:08x}",
                        f.offset,
                        if f.more_fragments { " MF" } else { "" },
                        f.identification
                    );
                }
                match h.upper_layer_protocol {
                    Some(p) => {
                        let _ = write!(
                            text,
                            ", next {} ({p})",
                            h.upper_layer_name.unwrap_or("unknown")
                        );
                    }
                    None => {
                        let _ = write!(text, ", next header {}", h.next_header);
                    }
                }
                text
            }
            Self::Icmp(h) | Self::Icmpv6(h) => {
                let mut text = format!(
                    "{} (type {}, code {})",
                    h.type_name.unwrap_or("unknown"),
                    h.icmp_type,
                    h.code
                );
                if let (Some(id), Some(seq)) = (h.identifier, h.sequence) {
                    let _ = write!(text, ", id {id}, seq {seq}");
                }
                let _ = write!(text, ", payload {} bytes", h.payload_length);
                text
            }
            Self::Tcp(h) => format!(
                "{} -> {}, flags {}, seq {}, ack {}, window {}, urgent {}, header {} bytes (options {}), payload {} bytes",
                h.source_port,
                h.destination_port,
                h.flags,
                h.sequence_number,
                h.acknowledgment_number,
                h.window,
                h.urgent_pointer,
                h.header_length,
                h.options_length,
                h.payload_length
            ),
            Self::Udp(h) => format!(
                "{} -> {}, length {}, payload {} bytes",
                h.source_port, h.destination_port, h.length, h.payload_length
            ),
        }
    }

    /// Display name of this layer's protocol.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ethernet(_) => "Ethernet II",
            other => other.protocol().as_str(),
        }
    }
}
