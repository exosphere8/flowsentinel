//! One-line summaries of decoded packets for tables.

use std::fmt::Write as _;

use crate::app::dhcp::DhcpMessage;
use crate::app::dns::DnsMessage;
use crate::app::http::{HttpKind, HttpMessage};
use crate::app::tls::{self, TlsHandshake};
use crate::model::{DecodeStatus, DecodedPacket, Layer, Protocol, TcpFlags};

/// Answers listed in one-line DNS descriptions.
const DESCRIBED_ANSWERS: usize = 8;

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
            Some(Layer::Dns(m)) => dns_info(m),
            Some(Layer::Dhcp(m)) => dhcp_info(m),
            Some(Layer::Http(m)) => http_info(m),
            Some(Layer::Tls(m)) => tls_info(m),
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
            Self::Dns(m) => dns_describe(m),
            Self::Dhcp(m) => dhcp_describe(m),
            Self::Http(m) => http_describe(m),
            Self::Tls(m) => tls_describe(m),
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

fn dns_info(m: &DnsMessage) -> String {
    let kind = if m.is_response { "response" } else { "query" };
    let mut text = format!("{kind} 0x{:04x}", m.transaction_id);
    if m.is_response {
        let _ = write!(text, " {}", m.response_code_name.unwrap_or("rcode"));
    }
    if let Some(q) = m.questions.first() {
        let _ = write!(text, " {} {}", q.type_name.unwrap_or("TYPE"), q.name);
    }
    let data: Vec<&str> = m
        .answers
        .iter()
        .filter_map(|a| a.data.as_deref())
        .take(3)
        .collect();
    if !data.is_empty() {
        let _ = write!(text, " -> {}", data.join(", "));
    }
    if usize::from(m.answer_count) > data.len() {
        let _ = write!(text, " (answers: {})", m.answer_count);
    }
    text
}

fn dns_describe(m: &DnsMessage) -> String {
    let mut flags = Vec::new();
    for (set, name) in [
        (m.authoritative, "AA"),
        (m.truncated, "TC"),
        (m.recursion_desired, "RD"),
        (m.recursion_available, "RA"),
    ] {
        if set {
            flags.push(name);
        }
    }
    let mut text = format!(
        "{} over {}, id 0x{:04x}, opcode {}, ",
        if m.is_response { "response" } else { "query" },
        match m.transport {
            crate::app::AppTransport::Udp => "UDP",
            crate::app::AppTransport::Tcp => "TCP",
        },
        m.transaction_id,
        m.opcode_name.unwrap_or("unknown"),
    );
    if m.is_response {
        let _ = write!(
            text,
            "rcode {}, ",
            m.response_code_name.unwrap_or("unknown")
        );
    }
    let _ = write!(
        text,
        "flags [{}], questions {}, answers {}, authority {}, additional {}",
        flags.join(" "),
        m.question_count,
        m.answer_count,
        m.authority_count,
        m.additional_count
    );
    for q in &m.questions {
        let _ = write!(
            text,
            "; question {} {} class {}",
            q.name,
            q.type_name.unwrap_or("TYPE"),
            q.class
        );
    }
    for a in m.answers.iter().take(DESCRIBED_ANSWERS) {
        let _ = write!(
            text,
            "; answer {} {} ttl {}",
            a.name,
            a.type_name.unwrap_or("TYPE"),
            a.ttl
        );
        match &a.data {
            Some(data) => {
                let _ = write!(text, " {data}");
            }
            None => {
                let _ = write!(text, " ({} bytes of data not shown)", a.data_length);
            }
        }
    }
    if m.answers.len() > DESCRIBED_ANSWERS {
        let _ = write!(
            text,
            "; +{} more answers",
            m.answers.len() - DESCRIBED_ANSWERS
        );
    }
    text
}

fn dhcp_info(m: &DhcpMessage) -> String {
    let mut text = format!(
        "{} xid 0x{:08x}",
        m.message_type_name.unwrap_or("BOOTP"),
        m.transaction_id
    );
    if !m.your_ip.is_unspecified() {
        let _ = write!(text, " your={}", m.your_ip);
    }
    if let Some(ip) = m.requested_ip {
        let _ = write!(text, " requested={ip}");
    }
    text
}

fn dhcp_describe(m: &DhcpMessage) -> String {
    let mut text = format!(
        "{} ({}), xid 0x{:08x}, hardware type {} length {}{}, client {}, your {}, server {}, relay {}",
        m.message_type_name.unwrap_or("no message type"),
        m.op,
        m.transaction_id,
        m.hardware_type,
        m.hardware_address_length,
        if m.broadcast { ", broadcast" } else { "" },
        m.client_ip,
        m.your_ip,
        m.server_ip,
        m.relay_ip
    );
    if let Some(mac) = m.client_mac {
        let _ = write!(text, ", client MAC {mac}");
    }
    if let Some(ip) = m.requested_ip {
        let _ = write!(text, ", requested {ip}");
    }
    if let Some(ip) = m.server_identifier {
        let _ = write!(text, ", server identifier {ip}");
    }
    if let Some(lease) = m.lease_time_seconds {
        let _ = write!(text, ", lease {lease} s");
    }
    if let Some(host) = &m.hostname {
        let _ = write!(text, ", hostname {host}");
    }
    let codes: Vec<String> = m.option_codes.iter().map(u8::to_string).collect();
    let _ = write!(text, ", options [{}]", codes.join(" "));
    text
}

fn http_info(m: &HttpMessage) -> String {
    let mut text = match m.kind {
        HttpKind::Request => format!(
            "{} {} {}",
            m.method.unwrap_or("?"),
            m.path.as_deref().unwrap_or(if m.method == Some("CONNECT") {
                "[connect target]"
            } else {
                "[target withheld]"
            }),
            m.version
        ),
        HttpKind::Response => format!(
            "{} {} {}",
            m.version,
            m.status_code.unwrap_or(0),
            m.reason.as_deref().unwrap_or("")
        ),
    };
    if m.kind == HttpKind::Request {
        if let Some(host) = &m.host {
            let _ = write!(text, " host={host}");
        }
    }
    if m.query_redacted
        || m.userinfo_redacted
        || m.target_withheld
        || m.path_segments_redacted > 0
        || !m.redacted_headers.is_empty()
    {
        text.push_str(" [redacted]");
    }
    text
}

fn http_describe(m: &HttpMessage) -> String {
    let mut text = match m.kind {
        HttpKind::Request => format!(
            "request {} {}{} {}",
            m.method.unwrap_or("?"),
            m.path.as_deref().unwrap_or("-"),
            if m.path_truncated { "..." } else { "" },
            m.version
        ),
        HttpKind::Response => format!(
            "response {} {} {}",
            m.version,
            m.status_code.unwrap_or(0),
            m.reason.as_deref().unwrap_or("")
        ),
    };
    if let Some(host) = &m.host {
        let _ = write!(text, ", host {host}");
    }
    if let Some(len) = m.content_length {
        let _ = write!(text, ", content length {len}");
    }
    if let Some(ct) = &m.content_type {
        let _ = write!(text, ", content type {ct}");
    }
    if let Some(conn) = &m.connection {
        let _ = write!(text, ", connection {conn}");
    }
    if m.chunked {
        text.push_str(", chunked");
    }
    if m.query_redacted {
        text.push_str(", query string redacted");
    }
    if m.userinfo_redacted {
        text.push_str(", URL credentials redacted");
    }
    if m.target_withheld {
        text.push_str(", request target withheld");
    }
    if m.path_segments_redacted > 0 {
        let _ = write!(
            text,
            ", {} path segments redacted",
            m.path_segments_redacted
        );
    }
    if !m.redacted_headers.is_empty() {
        let _ = write!(text, ", redacted headers: {}", m.redacted_headers.join(" "));
    }
    let _ = write!(
        text,
        ", {} header lines ({})",
        m.header_count,
        match m.header_block {
            crate::app::http::HeaderBlock::Complete => "complete",
            crate::app::http::HeaderBlock::Incomplete => "continues beyond this packet",
            crate::app::http::HeaderBlock::Stopped => "parsing stopped",
        }
    );
    text
}

fn version_label(version: u16) -> String {
    tls::version_name(version).map_or_else(|| format!("0x{version:04x}"), str::to_owned)
}

fn tls_info(m: &TlsHandshake) -> String {
    let mut text = if m.handshake_type_name == "client_hello" {
        "TLS ClientHello".to_owned()
    } else {
        "TLS ServerHello".to_owned()
    };
    if let Some(sni) = &m.server_name {
        let _ = write!(text, " SNI={sni}");
    }
    if !m.alpn.is_empty() {
        let _ = write!(text, " ALPN={}", m.alpn.join(","));
    }
    if let Some(v) = m.negotiated_version {
        let _ = write!(text, " {}", version_label(v));
    }
    if m.handshake_type_name == "server_hello" {
        if let Some(suite) = m.cipher_suites.first() {
            let _ = write!(text, " cipher=0x{suite:04x}");
        }
    }
    text.push_str(" (handshake metadata only)");
    text
}

fn tls_describe(m: &TlsHandshake) -> String {
    let list = |values: &[u16]| {
        values
            .iter()
            .map(|v| version_label(*v))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let hex = |values: &[u16]| {
        values
            .iter()
            .map(|v| format!("0x{v:04x}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut text = format!(
        "{}: {}, record {}, hello version {}",
        m.visibility,
        m.handshake_type_name,
        version_label(m.record_version),
        version_label(m.hello_version)
    );
    if let Some(sni) = &m.server_name {
        let _ = write!(text, ", SNI {sni}");
    }
    if !m.alpn.is_empty() {
        let _ = write!(text, ", ALPN {}", m.alpn.join(","));
    }
    if !m.supported_versions.is_empty() {
        let _ = write!(
            text,
            ", supported versions [{}]",
            list(&m.supported_versions)
        );
    }
    if let Some(v) = m.negotiated_version {
        let _ = write!(text, ", negotiated {}", version_label(v));
    }
    if !m.supported_groups.is_empty() {
        let _ = write!(text, ", groups [{}]", hex(&m.supported_groups));
    }
    let _ = write!(
        text,
        ", cipher suites {} [{}]",
        m.cipher_suite_count,
        hex(&m.cipher_suites)
    );
    let names: Vec<String> = m
        .extensions
        .iter()
        .map(|e| {
            e.name
                .map_or_else(|| format!("0x{:04x}", e.extension_type), str::to_owned)
        })
        .collect();
    let _ = write!(text, ", extensions [{}]", names.join(" "));
    if !m.complete {
        text.push_str(", handshake not complete in this packet");
    }
    text
}
