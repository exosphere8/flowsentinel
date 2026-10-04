//! The fields a filter may use, per target, and how each maps to SQL.
//!
//! Every SQL fragment here is a `'static` string from this file. User input
//! never becomes SQL text: it only becomes bound parameters.

/// What a filter selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Packets,
    Flows,
}

/// The type of a field's values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// An IPv4/IPv6 address or CIDR block; `==` means "within".
    Ip,
    /// An unsigned integer up to `max`.
    UInt { max: u64 },
    /// A non-negative decimal number.
    Float,
    /// Text; `==` and `contains` ignore letter case.
    Text,
    /// One of a fixed set of lowercase words.
    Enum(&'static [&'static str]),
    /// True or false; usable bare (`tcp.flags.syn`).
    Bool,
}

impl FieldType {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip address or cidr",
            Self::UInt { .. } => "unsigned integer",
            Self::Float => "number",
            Self::Text => "text",
            Self::Enum(_) => "keyword",
            Self::Bool => "boolean",
        }
    }
}

/// How a field is read in SQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    /// One column.
    One(&'static str),
    /// Either of two columns (for example source or destination address).
    Either(&'static str, &'static str),
    /// A boolean SQL expression (presence fields and flag bits).
    Predicate(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    pub name: &'static str,
    pub field_type: FieldType,
    pub column: Column,
    /// Extra condition that must also hold, for example `tcp.port` implies
    /// the packet is TCP.
    pub guard: Option<&'static str>,
    pub description: &'static str,
}

const DECODE_STATUS: &[&str] = &["complete", "unsupported", "truncated", "malformed"];
const TCP_STATES: &[&str] = &[
    "syn_sent",
    "syn_received",
    "established",
    "midstream",
    "closing",
    "closed",
    "reset",
];
const END_REASONS: &[&str] = &[
    "idle_timeout",
    "tcp_finished",
    "evicted",
    "capture_end",
    "clock_reset",
];
/// Flows without ports (other protocols, or TCP/UDP seen only as fragments)
/// store port 0 on both sides; port fields must not match them.
const PORTED: Option<&str> =
    Some("protocol IN (6, 17) AND (initiator_port <> 0 OR responder_port <> 0)");
const SEVERITIES: &[&str] = &["low", "medium", "high"];
const U16: FieldType = FieldType::UInt { max: 65_535 };

const fn field(
    name: &'static str,
    field_type: FieldType,
    column: Column,
    guard: Option<&'static str>,
    description: &'static str,
) -> Field {
    Field {
        name,
        field_type,
        column,
        guard,
        description,
    }
}

use Column::{Either, One, Predicate};
use FieldType::{Bool, Enum, Float, Ip, Text, UInt};

pub const PACKET_FIELDS: &[Field] = &[
    field(
        "frame.number",
        UInt { max: u64::MAX >> 1 },
        One("packet_index"),
        None,
        "1-based packet index",
    ),
    field(
        "frame.len",
        UInt {
            max: u32::MAX as u64,
        },
        One("original_length"),
        None,
        "on-the-wire length in bytes",
    ),
    field(
        "frame.cap_len",
        UInt {
            max: u32::MAX as u64,
        },
        One("captured_length"),
        None,
        "captured length in bytes",
    ),
    field("ip.src", Ip, One("src_ip"), None, "source IP address"),
    field("ip.dst", Ip, One("dst_ip"), None, "destination IP address"),
    field(
        "ip.addr",
        Ip,
        Either("src_ip", "dst_ip"),
        None,
        "source or destination IP address",
    ),
    field(
        "ip.proto",
        UInt { max: 255 },
        One("ip_protocol"),
        None,
        "IP protocol number",
    ),
    field(
        "port",
        U16,
        Either("src_port", "dst_port"),
        None,
        "TCP or UDP source or destination port",
    ),
    field(
        "tcp.port",
        U16,
        Either("src_port", "dst_port"),
        Some("'tcp' = ANY(protocols)"),
        "TCP source or destination port",
    ),
    field(
        "tcp.srcport",
        U16,
        One("src_port"),
        Some("'tcp' = ANY(protocols)"),
        "TCP source port",
    ),
    field(
        "tcp.dstport",
        U16,
        One("dst_port"),
        Some("'tcp' = ANY(protocols)"),
        "TCP destination port",
    ),
    field(
        "udp.port",
        U16,
        Either("src_port", "dst_port"),
        Some("'udp' = ANY(protocols)"),
        "UDP source or destination port",
    ),
    field(
        "udp.srcport",
        U16,
        One("src_port"),
        Some("'udp' = ANY(protocols)"),
        "UDP source port",
    ),
    field(
        "udp.dstport",
        U16,
        One("dst_port"),
        Some("'udp' = ANY(protocols)"),
        "UDP destination port",
    ),
    field(
        "tcp.flags.fin",
        Bool,
        Predicate("(tcp_flags & 1) <> 0"),
        None,
        "TCP FIN flag",
    ),
    field(
        "tcp.flags.syn",
        Bool,
        Predicate("(tcp_flags & 2) <> 0"),
        None,
        "TCP SYN flag",
    ),
    field(
        "tcp.flags.rst",
        Bool,
        Predicate("(tcp_flags & 4) <> 0"),
        None,
        "TCP RST flag",
    ),
    field(
        "tcp.flags.psh",
        Bool,
        Predicate("(tcp_flags & 8) <> 0"),
        None,
        "TCP PSH flag",
    ),
    field(
        "tcp.flags.ack",
        Bool,
        Predicate("(tcp_flags & 16) <> 0"),
        None,
        "TCP ACK flag",
    ),
    field(
        "tcp.flags.urg",
        Bool,
        Predicate("(tcp_flags & 32) <> 0"),
        None,
        "TCP URG flag",
    ),
    field(
        "dns.qry.name",
        Text,
        One("dns_query"),
        None,
        "first DNS question name",
    ),
    field("http.host", Text, One("http_host"), None, "HTTP host"),
    field(
        "tls.sni",
        Text,
        One("tls_sni"),
        None,
        "TLS server name (SNI)",
    ),
    field(
        "decode.status",
        Enum(DECODE_STATUS),
        One("decode_status"),
        None,
        "decode status",
    ),
    field(
        "ethernet",
        Bool,
        Predicate("'ethernet' = ANY(protocols)"),
        None,
        "has an Ethernet layer",
    ),
    field(
        "arp",
        Bool,
        Predicate("'arp' = ANY(protocols)"),
        None,
        "is ARP",
    ),
    field(
        "ip",
        Bool,
        Predicate("('ipv4' = ANY(protocols) OR 'ipv6' = ANY(protocols))"),
        None,
        "has an IPv4 or IPv6 layer",
    ),
    field(
        "ipv4",
        Bool,
        Predicate("'ipv4' = ANY(protocols)"),
        None,
        "has an IPv4 layer",
    ),
    field(
        "ipv6",
        Bool,
        Predicate("'ipv6' = ANY(protocols)"),
        None,
        "has an IPv6 layer",
    ),
    field(
        "icmp",
        Bool,
        Predicate("'icmp' = ANY(protocols)"),
        None,
        "is ICMP",
    ),
    field(
        "icmpv6",
        Bool,
        Predicate("'icmpv6' = ANY(protocols)"),
        None,
        "is ICMPv6",
    ),
    field(
        "tcp",
        Bool,
        Predicate("'tcp' = ANY(protocols)"),
        None,
        "is TCP",
    ),
    field(
        "udp",
        Bool,
        Predicate("'udp' = ANY(protocols)"),
        None,
        "is UDP",
    ),
    field(
        "dns",
        Bool,
        Predicate("'dns' = ANY(protocols)"),
        None,
        "carries DNS",
    ),
    field(
        "dhcp",
        Bool,
        Predicate("'dhcp' = ANY(protocols)"),
        None,
        "carries DHCP",
    ),
    field(
        "http",
        Bool,
        Predicate("'http' = ANY(protocols)"),
        None,
        "carries HTTP",
    ),
    field(
        "tls",
        Bool,
        Predicate("'tls' = ANY(protocols)"),
        None,
        "carries a TLS handshake",
    ),
];

pub const FLOW_FIELDS: &[Field] = &[
    field(
        "flow.id",
        UInt { max: u64::MAX >> 1 },
        One("flow_id"),
        None,
        "flow ID",
    ),
    field(
        "flow.initiator",
        Ip,
        One("initiator_ip"),
        None,
        "initiator IP address",
    ),
    field(
        "flow.responder",
        Ip,
        One("responder_ip"),
        None,
        "responder IP address",
    ),
    field(
        "ip.addr",
        Ip,
        Either("initiator_ip", "responder_ip"),
        None,
        "either endpoint's IP address",
    ),
    field(
        "ip.version",
        UInt { max: 6 },
        One("ip_version"),
        None,
        "IP version (4 or 6)",
    ),
    field(
        "ip.proto",
        UInt { max: 255 },
        One("protocol"),
        None,
        "IP protocol number",
    ),
    field(
        "flow.initiator_port",
        U16,
        One("initiator_port"),
        PORTED,
        "initiator port",
    ),
    field(
        "flow.responder_port",
        U16,
        One("responder_port"),
        PORTED,
        "responder port",
    ),
    field(
        "port",
        U16,
        Either("initiator_port", "responder_port"),
        PORTED,
        "either endpoint's port",
    ),
    field(
        "tcp.port",
        U16,
        Either("initiator_port", "responder_port"),
        Some("protocol = 6"),
        "either TCP port",
    ),
    field(
        "udp.port",
        U16,
        Either("initiator_port", "responder_port"),
        Some("protocol = 17"),
        "either UDP port",
    ),
    field(
        "flow.bytes",
        UInt { max: u64::MAX >> 1 },
        One("bytes_total"),
        None,
        "bytes in both directions",
    ),
    field(
        "flow.packets",
        UInt { max: u64::MAX >> 1 },
        One("packets_total"),
        None,
        "packets in both directions",
    ),
    field(
        "flow.duration",
        Float,
        One("duration_seconds"),
        None,
        "duration in seconds",
    ),
    field(
        "flow.state",
        Enum(TCP_STATES),
        One("tcp_state"),
        None,
        "approximate TCP state",
    ),
    field(
        "flow.end_reason",
        Enum(END_REASONS),
        One("end_reason"),
        None,
        "why the flow ended",
    ),
    field(
        "dns.qry.name",
        Text,
        One("dns_query"),
        None,
        "first DNS name queried in the flow",
    ),
    field(
        "http.host",
        Text,
        One("http_host"),
        None,
        "first HTTP host in the flow",
    ),
    field(
        "tls.sni",
        Text,
        One("tls_sni"),
        None,
        "first TLS server name in the flow",
    ),
    field("ipv4", Bool, Predicate("ip_version = 4"), None, "is IPv4"),
    field("ipv6", Bool, Predicate("ip_version = 6"), None, "is IPv6"),
    field("tcp", Bool, Predicate("protocol = 6"), None, "is TCP"),
    field("udp", Bool, Predicate("protocol = 17"), None, "is UDP"),
    field("icmp", Bool, Predicate("protocol = 1"), None, "is ICMP"),
    field(
        "icmpv6",
        Bool,
        Predicate("protocol = 58"),
        None,
        "is ICMPv6",
    ),
    field(
        "dns",
        Bool,
        Predicate("'dns' = ANY(application_protocols)"),
        None,
        "carried DNS",
    ),
    field(
        "dhcp",
        Bool,
        Predicate("'dhcp' = ANY(application_protocols)"),
        None,
        "carried DHCP",
    ),
    field(
        "http",
        Bool,
        Predicate("'http' = ANY(application_protocols)"),
        None,
        "carried HTTP",
    ),
    field(
        "tls",
        Bool,
        Predicate("'tls' = ANY(application_protocols)"),
        None,
        "carried a TLS handshake",
    ),
    field(
        "alert",
        Bool,
        Predicate("alert_count > 0"),
        None,
        "cited by at least one alert",
    ),
    field(
        "alert.count",
        UInt { max: 16 },
        One("alert_count"),
        None,
        "alerts citing the flow (at most 16 are linked)",
    ),
    field(
        "alert.severity",
        Enum(SEVERITIES),
        One("max_alert_severity"),
        None,
        "most severe alert citing the flow: low, medium or high",
    ),
];

/// Fields available for `target`.
pub fn fields(target: Target) -> &'static [Field] {
    match target {
        Target::Packets => PACKET_FIELDS,
        Target::Flows => FLOW_FIELDS,
    }
}

/// Looks up a field by its (lowercase) name.
pub fn lookup(target: Target, name: &str) -> Option<&'static Field> {
    fields(target).iter().find(|f| f.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_names_are_unique_lowercase_and_documented() {
        let docs = include_str!("../../../docs/filter-language.md");
        for target in [Target::Packets, Target::Flows] {
            let all = fields(target);
            for (i, field) in all.iter().enumerate() {
                assert_eq!(field.name, field.name.to_ascii_lowercase());
                assert!(all.iter().skip(i + 1).all(|other| other.name != field.name));
                assert!(
                    docs.contains(&format!("| `{}` |", field.name)),
                    "{} is not documented",
                    field.name
                );
            }
        }
    }
}
