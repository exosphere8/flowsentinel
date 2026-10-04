//! Names for well-known protocol numbers. Lookup only; nothing here affects
//! which protocols are decoded.

pub(crate) const ETHERTYPE_IPV4: u16 = 0x0800;
pub(crate) const ETHERTYPE_ARP: u16 = 0x0806;
pub(crate) const ETHERTYPE_IPV6: u16 = 0x86DD;
pub(crate) const ETHERTYPE_VLAN: u16 = 0x8100;
pub(crate) const ETHERTYPE_QINQ: u16 = 0x88A8;
pub(crate) const ETHERTYPE_QINQ_LEGACY: u16 = 0x9100;

pub(crate) const IP_PROTO_ICMP: u8 = 1;
pub(crate) const IP_PROTO_TCP: u8 = 6;
pub(crate) const IP_PROTO_UDP: u8 = 17;
pub(crate) const IP_PROTO_ICMPV6: u8 = 58;

/// Name of an EtherType value.
pub fn ethertype_name(ethertype: u16) -> Option<&'static str> {
    Some(match ethertype {
        ETHERTYPE_IPV4 => "IPv4",
        ETHERTYPE_ARP => "ARP",
        0x0842 => "Wake-on-LAN",
        0x8035 => "RARP",
        ETHERTYPE_VLAN => "802.1Q VLAN",
        ETHERTYPE_IPV6 => "IPv6",
        0x8808 => "Ethernet flow control",
        0x8847 => "MPLS unicast",
        0x8848 => "MPLS multicast",
        0x8863 => "PPPoE discovery",
        0x8864 => "PPPoE session",
        0x888E => "EAPOL",
        ETHERTYPE_QINQ => "802.1ad QinQ",
        0x88CC => "LLDP",
        0x88E5 => "MACsec",
        0x88F7 => "PTP",
        ETHERTYPE_QINQ_LEGACY => "QinQ (legacy)",
        _ => return None,
    })
}

/// Name of an IP protocol / IPv6 next-header value.
pub fn ip_protocol_name(protocol: u8) -> Option<&'static str> {
    Some(match protocol {
        0 => "IPv6 Hop-by-Hop",
        IP_PROTO_ICMP => "ICMP",
        2 => "IGMP",
        4 => "IPv4-in-IP",
        IP_PROTO_TCP => "TCP",
        IP_PROTO_UDP => "UDP",
        41 => "IPv6-in-IP",
        43 => "IPv6 Routing",
        44 => "IPv6 Fragment",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        IP_PROTO_ICMPV6 => "ICMPv6",
        59 => "IPv6 No Next Header",
        60 => "IPv6 Destination Options",
        89 => "OSPF",
        103 => "PIM",
        112 => "VRRP",
        132 => "SCTP",
        135 => "Mobility",
        _ => return None,
    })
}

pub(crate) fn arp_operation_name(operation: u16) -> Option<&'static str> {
    Some(match operation {
        1 => "request",
        2 => "reply",
        3 => "RARP request",
        4 => "RARP reply",
        _ => return None,
    })
}

pub(crate) fn icmp_type_name(icmp_type: u8) -> Option<&'static str> {
    Some(match icmp_type {
        0 => "echo reply",
        3 => "destination unreachable",
        4 => "source quench",
        5 => "redirect",
        8 => "echo request",
        9 => "router advertisement",
        10 => "router solicitation",
        11 => "time exceeded",
        12 => "parameter problem",
        13 => "timestamp request",
        14 => "timestamp reply",
        _ => return None,
    })
}

pub(crate) fn icmpv6_type_name(icmp_type: u8) -> Option<&'static str> {
    Some(match icmp_type {
        1 => "destination unreachable",
        2 => "packet too big",
        3 => "time exceeded",
        4 => "parameter problem",
        128 => "echo request",
        129 => "echo reply",
        130 => "multicast listener query",
        131 => "multicast listener report",
        132 => "multicast listener done",
        133 => "router solicitation",
        134 => "router advertisement",
        135 => "neighbor solicitation",
        136 => "neighbor advertisement",
        137 => "redirect",
        143 => "multicast listener report v2",
        _ => return None,
    })
}
