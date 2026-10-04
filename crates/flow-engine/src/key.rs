//! Canonical bidirectional flow keys.

use std::fmt;
use std::net::IpAddr;

use serde::Serialize;

/// One side of a flow: an IP address and a transport port (0 for protocols
/// without ports).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(ip) => write!(f, "{ip}:{}", self.port),
            IpAddr::V6(ip) => write!(f, "[{ip}]:{}", self.port),
        }
    }
}

/// Identifies a conversation regardless of packet direction: the protocol
/// number plus both endpoints in a fixed (sorted) order. The sort order is
/// only for matching; which side started the flow is tracked separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct FlowKey {
    /// IP protocol number (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6, ...).
    pub protocol: u8,
    pub lower: Endpoint,
    pub upper: Endpoint,
}

impl FlowKey {
    /// Builds the canonical key for a packet from `source` to `destination`.
    /// Packets in either direction of the same conversation get equal keys.
    pub fn new(protocol: u8, source: Endpoint, destination: Endpoint) -> Self {
        let (lower, upper) = if source <= destination {
            (source, destination)
        } else {
            (destination, source)
        };
        Self {
            protocol,
            lower,
            upper,
        }
    }

    /// 4 or 6.
    pub fn ip_version(&self) -> u8 {
        if self.lower.ip.is_ipv4() { 4 } else { 6 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(ip: &str, port: u16) -> Endpoint {
        Endpoint {
            ip: ip.parse().unwrap(),
            port,
        }
    }

    #[test]
    fn both_directions_share_a_key() {
        let a = ep("192.0.2.10", 40000);
        let b = ep("198.51.100.20", 443);
        assert_eq!(FlowKey::new(6, a, b), FlowKey::new(6, b, a));
        assert_ne!(FlowKey::new(6, a, b), FlowKey::new(17, a, b));
        assert_eq!(FlowKey::new(6, a, b).ip_version(), 4);
    }

    #[test]
    fn ports_and_addresses_both_matter() {
        let a = ep("192.0.2.10", 40000);
        assert_ne!(
            FlowKey::new(6, a, ep("198.51.100.20", 443)),
            FlowKey::new(6, a, ep("198.51.100.20", 444))
        );
        let v6 = FlowKey::new(17, ep("2001:db8::1", 53), ep("2001:db8::2", 5353));
        assert_eq!(v6.ip_version(), 6);
    }

    #[test]
    fn endpoints_display_with_brackets_for_ipv6() {
        assert_eq!(ep("192.0.2.1", 80).to_string(), "192.0.2.1:80");
        assert_eq!(ep("2001:db8::1", 443).to_string(), "[2001:db8::1]:443");
    }
}
