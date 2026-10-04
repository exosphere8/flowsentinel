//! DHCPv4 message metadata (RFC 2131, RFC 2132).
//!
//! Recognition requires the BOOTP fixed fields, a valid `op`, a hardware
//! address length of at most 16 and the DHCP magic cookie. Only five options
//! are extracted (message type, requested address, server identifier, lease
//! time, host name); other options are listed by code only and their bytes
//! are never exposed.

use std::net::Ipv4Addr;

use serde::Serialize;

use super::{Issue, Issues, text};
use crate::bytes::{array, slice, u8_at, u16_at, u32_at};
use crate::model::MacAddr;

const FIXED_LEN: usize = 236;
const MAGIC_COOKIE: u32 = 0x6382_5363;
/// Options walked per message.
pub const MAX_OPTIONS: usize = 64;
/// Longest host name shown.
pub const MAX_HOSTNAME_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DhcpMessage {
    /// `request` (BOOTREQUEST) or `reply` (BOOTREPLY).
    pub op: &'static str,
    pub message_type: Option<u8>,
    pub message_type_name: Option<&'static str>,
    pub transaction_id: u32,
    pub hardware_type: u8,
    pub hardware_address_length: u8,
    pub broadcast: bool,
    pub client_ip: Ipv4Addr,
    pub your_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub relay_ip: Ipv4Addr,
    /// Client hardware address, for Ethernet (type 1, length 6) only.
    pub client_mac: Option<MacAddr>,
    pub requested_ip: Option<Ipv4Addr>,
    pub server_identifier: Option<Ipv4Addr>,
    pub lease_time_seconds: Option<u32>,
    /// Option 12, printable ASCII only, at most 64 characters.
    pub hostname: Option<String>,
    /// Codes of every option present, in order (bytes are not exposed).
    pub option_codes: Vec<u8>,
}

pub(crate) fn parse(payload: &[u8]) -> Option<(DhcpMessage, Issues)> {
    let op = match u8_at(payload, 0)? {
        1 => "request",
        2 => "reply",
        _ => return None,
    };
    let (hardware_type, hlen) = (u8_at(payload, 1)?, u8_at(payload, 2)?);
    if hlen > 16 || u32_at(payload, FIXED_LEN)? != MAGIC_COOKIE {
        return None;
    }
    let ip = |offset| array::<4>(payload, offset).map(Ipv4Addr::from);
    let mut dhcp = DhcpMessage {
        op,
        message_type: None,
        message_type_name: None,
        transaction_id: u32_at(payload, 4)?,
        hardware_type,
        hardware_address_length: hlen,
        broadcast: u16_at(payload, 10)? & 0x8000 != 0,
        client_ip: ip(12)?,
        your_ip: ip(16)?,
        server_ip: ip(20)?,
        relay_ip: ip(24)?,
        client_mac: (hardware_type == 1 && hlen == 6)
            .then(|| array::<6>(payload, 28).map(MacAddr))
            .flatten(),
        requested_ip: None,
        server_identifier: None,
        lease_time_seconds: None,
        hostname: None,
        option_codes: Vec::new(),
    };

    let mut issues = Issues::default();
    let mut pos = FIXED_LEN + 4;
    // Options may legally end without an END option at the packet end.
    while let Some(code) = u8_at(payload, pos) {
        match code {
            0 => {
                pos += 1;
                continue;
            }
            255 => break,
            _ => {}
        }
        if dhcp.option_codes.len() == MAX_OPTIONS {
            issues.push(Issue::limit("more DHCP options than are examined"));
            break;
        }
        let Some(value) =
            u8_at(payload, pos + 1).and_then(|len| slice(payload, pos + 2, usize::from(len)))
        else {
            issues.push(Issue::ran_out("DHCP option extends past the captured data"));
            break;
        };
        dhcp.option_codes.push(code);
        match (code, value.len()) {
            (53, 1) => {
                dhcp.message_type = u8_at(value, 0);
                dhcp.message_type_name = dhcp.message_type.and_then(message_type_name);
            }
            (50, 4) => dhcp.requested_ip = array::<4>(value, 0).map(Ipv4Addr::from),
            (54, 4) => dhcp.server_identifier = array::<4>(value, 0).map(Ipv4Addr::from),
            (51, 4) => dhcp.lease_time_seconds = u32_at(value, 0),
            (12, 1..) => {
                let (hostname, shortened) = text::printable(value, MAX_HOSTNAME_CHARS);
                if shortened {
                    issues.push(Issue::limit("DHCP host name longer than the display limit"));
                }
                dhcp.hostname = Some(hostname);
            }
            (53 | 50 | 54 | 51 | 12, _) => {
                issues.push(Issue::malformed("DHCP option has an invalid length"));
            }
            _ => {}
        }
        pos += 2 + value.len();
    }
    Some((dhcp, issues))
}

fn message_type_name(message_type: u8) -> Option<&'static str> {
    Some(match message_type {
        1 => "DHCPDISCOVER",
        2 => "DHCPOFFER",
        3 => "DHCPREQUEST",
        4 => "DHCPDECLINE",
        5 => "DHCPACK",
        6 => "DHCPNAK",
        7 => "DHCPRELEASE",
        8 => "DHCPINFORM",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DecodeWarningCode;

    fn message(options: &[u8]) -> Vec<u8> {
        let mut out = vec![1, 1, 6, 0];
        out.extend(0x1234_5678u32.to_be_bytes());
        out.extend([0, 0, 0x80, 0]);
        out.extend([0u8; 16]); // ciaddr, yiaddr, siaddr, giaddr
        out.extend([2, 0, 0, 0, 0, 1]);
        out.extend([0u8; 10 + 64 + 128]);
        out.extend(MAGIC_COOKIE.to_be_bytes());
        out.extend(options);
        out
    }

    #[test]
    fn extracts_known_options_only() {
        let opts = [
            53, 1, 3, 50, 4, 192, 0, 2, 10, 54, 4, 192, 0, 2, 1, 12, 4, b'l', b'a', b'b', 0x07, 61,
            3, 0xDE, 0xAD, 0x01, 0, 0, 255,
        ];
        let (dhcp, issues) = parse(&message(&opts)).unwrap();
        assert!(issues.is_empty());
        assert_eq!(dhcp.op, "request");
        assert_eq!(dhcp.message_type_name, Some("DHCPREQUEST"));
        assert_eq!(dhcp.transaction_id, 0x1234_5678);
        assert!(dhcp.broadcast);
        assert_eq!(
            dhcp.client_mac.map(|m| m.to_string()).as_deref(),
            Some("02:00:00:00:00:01")
        );
        assert_eq!(dhcp.requested_ip, Some(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(dhcp.server_identifier, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(dhcp.hostname.as_deref(), Some("lab?"));
        assert_eq!(dhcp.option_codes, [53, 50, 54, 12, 61]);
        let json = serde_json::to_string(&dhcp).unwrap();
        assert!(
            !json.contains("222") && !json.contains("dead"),
            "client-id bytes are not exposed"
        );
    }

    #[test]
    fn requires_magic_cookie_and_valid_op() {
        let mut bad_cookie = message(&[255]);
        bad_cookie[236] = 0;
        assert!(parse(&bad_cookie).is_none());
        let mut bad_op = message(&[255]);
        bad_op[0] = 3;
        assert!(parse(&bad_op).is_none());
        assert!(parse(&message(&[255])[..200]).is_none());
    }

    #[test]
    fn option_problems_are_reported() {
        let (_, issues) = parse(&message(&[53, 2, 1, 1, 255])).unwrap();
        assert_eq!(issues[0].code, DecodeWarningCode::MalformedApplicationData);
        let (_, issues) = parse(&message(&[12, 40, b'a'])).unwrap();
        assert_eq!(issues[0].code, DecodeWarningCode::IncompleteApplicationData);
        let mut many = Vec::new();
        for _ in 0..(MAX_OPTIONS + 5) {
            many.extend([200, 0]);
        }
        let (dhcp, issues) = parse(&message(&many)).unwrap();
        assert_eq!(dhcp.option_codes.len(), MAX_OPTIONS);
        assert_eq!(issues[0].code, DecodeWarningCode::ApplicationLimitReached);
    }

    #[test]
    fn long_hostnames_are_bounded() {
        let mut opts = vec![12, 200];
        opts.extend([b'h'; 200]);
        let (dhcp, _) = parse(&message(&opts)).unwrap();
        assert_eq!(dhcp.hostname.map(|h| h.len()), Some(MAX_HOSTNAME_CHARS));
    }
}
