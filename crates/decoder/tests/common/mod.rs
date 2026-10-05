//! Byte-level builders for synthetic test packets. Addresses are from
//! documentation ranges (RFC 5737, RFC 3849) and locally administered MACs.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![allow(dead_code)]

pub const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
pub const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
pub const IP4_A: [u8; 4] = [192, 0, 2, 10];
pub const IP4_B: [u8; 4] = [198, 51, 100, 20];
pub const IP6_A: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a,
];
pub const IP6_B: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14,
];
pub const MARKER: &[u8] = b"FLOWSENTINEL-SYNTHETIC-PAYLOAD-MARKER";

pub fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = MAC_B.to_vec();
    out.extend(MAC_A);
    out.extend(ethertype.to_be_bytes());
    out.extend(payload);
    out
}

pub fn vlan_ethernet(tags: &[(u16, u16)], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = MAC_B.to_vec();
    out.extend(MAC_A);
    for (tpid, tci) in tags {
        out.extend(tpid.to_be_bytes());
        out.extend(tci.to_be_bytes());
    }
    out.extend(ethertype.to_be_bytes());
    out.extend(payload);
    out
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub struct Ipv4 {
    pub protocol: u8,
    pub ttl: u8,
    pub flags_fragment: u16,
    pub options: Vec<u8>,
    pub total_length: Option<u16>,
    pub version_ihl: Option<u8>,
    pub break_checksum: bool,
}

impl Default for Ipv4 {
    fn default() -> Self {
        Self {
            protocol: 17,
            ttl: 64,
            flags_fragment: 0x4000,
            options: Vec::new(),
            total_length: None,
            version_ihl: None,
            break_checksum: false,
        }
    }
}

pub fn ipv4(opts: &Ipv4, payload: &[u8]) -> Vec<u8> {
    let header_len = 20 + opts.options.len();
    let total = opts
        .total_length
        .unwrap_or((header_len + payload.len()) as u16);
    let version_ihl = opts.version_ihl.unwrap_or(0x40 | (header_len / 4) as u8);
    let mut header = vec![version_ihl, 0];
    header.extend(total.to_be_bytes());
    header.extend(0x1234u16.to_be_bytes());
    header.extend(opts.flags_fragment.to_be_bytes());
    header.extend([opts.ttl, opts.protocol, 0, 0]);
    header.extend(IP4_A);
    header.extend(IP4_B);
    header.extend(&opts.options);
    let mut sum = checksum(&header);
    if opts.break_checksum {
        sum ^= 0x00FF;
    }
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    header.extend(payload);
    header
}

pub fn ipv6(next_header: u8, payload: &[u8]) -> Vec<u8> {
    ipv6_with_length(next_header, payload.len() as u16, payload)
}

pub fn ipv6_with_length(next_header: u8, payload_length: u16, payload: &[u8]) -> Vec<u8> {
    // Version 6, traffic class 0x2e, flow label 0x12345.
    let word0: u32 = (6 << 28) | (0x2E << 20) | 0x12345;
    let mut out = word0.to_be_bytes().to_vec();
    out.extend(payload_length.to_be_bytes());
    out.extend([next_header, 64]);
    out.extend(IP6_A);
    out.extend(IP6_B);
    out.extend(payload);
    out
}

/// Generic IPv6 extension header (Hop-by-Hop, Routing, Destination Options).
pub fn ext_header(next_header: u8, units: u8) -> Vec<u8> {
    let mut out = vec![next_header, units];
    out.resize((usize::from(units) + 1) * 8, 0);
    out
}

pub fn fragment_header(next_header: u8, offset_bytes: u16, more: bool, id: u32) -> Vec<u8> {
    let mut out = vec![next_header, 0];
    out.extend(((offset_bytes / 8) << 3 | u16::from(more)).to_be_bytes());
    out.extend(id.to_be_bytes());
    out
}

pub fn tcp(sport: u16, dport: u16, flags: u16, options: &[u8], payload: &[u8]) -> Vec<u8> {
    let header_len = 20 + options.len();
    let mut out = sport.to_be_bytes().to_vec();
    out.extend(dport.to_be_bytes());
    out.extend(1000u32.to_be_bytes());
    out.extend(2000u32.to_be_bytes());
    out.push(((header_len / 4) as u8) << 4 | ((flags >> 8) as u8 & 0x01));
    out.push(flags as u8);
    out.extend(64240u16.to_be_bytes());
    out.extend([0, 0, 0, 0]);
    out.extend(options);
    out.extend(payload);
    out
}

pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    udp_with_length(sport, dport, (8 + payload.len()) as u16, payload)
}

pub fn udp_with_length(sport: u16, dport: u16, length: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = sport.to_be_bytes().to_vec();
    out.extend(dport.to_be_bytes());
    out.extend(length.to_be_bytes());
    out.extend([0, 0]);
    out.extend(payload);
    out
}

pub fn icmp_echo(icmp_type: u8, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![icmp_type, 0, 0, 0];
    out.extend(id.to_be_bytes());
    out.extend(seq.to_be_bytes());
    out.extend(payload);
    out
}

pub fn arp(operation: u16, sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut out = vec![0, 1, 0x08, 0x00, 6, 4];
    out.extend(operation.to_be_bytes());
    out.extend(MAC_A);
    out.extend(sender_ip);
    out.extend(if operation == 1 { [0; 6] } else { MAC_B });
    out.extend(target_ip);
    out
}
