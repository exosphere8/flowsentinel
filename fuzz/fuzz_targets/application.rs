//! Wraps arbitrary bytes in a valid Ethernet/IPv4/TCP-or-UDP frame so the
//! application parsers (DNS, DHCP, HTTP, TLS) are reached on every run. The
//! first input byte picks the transport, the port, and whether the frame
//! is treated as cut short by a snapshot length.
#![no_main]

use libfuzzer_sys::fuzz_target;

const PORTS: [u16; 8] = [53, 5353, 5355, 67, 68, 80, 443, 9];

fn frame(tcp: bool, port: u16, payload: &[u8]) -> Vec<u8> {
    let transport_len = if tcp { 20 } else { 8 } + payload.len();
    let total = u16::try_from(20 + transport_len).unwrap_or(u16::MAX);
    let mut out = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00];
    out.extend([0x45, 0]);
    out.extend(total.to_be_bytes());
    out.extend([0, 1, 0x40, 0, 64, if tcp { 6 } else { 17 }, 0, 0]);
    out.extend([192, 0, 2, 10, 198, 51, 100, 20]);
    out.extend(40000u16.to_be_bytes());
    out.extend(port.to_be_bytes());
    if tcp {
        out.extend([0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0xFA, 0xF0, 0, 0, 0, 0]);
    } else {
        let len = u16::try_from(transport_len).unwrap_or(u16::MAX);
        out.extend(len.to_be_bytes());
        out.extend([0, 0]);
    }
    out.extend(payload);
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    let port = PORTS[usize::from(selector >> 2) % PORTS.len()];
    let tcp = selector & 1 == 0;
    let bytes = frame(tcp, port, payload);
    let wire = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    // Snapped: keep every header but only the first half of the payload, so
    // the application parsers see snapshot-cut data on every such run.
    let headers = 14 + 20 + if tcp { 20 } else { 8 };
    let captured = if selector & 2 == 0 {
        bytes.len()
    } else {
        headers + payload.len() / 2
    };
    let packet = decoder::decode_packet(
        decoder::LINKTYPE_ETHERNET,
        bytes.get(..captured).unwrap_or(&bytes),
        wire,
    );
    let _ = packet.info();
    for layer in &packet.layers {
        let _ = layer.describe();
    }
});
