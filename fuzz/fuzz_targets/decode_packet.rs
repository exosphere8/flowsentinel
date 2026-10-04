//! Decodes arbitrary bytes as one packet. The first input byte picks the
//! link type (Ethernet or not) and whether the frame counts as snapped, so
//! every decoder path is reachable.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, frame)) = data.split_first() else {
        return;
    };
    let link_type = if selector & 1 == 0 {
        decoder::LINKTYPE_ETHERNET
    } else {
        u16::from(selector)
    };
    let captured = u32::try_from(frame.len()).unwrap_or(u32::MAX);
    let wire_length = if selector & 2 == 0 { captured } else { captured.saturating_add(1) };
    let packet = decoder::decode_packet(link_type, frame, wire_length);
    // Exercise the formatting paths too.
    let _ = packet.info();
    let _ = packet.endpoints();
    for layer in &packet.layers {
        let _ = layer.describe();
    }
});
