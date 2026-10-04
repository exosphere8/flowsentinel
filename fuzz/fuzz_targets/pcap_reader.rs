//! Reads arbitrary bytes as a PCAP file and decodes every record.
#![no_main]

use std::io::Cursor;
use std::time::Duration;

use capture::{
    CaptureLimits, Clock, PacketRecordMetadata, PacketSink, PcapGlobalHeader,
    inspect_reader_with_sink,
};
use libfuzzer_sys::fuzz_target;

struct Frozen;

impl Clock for Frozen {
    fn elapsed(&self) -> Duration {
        Duration::ZERO
    }
}

#[derive(Default)]
struct Decode {
    link_type: u16,
}

impl PacketSink for Decode {
    fn start(&mut self, header: &PcapGlobalHeader) {
        self.link_type = header.link_type.0;
    }

    fn packet(&mut self, record: &PacketRecordMetadata, data: &[u8]) {
        let _ = decoder::decode_packet(self.link_type, data, record.original_length);
    }
}

fuzz_target!(|data: &[u8]| {
    let limits = CaptureLimits::from_cli_units(1, 10_000, 60);
    let mut sink = Decode::default();
    let _ = inspect_reader_with_sink(
        Cursor::new(data),
        "fuzz.pcap".to_owned(),
        data.len() as u64,
        &limits,
        &Frozen,
        Some(&mut sink),
    );
});
