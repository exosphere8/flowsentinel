//! Property tests: the reader must never panic or loop on arbitrary input, and
//! must report exactly what a well-formed capture contains.

use std::io::Cursor;
use std::time::Duration;

use capture::{CaptureLimits, Clock, CompletionState, inspect_reader};
use proptest::prelude::*;

struct FrozenClock;

impl Clock for FrozenClock {
    fn elapsed(&self) -> Duration {
        Duration::ZERO
    }
}

fn limits() -> CaptureLimits {
    CaptureLimits::from_cli_units(1, 10_000, 60)
}

fn header(big: bool, nanos: bool, minor: u16, snap: u32) -> Vec<u8> {
    let magic: u32 = if nanos { 0xA1B2_3C4D } else { 0xA1B2_C3D4 };
    let u16b = |v: u16| {
        if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let u32b = |v: u32| {
        if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let mut out = u32b(magic).to_vec();
    out.extend(u16b(2));
    out.extend(u16b(minor));
    out.extend([0u8; 8]);
    out.extend(u32b(snap));
    out.extend(u32b(1));
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Completely arbitrary bytes.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let len = bytes.len() as u64;
        let _ = inspect_reader(Cursor::new(bytes), "fuzz.pcap".into(), len, &limits(), &FrozenClock);
    }

    /// A valid global header followed by arbitrary bytes exercises the record
    /// parser far more often than fully random input.
    #[test]
    fn arbitrary_records_never_panic(
        big in any::<bool>(),
        nanos in any::<bool>(),
        minor in 0u16..=4,
        body in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let mut bytes = header(big, nanos, minor, 65_535);
        bytes.extend(body);
        let len = bytes.len() as u64;
        if let Ok(report) = inspect_reader(Cursor::new(bytes), "fuzz.pcap".into(), len, &limits(), &FrozenClock) {
            // Every record consumes at least its 16-byte header.
            prop_assert!(report.summary.packets_processed <= len / 16);
        }
    }

    /// Well-formed captures round-trip exactly.
    #[test]
    fn well_formed_captures_round_trip(
        big in any::<bool>(),
        records in proptest::collection::vec((any::<u32>(), 0u32..1_000_000, 0usize..200, any::<u32>()), 0..40),
        max_packets in 1u64..60,
    ) {
        let u32b = |v: u32| if big { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut bytes = header(big, false, 4, 65_535);
        for (secs, micros, len, orig) in &records {
            bytes.extend(u32b(*secs));
            bytes.extend(u32b(*micros));
            bytes.extend(u32b(*len as u32));
            bytes.extend(u32b(*orig));
            bytes.extend(std::iter::repeat_n(0x5A, *len));
        }
        let limits = CaptureLimits { max_packets, ..limits() };
        let total = bytes.len() as u64;
        let report = inspect_reader(Cursor::new(bytes), "ok.pcap".into(), total, &limits, &FrozenClock).unwrap();

        let expected = records.len().min(max_packets as usize);
        prop_assert_eq!(report.packets.len(), expected);
        let state = if (records.len() as u64) > max_packets {
            CompletionState::PacketLimitReached
        } else {
            CompletionState::Complete
        };
        prop_assert_eq!(report.completion_state, state);
        for (packet, (secs, micros, len, orig)) in report.packets.iter().zip(&records) {
            let ts = packet.timestamp.expect("fractions are in range");
            prop_assert_eq!(ts.unix_seconds(), u64::from(*secs));
            prop_assert_eq!(ts.nanos(), micros * 1000);
            prop_assert_eq!(packet.captured_length as usize, *len);
            prop_assert_eq!(packet.original_length, *orig);
        }
    }
}
