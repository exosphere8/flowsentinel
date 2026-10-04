//! Compiles arbitrary text as a display filter for packets and for flows.
//! Error spans must be whole characters inside the input, and accepted
//! filters must reparse from their normalized form to the same SQL pieces,
//! unless normalizing (spaces, quotes) pushed it past the length limit.
#![no_main]

use filter_language::{FilterError, MAX_FILTER_BYTES, Target, compile};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for target in [Target::Packets, Target::Flows] {
        match compile(text, target) {
            Ok(filter) => match compile(&filter.normalized, target) {
                Ok(again) => assert!(again.pieces == filter.pieces),
                Err(FilterError::TooLong { .. }) => {
                    assert!(filter.normalized.len() > MAX_FILTER_BYTES);
                }
                Err(err) => panic!("normalized form rejected: {err}"),
            },
            Err(err) => {
                if let Some(span) = err.span() {
                    assert!(span.start <= span.end && text.get(span.start..span.end).is_some());
                }
            }
        }
    }
});
