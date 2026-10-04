//! Capture filter (BPF) validation.
//!
//! Filter text is checked here first (length and characters); libpcap then
//! compiles it, without opening an interface, before any capture starts. A
//! filter only selects which packets are kept; it cannot change anything on
//! the network.

/// Longest filter accepted, in bytes.
pub const MAX_FILTER_BYTES: usize = 1024;

/// Why filter text was refused before compiling.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterTextError {
    #[error("the capture filter is longer than {MAX_FILTER_BYTES} bytes")]
    TooLong,
    #[error("the capture filter may contain only printable ASCII characters")]
    InvalidCharacter,
}

/// Checks filter text: at most 1 KiB of printable ASCII and spaces. An empty
/// filter keeps every packet.
pub fn check_text(filter: &str) -> Result<(), FilterTextError> {
    if filter.len() > MAX_FILTER_BYTES {
        return Err(FilterTextError::TooLong);
    }
    if !filter.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) {
        return Err(FilterTextError::InvalidCharacter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_text_is_bounded_and_printable() {
        assert!(check_text("").is_ok());
        assert!(check_text("tcp port 443 and not host 192.0.2.1").is_ok());
        assert!(check_text("ether[0] & 1 != 0").is_ok());
        assert_eq!(check_text(&"a".repeat(1025)), Err(FilterTextError::TooLong));
        for bad in ["tcp\nport 80", "port 80\0", "tcp\tport 80", "hôte 1"] {
            assert_eq!(
                check_text(bad),
                Err(FilterTextError::InvalidCharacter),
                "{bad:?}"
            );
        }
    }
}
