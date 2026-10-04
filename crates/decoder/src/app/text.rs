//! Bounded, display-safe text extraction from untrusted bytes.

/// Copies at most `max_chars` bytes of printable ASCII from `bytes`,
/// replacing every other byte with `?`. Returns the text and whether it was
/// shortened.
pub(crate) fn printable(bytes: &[u8], max_chars: usize) -> (String, bool) {
    let shown = bytes.get(..max_chars).unwrap_or(bytes);
    let text = shown
        .iter()
        .map(|&b| {
            if (0x20..0x7F).contains(&b) {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect();
    (text, shown.len() < bytes.len())
}

/// Whether `bytes` is a plausible hostname: 1-253 bytes of letters, digits,
/// `-`, `_` and `.`, not starting with a dot.
pub(crate) fn is_hostname(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= 253
        && bytes.first() != Some(&b'.')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Lowercased hostname if `bytes` is one.
pub(crate) fn hostname(bytes: &[u8]) -> Option<String> {
    is_hostname(bytes).then(|| String::from_utf8_lossy(bytes).to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_replaces_and_bounds() {
        assert_eq!(printable(b"ab\x00c\xff", 10), ("ab?c?".to_owned(), false));
        assert_eq!(printable(b"abcdef", 3), ("abc".to_owned(), true));
        assert_eq!(printable(b"\x1b[31m", 10).0, "?[31m");
    }

    #[test]
    fn hostnames_are_validated() {
        assert_eq!(
            hostname(b"WWW.Example.COM").as_deref(),
            Some("www.example.com")
        );
        assert!(hostname(b"a b").is_none());
        assert!(hostname(b"").is_none());
        assert!(hostname(b".example").is_none());
        assert!(hostname(&[b'a'; 254]).is_none());
        assert!(hostname(b"host\x00name").is_none());
    }
}
