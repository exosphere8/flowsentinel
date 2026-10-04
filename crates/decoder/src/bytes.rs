//! Bounds-checked big-endian field access.
//!
//! Every read returns `None` instead of panicking when it would go past the
//! end of the slice. Protocol parsers turn `None` into a `truncated_header`
//! warning.

/// Copies `N` bytes starting at `offset`.
pub(crate) fn array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    data.get(offset..end)?.try_into().ok()
}

pub(crate) fn u8_at(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

pub(crate) fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    array(data, offset).map(u16::from_be_bytes)
}

pub(crate) fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    array(data, offset).map(u32::from_be_bytes)
}

/// The sub-slice `offset..offset + len`, if fully present.
pub(crate) fn slice(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    let end = offset.checked_add(len)?;
    data.get(offset..end)
}

/// Everything from `offset` on; empty if `offset` is past the end.
pub(crate) fn rest(data: &[u8], offset: usize) -> &[u8] {
    data.get(offset..).unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounds_checked() {
        let data = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(u8_at(&data, 3), Some(0x78));
        assert_eq!(u8_at(&data, 4), None);
        assert_eq!(u16_at(&data, 2), Some(0x5678));
        assert_eq!(u16_at(&data, 3), None);
        assert_eq!(u32_at(&data, 0), Some(0x1234_5678));
        assert_eq!(u32_at(&data, 1), None);
        assert_eq!(u32_at(&data, usize::MAX), None);
        assert_eq!(slice(&data, 1, 2), Some(&data[1..3]));
        assert_eq!(slice(&data, 3, 2), None);
        assert_eq!(slice(&data, usize::MAX, 2), None);
        assert_eq!(rest(&data, 2), &data[2..]);
        assert!(rest(&data, 9).is_empty());
    }
}
