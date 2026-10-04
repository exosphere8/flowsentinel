//! Limits for one live capture. Every capture stops at the first limit it
//! reaches; requests can lower the server's maximums but never raise them.

use std::time::Duration;

/// The limits of one capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveLimits {
    /// Packets written.
    pub max_packets: u64,
    /// Bytes of the capture file, headers included.
    pub max_bytes: u64,
    /// Time from the start of capture.
    pub max_duration: Duration,
    /// Bytes kept of each packet.
    pub snaplen: u32,
}

/// Smallest and largest snapshot lengths accepted.
pub const SNAPLEN_RANGE: std::ops::RangeInclusive<u32> = 64..=262_144;

impl LiveLimits {
    /// Defaults when a request names no limit: 60 seconds, 100,000 packets,
    /// 100 MiB and a 65,535-byte snapshot length, within `max`.
    pub fn defaults_within(max: &LiveLimits) -> Self {
        Self {
            max_packets: max.max_packets.min(100_000),
            max_bytes: max.max_bytes.min(100 * 1024 * 1024),
            max_duration: max.max_duration.min(Duration::from_secs(60)),
            snaplen: max.snaplen.min(65_535),
        }
    }
}

/// A requested limit outside what the server allows.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{field} must be between {min} and {max}")]
pub struct LimitError {
    pub field: &'static str,
    pub min: u64,
    pub max: u64,
}

fn within(
    field: &'static str,
    value: Option<u64>,
    min: u64,
    max: u64,
    default: u64,
) -> Result<u64, LimitError> {
    match value {
        None => Ok(default),
        Some(v) if (min..=max).contains(&v) => Ok(v),
        Some(_) => Err(LimitError { field, min, max }),
    }
}

/// Resolves requested limits against the server's maximums.
pub fn resolve(
    max: &LiveLimits,
    max_packets: Option<u64>,
    max_bytes: Option<u64>,
    max_seconds: Option<u64>,
    snaplen: Option<u32>,
) -> Result<LiveLimits, LimitError> {
    let defaults = LiveLimits::defaults_within(max);
    let snap_min = u64::from(*SNAPLEN_RANGE.start());
    Ok(LiveLimits {
        max_packets: within(
            "max_packets",
            max_packets,
            1,
            max.max_packets,
            defaults.max_packets,
        )?,
        // Room for the file header and at least one small packet.
        max_bytes: within(
            "max_bytes",
            max_bytes,
            1024,
            max.max_bytes,
            defaults.max_bytes,
        )?,
        max_duration: Duration::from_secs(within(
            "max_seconds",
            max_seconds,
            1,
            max.max_duration.as_secs(),
            defaults.max_duration.as_secs(),
        )?),
        snaplen: u32::try_from(within(
            "snaplen",
            snaplen.map(u64::from),
            snap_min,
            u64::from(max.snaplen),
            u64::from(defaults.snaplen),
        )?)
        .unwrap_or(defaults.snaplen),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: LiveLimits = LiveLimits {
        max_packets: 1_000_000,
        max_bytes: 512 * 1024 * 1024,
        max_duration: Duration::from_secs(3600),
        snaplen: 262_144,
    };

    #[test]
    fn defaults_apply_and_stay_within_the_maximums() {
        let limits = resolve(&MAX, None, None, None, None).unwrap();
        assert_eq!(limits.max_packets, 100_000);
        assert_eq!(limits.max_bytes, 100 * 1024 * 1024);
        assert_eq!(limits.max_duration, Duration::from_secs(60));
        assert_eq!(limits.snaplen, 65_535);
        let small = LiveLimits {
            max_packets: 10,
            max_bytes: 4096,
            max_duration: Duration::from_secs(5),
            snaplen: 128,
        };
        assert_eq!(resolve(&small, None, None, None, None).unwrap(), small);
    }

    #[test]
    fn requests_may_lower_but_not_raise_limits() {
        let limits = resolve(&MAX, Some(10), Some(2048), Some(5), Some(96)).unwrap();
        assert_eq!(
            (
                limits.max_packets,
                limits.max_bytes,
                limits.max_duration.as_secs(),
                limits.snaplen
            ),
            (10, 2048, 5, 96)
        );
        for (packets, bytes, seconds, snap, field) in [
            (Some(0), None, None, None, "max_packets"),
            (Some(1_000_001), None, None, None, "max_packets"),
            (None, Some(100), None, None, "max_bytes"),
            (None, None, Some(3601), None, "max_seconds"),
            (None, None, Some(0), None, "max_seconds"),
            (None, None, None, Some(63), "snaplen"),
            (None, None, None, Some(262_145), "snaplen"),
        ] {
            let err = resolve(&MAX, packets, bytes, seconds, snap).unwrap_err();
            assert_eq!(err.field, field);
        }
    }
}
