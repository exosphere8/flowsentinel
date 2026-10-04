//! Resource limits for one inspection, and the clock used to enforce the
//! time limit.

use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use serde::Serialize;

const MIB: u64 = 1024 * 1024;

/// Upper bounds applied to a single capture inspection.
///
/// Reaching `max_packets` or `max_duration` is not an error: the inspection
/// stops early and reports a partial [`CompletionState`](crate::CompletionState).
/// Exceeding `max_file_size_bytes` rejects the file before parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureLimits {
    pub max_file_size_bytes: u64,
    pub max_packets: u64,
    pub max_duration: Duration,
}

impl CaptureLimits {
    /// Default `--max-file-size-mb`.
    pub const DEFAULT_MAX_FILE_SIZE_MB: u64 = 512;
    /// Allowed `--max-file-size-mb` range.
    pub const MAX_FILE_SIZE_MB_RANGE: RangeInclusive<u64> = 1..=65_536;
    /// Default `--max-packets`.
    pub const DEFAULT_MAX_PACKETS: u64 = 100_000;
    /// Allowed `--max-packets` range. Each retained record is 40 bytes, so the
    /// upper bound keeps the packet table at or below about 40 MB.
    pub const MAX_PACKETS_RANGE: RangeInclusive<u64> = 1..=1_000_000;
    /// Default `--max-duration-seconds`.
    pub const DEFAULT_MAX_DURATION_SECONDS: u64 = 60;
    /// Allowed `--max-duration-seconds` range.
    pub const MAX_DURATION_SECONDS_RANGE: RangeInclusive<u64> = 1..=3_600;

    /// Returns these limits with each value clamped into its documented
    /// range, so library callers cannot disable a bound by accident. The
    /// inspection functions apply this themselves.
    pub fn clamped(&self) -> Self {
        let mib_range = &Self::MAX_FILE_SIZE_MB_RANGE;
        let secs_range = &Self::MAX_DURATION_SECONDS_RANGE;
        Self {
            max_file_size_bytes: self.max_file_size_bytes.clamp(
                mib_range.start().saturating_mul(MIB),
                mib_range.end().saturating_mul(MIB),
            ),
            max_packets: self.max_packets.clamp(
                *Self::MAX_PACKETS_RANGE.start(),
                *Self::MAX_PACKETS_RANGE.end(),
            ),
            max_duration: self.max_duration.clamp(
                Duration::from_secs(*secs_range.start()),
                Duration::from_secs(*secs_range.end()),
            ),
        }
    }

    /// Builds limits from the units used on the command line.
    pub fn from_cli_units(
        max_file_size_mb: u64,
        max_packets: u64,
        max_duration_seconds: u64,
    ) -> Self {
        Self {
            max_file_size_bytes: max_file_size_mb.saturating_mul(MIB),
            max_packets,
            max_duration: Duration::from_secs(max_duration_seconds),
        }
    }
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self::from_cli_units(
            Self::DEFAULT_MAX_FILE_SIZE_MB,
            Self::DEFAULT_MAX_PACKETS,
            Self::DEFAULT_MAX_DURATION_SECONDS,
        )
    }
}

/// The limits as reported in output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AppliedLimits {
    pub max_file_size_bytes: u64,
    pub max_packets: u64,
    pub max_duration_seconds: u64,
}

impl From<&CaptureLimits> for AppliedLimits {
    fn from(limits: &CaptureLimits) -> Self {
        Self {
            max_file_size_bytes: limits.max_file_size_bytes,
            max_packets: limits.max_packets,
            max_duration_seconds: limits.max_duration.as_secs(),
        }
    }
}

/// Source of elapsed time for the duration limit. Injectable so tests can
/// exercise the time limit deterministically.
pub trait Clock {
    /// Time elapsed since the inspection started.
    fn elapsed(&self) -> Duration;
}

/// Wall-clock implementation backed by a monotonic [`Instant`].
#[derive(Debug, Clone, Copy)]
pub struct MonotonicClock {
    start: Instant,
}

impl MonotonicClock {
    /// Starts measuring from now.
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Clock for MonotonicClock {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented_values() {
        let limits = CaptureLimits::default();
        assert_eq!(limits.max_file_size_bytes, 512 * MIB);
        assert_eq!(limits.max_packets, 100_000);
        assert_eq!(limits.max_duration, Duration::from_secs(60));
    }

    #[test]
    fn megabytes_convert_without_overflow() {
        assert_eq!(
            CaptureLimits::from_cli_units(1, 1, 1).max_file_size_bytes,
            MIB
        );
        assert_eq!(
            CaptureLimits::from_cli_units(u64::MAX, 1, 1).max_file_size_bytes,
            u64::MAX
        );
    }

    #[test]
    fn clamping_enforces_documented_ranges() {
        let wild = CaptureLimits {
            max_file_size_bytes: u64::MAX,
            max_packets: u64::MAX,
            max_duration: Duration::from_secs(u64::MAX),
        }
        .clamped();
        assert_eq!(wild.max_file_size_bytes, 65_536 * MIB);
        assert_eq!(wild.max_packets, 1_000_000);
        assert_eq!(wild.max_duration, Duration::from_secs(3_600));

        let zero = CaptureLimits {
            max_file_size_bytes: 0,
            max_packets: 0,
            max_duration: Duration::ZERO,
        }
        .clamped();
        assert_eq!(zero.max_file_size_bytes, MIB);
        assert_eq!(zero.max_packets, 1);
        assert_eq!(zero.max_duration, Duration::from_secs(1));

        assert_eq!(CaptureLimits::default().clamped(), CaptureLimits::default());
    }

    #[test]
    fn monotonic_clock_advances() {
        let clock = MonotonicClock::start();
        let first = clock.elapsed();
        assert!(clock.elapsed() >= first);
    }
}
