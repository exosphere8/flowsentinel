//! Record timestamps and RFC 3339 formatting without a date-time dependency.

use std::fmt;

use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::header::TimestampResolution;

const SECONDS_PER_DAY: u64 = 86_400;

/// A validated record timestamp: whole seconds since the Unix epoch plus a
/// fraction, kept at the file's resolution.
///
/// Serializes as `{"unix_seconds": u64, "nanos": u32, "rfc3339": string}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    seconds: u64,
    nanos: u32,
    resolution: TimestampResolution,
}

impl Timestamp {
    /// Builds a timestamp from the raw record fields. Returns `None` if the
    /// fraction is not below one second at the given resolution.
    pub fn from_record(
        seconds: u32,
        fraction: u32,
        resolution: TimestampResolution,
    ) -> Option<Self> {
        if fraction >= resolution.units_per_second() {
            return None;
        }
        let nanos = match resolution {
            // fraction < 1_000_000, so the product stays below 1_000_000_000.
            TimestampResolution::Microsecond => fraction.checked_mul(1_000)?,
            TimestampResolution::Nanosecond => fraction,
        };
        Some(Self {
            seconds: u64::from(seconds),
            nanos,
            resolution,
        })
    }

    /// Whole seconds since 1970-01-01T00:00:00Z.
    pub fn unix_seconds(&self) -> u64 {
        self.seconds
    }

    /// Nanoseconds within the second (always below 1,000,000,000).
    pub fn nanos(&self) -> u32 {
        self.nanos
    }

    /// Resolution recorded in the file.
    pub fn resolution(&self) -> TimestampResolution {
        self.resolution
    }

    /// Nanoseconds since the Unix epoch.
    pub fn as_unix_nanos(&self) -> u128 {
        u128::from(self.seconds) * 1_000_000_000 + u128::from(self.nanos)
    }

    /// RFC 3339 UTC string with 6 or 9 fractional digits, matching the file's
    /// resolution, for example `2026-01-01T00:00:00.250000Z`.
    pub fn to_rfc3339(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (year, month, day) = civil_from_days(self.seconds / SECONDS_PER_DAY);
        let secs_of_day = self.seconds % SECONDS_PER_DAY;
        let (hour, minute, second) = (secs_of_day / 3600, secs_of_day / 60 % 60, secs_of_day % 60);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}."
        )?;
        match self.resolution {
            TimestampResolution::Microsecond => write!(f, "{:06}Z", self.nanos / 1_000),
            TimestampResolution::Nanosecond => write!(f, "{:09}Z", self.nanos),
        }
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Timestamp", 3)?;
        state.serialize_field("unix_seconds", &self.seconds)?;
        state.serialize_field("nanos", &self.nanos)?;
        state.serialize_field("rfc3339", &self.to_rfc3339())?;
        state.end()
    }
}

/// Converts days since 1970-01-01 to a proleptic Gregorian (year, month, day).
///
/// Howard Hinnant's `civil_from_days` algorithm, restricted to non-negative
/// day counts. PCAP seconds are 32-bit, so `days` is at most about 49,710 and
/// no intermediate value can overflow.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use TimestampResolution::{Microsecond, Nanosecond};

    fn rfc(seconds: u32, fraction: u32, resolution: TimestampResolution) -> String {
        Timestamp::from_record(seconds, fraction, resolution)
            .unwrap()
            .to_rfc3339()
    }

    #[test]
    fn formats_known_instants() {
        assert_eq!(rfc(0, 0, Microsecond), "1970-01-01T00:00:00.000000Z");
        assert_eq!(
            rfc(1_767_225_600, 250_000, Microsecond),
            "2026-01-01T00:00:00.250000Z"
        );
        assert_eq!(
            rfc(1_767_225_600, 1, Nanosecond),
            "2026-01-01T00:00:00.000000001Z"
        );
        // Leap day.
        assert_eq!(
            rfc(951_782_400, 0, Microsecond),
            "2000-02-29T00:00:00.000000Z"
        );
        assert_eq!(
            rfc(951_868_799, 999_999, Microsecond),
            "2000-02-29T23:59:59.999999Z"
        );
        // Largest representable PCAP second.
        assert_eq!(
            rfc(u32::MAX, 999_999_999, Nanosecond),
            "2106-02-07T06:28:15.999999999Z"
        );
    }

    #[test]
    fn rejects_out_of_range_fractions() {
        assert!(Timestamp::from_record(0, 1_000_000, Microsecond).is_none());
        assert!(Timestamp::from_record(0, 999_999, Microsecond).is_some());
        assert!(Timestamp::from_record(0, 1_000_000_000, Nanosecond).is_none());
        assert!(Timestamp::from_record(0, 999_999_999, Nanosecond).is_some());
    }

    #[test]
    fn microseconds_are_stored_as_nanoseconds() {
        let ts = Timestamp::from_record(10, 5, Microsecond).unwrap();
        assert_eq!(ts.nanos(), 5_000);
        assert_eq!(ts.as_unix_nanos(), 10_000_005_000);
    }

    #[test]
    fn ordering_follows_time() {
        let a = Timestamp::from_record(10, 999_999, Microsecond).unwrap();
        let b = Timestamp::from_record(11, 0, Microsecond).unwrap();
        assert!(a < b);
    }

    #[test]
    fn serializes_three_fields() {
        let ts = Timestamp::from_record(1_767_225_600, 0, Microsecond).unwrap();
        assert_eq!(
            serde_json::to_string(&ts).unwrap(),
            r#"{"unix_seconds":1767225600,"nanos":0,"rfc3339":"2026-01-01T00:00:00.000000Z"}"#
        );
    }

    /// Cross-checks the calendar math against a naive day-by-day walk.
    #[test]
    fn civil_from_days_matches_naive_walk() {
        let (mut y, mut m, mut d) = (1970u64, 1u64, 1u64);
        for days in 0..60_000u64 {
            assert_eq!(civil_from_days(days), (y, m, d), "day {days}");
            let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
            let month_len = match m {
                2 if leap => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            d += 1;
            if d > month_len {
                d = 1;
                m += 1;
                if m > 12 {
                    m = 1;
                    y += 1;
                }
            }
        }
    }
}
