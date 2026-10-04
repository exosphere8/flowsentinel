//! Streaming statistics with constant memory.

use serde::Serialize;

/// Running count, min, max, mean and population standard deviation
/// (Welford's algorithm), using constant memory.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Running {
    count: u64,
    mean: f64,
    m2: f64,
    min: f64,
    max: f64,
}

impl Running {
    pub(crate) fn add(&mut self, value: f64) {
        if !value.is_finite() {
            return;
        }
        self.count = self.count.saturating_add(1);
        if self.count == 1 {
            self.min = value;
            self.max = value;
        } else {
            self.min = self.min.min(value);
            self.max = self.max.max(value);
        }
        let n = self.count as f64;
        let delta = value - self.mean;
        self.mean += delta / n;
        self.m2 += delta * (value - self.mean);
    }

    #[cfg(test)]
    pub(crate) fn count(&self) -> u64 {
        self.count
    }

    pub(crate) fn summary(&self) -> Option<Summary> {
        if self.count == 0 {
            return None;
        }
        let n = self.count as f64;
        let variance = (self.m2 / n).max(0.0);
        Some(Summary {
            min: self.min,
            max: self.max,
            mean: self.mean,
            stddev: variance.sqrt(),
        })
    }
}

/// Snapshot of a [`Running`] statistic.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Summary {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    /// Population standard deviation.
    pub stddev: f64,
}

/// Keeps the first [`Self::CAPACITY`] values to compute a median. Beyond
/// that, the median is computed over those first values only and reported
/// as approximate.
#[derive(Debug, Clone, Default)]
pub(crate) struct MedianSample {
    values: Vec<u32>,
    seen: u64,
}

impl MedianSample {
    pub(crate) const CAPACITY: usize = 256;

    pub(crate) fn add(&mut self, value: u32) {
        self.seen = self.seen.saturating_add(1);
        if self.values.len() < Self::CAPACITY {
            self.values.push(value);
        }
    }

    /// The median and whether it is exact (all values were kept).
    pub(crate) fn median(&self) -> Option<(f64, bool)> {
        let mut sorted = self.values.clone();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        let median = match sorted.len() {
            0 => return None,
            n if n % 2 == 1 => f64::from(*sorted.get(mid)?),
            _ => (f64::from(*sorted.get(mid - 1)?) + f64::from(*sorted.get(mid)?)) / 2.0,
        };
        let exact = u64::try_from(sorted.len()).is_ok_and(|kept| kept == self.seen);
        Some((median, exact))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_statistics_match_direct_computation() {
        let values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let mut r = Running::default();
        for v in values {
            r.add(v);
        }
        let s = r.summary().unwrap();
        assert_eq!((s.min, s.max), (2.0, 9.0));
        assert!((s.mean - 5.0).abs() < 1e-12);
        assert!((s.stddev - 2.0).abs() < 1e-12);
        assert_eq!(r.count(), 8);
    }

    #[test]
    fn empty_and_non_finite_inputs() {
        let mut r = Running::default();
        assert!(r.summary().is_none());
        r.add(f64::NAN);
        r.add(f64::INFINITY);
        assert!(r.summary().is_none());
        r.add(3.0);
        assert_eq!(r.summary().unwrap().stddev, 0.0);
    }

    #[test]
    fn median_is_exact_until_capacity() {
        let mut m = MedianSample::default();
        assert!(m.median().is_none());
        for v in [5, 1, 3] {
            m.add(v);
        }
        assert_eq!(m.median(), Some((3.0, true)));
        m.add(10);
        assert_eq!(m.median(), Some((4.0, true)));
        for _ in 0..MedianSample::CAPACITY {
            m.add(100);
        }
        assert!(!m.median().unwrap().1);
    }
}
