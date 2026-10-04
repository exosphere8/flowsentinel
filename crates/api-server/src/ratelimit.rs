//! Limits on failed password checks, per account name and per client
//! address, kept in memory.
//!
//! An account name with [`MAX_FAILURES_PER_NAME`] failures in the last
//! [`WINDOW`] is locked until the oldest of them is older than the window;
//! a client address with [`MAX_FAILURES_PER_ADDRESS`] failures likewise.
//! The table holds at most [`MAX_KEYS`] names and addresses; when it is full,
//! keys whose failures have all expired go first, then the least recently
//! failed. Limits reset when the server restarts.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

pub const WINDOW: Duration = Duration::from_secs(15 * 60);
pub const MAX_FAILURES_PER_NAME: usize = 5;
pub const MAX_FAILURES_PER_ADDRESS: usize = 20;
pub const MAX_KEYS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Name(String),
    Address(IpAddr),
}

impl Key {
    fn limit(&self) -> usize {
        match self {
            Self::Name(_) => MAX_FAILURES_PER_NAME,
            Self::Address(_) => MAX_FAILURES_PER_ADDRESS,
        }
    }
}

/// Recent failure times per key, oldest first.
#[derive(Debug, Default)]
pub struct LoginLimiter {
    failures: Mutex<HashMap<Key, VecDeque<Instant>>>,
}

fn keys(name: &str, address: Option<IpAddr>) -> impl Iterator<Item = Key> {
    std::iter::once(Key::Name(name.to_owned())).chain(address.map(Key::Address))
}

fn expire(times: &mut VecDeque<Instant>, now: Instant) {
    while times
        .front()
        .is_some_and(|&first| now.saturating_duration_since(first) >= WINDOW)
    {
        times.pop_front();
    }
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// `Err(retry_after)` when the name or the address is locked at `now`.
    pub fn check(&self, name: &str, address: Option<IpAddr>, now: Instant) -> Result<(), Duration> {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let mut wait = Duration::ZERO;
        for key in keys(name, address) {
            let limit = key.limit();
            if let Some(times) = failures.get_mut(&key) {
                expire(times, now);
                if times.len() >= limit {
                    // Unlocked once enough of the failures leave the window.
                    let unlock = times
                        .get(times.len() - limit)
                        .map(|&t| WINDOW.saturating_sub(now.saturating_duration_since(t)))
                        .unwrap_or(WINDOW);
                    wait = wait.max(unlock);
                }
            }
        }
        if wait.is_zero() {
            Ok(())
        } else {
            Err(wait.max(Duration::from_secs(1)))
        }
    }

    /// Records a failed password check.
    pub fn failure(&self, name: &str, address: Option<IpAddr>, now: Instant) {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        for key in keys(name, address) {
            if !failures.contains_key(&key) && failures.len() >= MAX_KEYS {
                make_room(&mut failures, now);
            }
            let limit = key.limit();
            let times = failures.entry(key).or_default();
            expire(times, now);
            times.push_back(now);
            // Older failures no longer change the outcome.
            while times.len() > limit {
                times.pop_front();
            }
        }
    }

    /// Clears an account name's failures after a successful sign-in. The
    /// address keeps its count.
    pub fn success(&self, name: &str) {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        failures.remove(&Key::Name(name.to_owned()));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Frees at least one slot: drops expired keys, or else the key whose last
/// failure is oldest.
fn make_room(failures: &mut HashMap<Key, VecDeque<Instant>>, now: Instant) {
    failures.retain(|_, times| {
        expire(times, now);
        !times.is_empty()
    });
    if failures.len() < MAX_KEYS {
        return;
    }
    let oldest = failures
        .iter()
        .min_by_key(|(_, times)| times.back().copied())
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest {
        failures.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9)));

    #[test]
    fn names_lock_after_five_failures_until_the_window_passes() {
        let limiter = LoginLimiter::new();
        let start = Instant::now();
        for i in 0..MAX_FAILURES_PER_NAME {
            assert!(limiter.check("ana", ADDR, start).is_ok(), "attempt {i}");
            limiter.failure("ana", ADDR, start + Duration::from_secs(i as u64));
        }
        let locked = limiter.check("ana", None, start + Duration::from_secs(10));
        // The first failure (at +0 s) leaves the window at +15 min.
        assert_eq!(locked, Err(WINDOW - Duration::from_secs(10)));
        // Other names are unaffected.
        assert!(limiter.check("bob", None, start).is_ok());
        assert!(limiter.check("ana", None, start + WINDOW).is_ok());
    }

    #[test]
    fn a_success_clears_the_name_but_not_the_address() {
        let limiter = LoginLimiter::new();
        let now = Instant::now();
        for _ in 0..MAX_FAILURES_PER_NAME {
            limiter.failure("ana", ADDR, now);
        }
        assert!(limiter.check("ana", None, now).is_err());
        limiter.success("ana");
        assert!(limiter.check("ana", None, now).is_ok());
        for i in 0..MAX_FAILURES_PER_ADDRESS {
            limiter.failure(&format!("user{i}"), ADDR, now);
        }
        assert!(limiter.check("someone-new", ADDR, now).is_err());
        assert!(limiter.check("someone-new", None, now).is_ok());
    }

    #[test]
    fn the_table_stays_bounded() {
        let limiter = LoginLimiter::new();
        let now = Instant::now();
        for i in 0..(MAX_KEYS + 50) {
            limiter.failure(
                &format!("user{i}"),
                None,
                now + Duration::from_millis(i as u64),
            );
        }
        assert_eq!(limiter.len(), MAX_KEYS);
        // The newest keys are kept.
        for _ in 1..MAX_FAILURES_PER_NAME {
            limiter.failure(&format!("user{}", MAX_KEYS + 49), None, now);
        }
        assert!(
            limiter
                .check(&format!("user{}", MAX_KEYS + 49), None, now)
                .is_err()
        );
        // Expired keys make room before live ones are dropped.
        limiter.failure("late", None, now + WINDOW + Duration::from_secs(60));
        assert_eq!(limiter.len(), 1);
    }
}
