//! Limits on password checks, per account name and per client address, kept
//! in memory.
//!
//! Every password check first reserves an attempt with [`LoginLimiter::attempt`],
//! which checks the limits and records the attempt in one step, so requests
//! running in parallel cannot all pass the check before any of them has
//! failed. A successful check gives the attempt back
//! ([`LoginLimiter::succeeded`]); a failed one keeps it.
//!
//! An account name with [`MAX_FAILURES_PER_NAME`] attempts kept in the last
//! [`WINDOW`] is locked until the oldest of them is older than the window;
//! a client address with [`MAX_FAILURES_PER_ADDRESS`] likewise. The table
//! holds at most [`MAX_KEYS`] names and addresses; when it is full, keys
//! whose attempts have all expired go first, then the least recently used.
//! Limits reset when the server restarts.

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

#[derive(Debug, Default)]
struct Entry {
    /// Attempts kept, oldest first.
    times: VecDeque<Instant>,
    /// A refusal during the current lock has already been reported.
    refusal_reported: bool,
}

/// A refused attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locked {
    pub retry_after: Duration,
    /// The first refusal since this lock began; later ones are not worth
    /// auditing one by one.
    pub first: bool,
}

/// Recent attempts per key.
#[derive(Debug, Default)]
pub struct LoginLimiter {
    entries: Mutex<HashMap<Key, Entry>>,
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

    /// Reserves a password check for `name` from `address` at `now`, or
    /// refuses it while either is locked.
    pub fn attempt(&self, name: &str, address: Option<IpAddr>, now: Instant) -> Result<(), Locked> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let mut wait = Duration::ZERO;
        let mut first = false;
        for key in keys(name, address) {
            let limit = key.limit();
            if let Some(entry) = entries.get_mut(&key) {
                expire(&mut entry.times, now);
                if entry.times.len() >= limit {
                    // Unlocked once enough attempts leave the window.
                    let unlock = entry
                        .times
                        .get(entry.times.len() - limit)
                        .map(|&t| WINDOW.saturating_sub(now.saturating_duration_since(t)))
                        .unwrap_or(WINDOW);
                    wait = wait.max(unlock);
                    first |= !entry.refusal_reported;
                    entry.refusal_reported = true;
                }
            }
        }
        if !wait.is_zero() {
            return Err(Locked {
                retry_after: wait.max(Duration::from_secs(1)),
                first,
            });
        }
        for key in keys(name, address) {
            if !entries.contains_key(&key) && entries.len() >= MAX_KEYS {
                make_room(&mut entries, now);
            }
            let limit = key.limit();
            let entry = entries.entry(key).or_default();
            entry.refusal_reported = false;
            entry.times.push_back(now);
            // Older attempts no longer change the outcome.
            while entry.times.len() > limit {
                entry.times.pop_front();
            }
        }
        Ok(())
    }

    /// Gives back an attempt made at `at` whose password was right: the
    /// name's attempts are cleared, and the address's attempt is removed.
    pub fn succeeded(&self, name: &str, address: Option<IpAddr>, at: Instant) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.remove(&Key::Name(name.to_owned()));
        if let Some(entry) = address.and_then(|a| entries.get_mut(&Key::Address(a))) {
            if let Some(position) = entry.times.iter().position(|&t| t == at) {
                entry.times.remove(position);
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Frees at least one slot: drops expired keys, or else the key whose last
/// attempt is oldest.
fn make_room(entries: &mut HashMap<Key, Entry>, now: Instant) {
    entries.retain(|_, entry| {
        expire(&mut entry.times, now);
        !entry.times.is_empty()
    });
    if entries.len() < MAX_KEYS {
        return;
    }
    let oldest = entries
        .iter()
        .min_by_key(|(_, entry)| entry.times.back().copied())
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest {
        entries.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9)));

    #[test]
    fn names_lock_after_five_attempts_until_the_window_passes() {
        let limiter = LoginLimiter::new();
        let start = Instant::now();
        for i in 0..MAX_FAILURES_PER_NAME {
            assert!(
                limiter
                    .attempt("ana", ADDR, start + Duration::from_secs(i as u64))
                    .is_ok(),
                "attempt {i}"
            );
        }
        let locked = limiter
            .attempt("ana", None, start + Duration::from_secs(10))
            .unwrap_err();
        // The first attempt (at +0 s) leaves the window at +15 min.
        assert_eq!(locked.retry_after, WINDOW - Duration::from_secs(10));
        assert!(locked.first);
        // Further refusals during the same lock are not "first".
        let again = limiter.attempt("ana", None, start + Duration::from_secs(11));
        assert!(!again.unwrap_err().first);
        // Other names are unaffected.
        assert!(limiter.attempt("bob", None, start).is_ok());
        assert!(limiter.attempt("ana", None, start + WINDOW).is_ok());
    }

    #[test]
    fn parallel_attempts_cannot_pass_together() {
        let limiter = std::sync::Arc::new(LoginLimiter::new());
        let now = Instant::now();
        let passed: usize = (0..64)
            .map(|_| {
                let limiter = std::sync::Arc::clone(&limiter);
                std::thread::spawn(move || limiter.attempt("admin", ADDR, now).is_ok())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum();
        assert_eq!(passed, MAX_FAILURES_PER_NAME);
    }

    #[test]
    fn a_success_gives_the_attempt_back() {
        let limiter = LoginLimiter::new();
        let now = Instant::now();
        for _ in 0..MAX_FAILURES_PER_NAME - 1 {
            limiter.attempt("ana", ADDR, now).unwrap();
        }
        let at = now + Duration::from_secs(1);
        limiter.attempt("ana", ADDR, at).unwrap();
        limiter.succeeded("ana", ADDR, at);
        assert!(limiter.attempt("ana", None, at).is_ok());
        // Successful sign-ins never lock an address.
        for i in 0..(MAX_FAILURES_PER_ADDRESS * 2) {
            let at = now + Duration::from_millis(10 + i as u64);
            limiter.attempt(&format!("user{i}"), ADDR, at).unwrap();
            limiter.succeeded(&format!("user{i}"), ADDR, at);
        }
        assert!(limiter.attempt("someone-new", ADDR, now).is_ok());
        // Failures from one address lock it for every name.
        for i in 0..MAX_FAILURES_PER_ADDRESS {
            let _ = limiter.attempt(&format!("guess{i}"), ADDR, now);
        }
        assert!(limiter.attempt("another", ADDR, now).is_err());
        assert!(limiter.attempt("another", None, now).is_ok());
    }

    #[test]
    fn the_table_stays_bounded() {
        let limiter = LoginLimiter::new();
        let now = Instant::now();
        for i in 0..(MAX_KEYS + 50) {
            let _ = limiter.attempt(
                &format!("user{i}"),
                None,
                now + Duration::from_millis(i as u64),
            );
        }
        assert_eq!(limiter.len(), MAX_KEYS);
        // The newest keys are kept.
        let newest = format!("user{}", MAX_KEYS + 49);
        for _ in 1..MAX_FAILURES_PER_NAME {
            let _ = limiter.attempt(&newest, None, now);
        }
        assert!(limiter.attempt(&newest, None, now).is_err());
        // Expired keys make room before live ones are dropped.
        let _ = limiter.attempt("late", None, now + WINDOW + Duration::from_secs(60));
        assert_eq!(limiter.len(), 1);
    }
}
