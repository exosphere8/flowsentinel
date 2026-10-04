//! Bounded sliding time windows.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::Duration;

/// Events kept per window; older events are dropped first when full, so a
/// window's memory is bounded however busy its key is.
pub const MAX_EVENTS_PER_WINDOW: usize = 4096;
/// Events kept across all keys of one packet rule. When the budget is used
/// up, further events are counted instead of evaluated until expired ones
/// are swept out.
pub const MAX_EVENTS_PER_RULE: usize = 131_072;
/// Fewest events between two sweeps, so sweeping stays cheap per event.
const MIN_EVENTS_BETWEEN_SWEEPS: usize = 256;
/// Windows smaller than this many slots are never shrunk.
const MIN_SHRINK_CAPACITY: usize = 64;

/// What an alert can cite for one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cite {
    /// A packet index (packet rules) or flow ID (flow rules).
    pub reference: u64,
    /// The flow the packet belongs to; 0 when it has none.
    pub flow: u64,
}

impl Cite {
    pub(crate) fn packet(index: u64, flow: Option<u64>) -> Self {
        Self {
            reference: index,
            flow: flow.unwrap_or(0),
        }
    }

    pub(crate) fn flow(flow_id: u64) -> Self {
        Self {
            reference: flow_id,
            flow: flow_id,
        }
    }
}

/// Counts events, and distinct values among them, within the last `width`
/// of time. Times may arrive slightly out of order; an event older than
/// `width` before the newest time seen is not counted.
#[derive(Debug)]
pub(crate) struct Window<T> {
    events: VecDeque<(u128, T, Cite)>,
    counts: HashMap<T, u32>,
    width: u128,
    newest: u128,
}

impl<T: Eq + Hash + Clone> Window<T> {
    pub(crate) fn new(width: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            counts: HashMap::new(),
            width: width.as_nanos(),
            newest: 0,
        }
    }

    /// Adds an event and returns `(events, distinct values)` in the window,
    /// or gives the value back when the event is not counted: older than the
    /// window, or later than `limit` (the latest believable time, when
    /// known). The newest time never passes `limit`, so one far-future
    /// timestamp cannot push every later event out of the window.
    pub(crate) fn add(
        &mut self,
        at: u128,
        value: T,
        cite: Cite,
        limit: Option<u128>,
    ) -> Result<(usize, usize), T> {
        if let Some(limit) = limit {
            if at > limit {
                return Err(value);
            }
            self.newest = self.newest.min(limit);
        }
        self.newest = self.newest.max(at);
        let cutoff = self.newest.saturating_sub(self.width);
        while let Some((time, _, _)) = self.events.front() {
            if *time >= cutoff && self.events.len() < MAX_EVENTS_PER_WINDOW {
                break;
            }
            self.pop_front();
        }
        self.shrink();
        if at < cutoff {
            return Err(value);
        }
        *self.counts.entry(value.clone()).or_insert(0) += 1;
        self.events.push_back((at, value, cite));
        Ok((self.events.len(), self.counts.len()))
    }

    /// The oldest `max` events still in the window.
    pub(crate) fn earliest(&self, max: usize) -> Vec<(u128, Cite)> {
        self.events
            .iter()
            .take(max)
            .map(|(time, _, cite)| (*time, *cite))
            .collect()
    }

    fn len(&self) -> usize {
        self.events.len()
    }

    fn newest(&self) -> u128 {
        self.newest
    }

    /// Drops events older than `cutoff`.
    fn expire(&mut self, cutoff: u128) {
        while self
            .events
            .front()
            .is_some_and(|(time, _, _)| *time < cutoff)
        {
            self.pop_front();
        }
        self.shrink();
    }

    /// Returns memory once a window holds far fewer events than it has room
    /// for, so memory follows the events held, not the peak.
    fn shrink(&mut self) {
        let len = self.events.len();
        if self.events.capacity() > MIN_SHRINK_CAPACITY
            && len.saturating_mul(4) < self.events.capacity()
        {
            self.events.shrink_to(len.saturating_mul(2));
        }
        let distinct = self.counts.len();
        if self.counts.capacity() > MIN_SHRINK_CAPACITY
            && distinct.saturating_mul(4) < self.counts.capacity()
        {
            self.counts.shrink_to(distinct.saturating_mul(2));
        }
    }

    fn pop_front(&mut self) {
        let Some((_, value, _)) = self.events.pop_front() else {
            return;
        };
        if let Some(count) = self.counts.get_mut(&value) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.counts.remove(&value);
            }
        }
    }
}

/// Windows by key, with fixed maximums for keys and for events across all
/// keys.
///
/// - Keys whose events have all expired are swept out periodically. The
///   time used for that is a clock that moves only when two consecutive
///   events agree, so a lone corrupt timestamp can neither expire every
///   window nor keep stale keys alive.
/// - Events more than a window ahead of that clock are not evaluated, and
///   no window's newest time can pass it, so one far-future timestamp cannot
///   blind a key.
/// - When the key table is full, the half of the keys seen least recently
///   is evicted, so new clients and domains are always evaluated.
/// - A clock confirmed to have jumped back by more than the window width
///   (for example, concatenated captures) starts every window afresh,
///   including the event that announced the jump.
///
/// Events that are not evaluated (over the event budget, too old or too far
/// ahead) are counted in `dropped`; evicted keys in `evicted`.
#[derive(Debug)]
pub(crate) struct Windows<K, T> {
    windows: HashMap<K, Window<T>>,
    width: Duration,
    max_keys: usize,
    max_events: usize,
    /// Events currently held across all windows.
    events: usize,
    since_sweep: usize,
    /// Events until the next sweep: the keys left by the previous sweep (at
    /// least 256), so a sweep costs at most twice the events since the last.
    sweep_every: usize,
    previous: Option<u128>,
    clock: Option<u128>,
    /// The last event not counted for being too old, re-added if the clock
    /// then confirms a backward jump.
    late: Option<(K, u128, T, Cite)>,
    pub dropped: u64,
    pub evicted: u64,
}

impl<K: Eq + Hash + Clone, T: Eq + Hash + Clone> Windows<K, T> {
    pub(crate) fn new(width: Duration, max_keys: usize) -> Self {
        Self::with_budget(width, max_keys, MAX_EVENTS_PER_RULE)
    }

    pub(crate) fn with_budget(width: Duration, max_keys: usize, max_events: usize) -> Self {
        Self {
            windows: HashMap::new(),
            width,
            max_keys: max_keys.max(2),
            max_events,
            events: 0,
            since_sweep: 0,
            sweep_every: MIN_EVENTS_BETWEEN_SWEEPS,
            previous: None,
            clock: None,
            late: None,
            dropped: 0,
            evicted: 0,
        }
    }

    /// Advances the confirmed clock: forward to the lower of the last two
    /// event times, or back (resetting every window) when both are more
    /// than a window width behind it.
    fn tick(&mut self, at: u128) {
        let previous = self.previous.replace(at);
        let Some(previous) = previous else {
            return;
        };
        let width = self.width.as_nanos();
        let (low, high) = (previous.min(at), previous.max(at));
        match self.clock {
            None => self.clock = Some(low),
            Some(clock) if low > clock => self.clock = Some(low),
            Some(clock) if high.saturating_add(width) < clock => {
                self.windows.clear();
                self.events = 0;
                self.since_sweep = 0;
                self.sweep_every = MIN_EVENTS_BETWEEN_SWEEPS;
                self.clock = Some(high);
                // The event that announced the jump was not counted; it
                // belongs to the new timeline.
                if let Some((key, time, value, cite)) = self.late.take() {
                    if time.saturating_add(width) >= high {
                        self.dropped = self.dropped.saturating_sub(1);
                        let _ = self.insert(key, time, value, cite);
                    }
                }
            }
            Some(_) => {}
        }
    }

    /// Expires events older than the window before the confirmed clock and
    /// removes empty windows. The keys it visits number at most the keys it
    /// left last time plus the events since, so its cost per event is
    /// constant.
    fn sweep_if_due(&mut self) {
        self.since_sweep = self.since_sweep.saturating_add(1);
        if self.since_sweep < self.sweep_every {
            return;
        }
        self.since_sweep = 0;
        let Some(clock) = self.clock else {
            return;
        };
        let cutoff = clock.saturating_sub(self.width.as_nanos());
        let mut events = 0usize;
        self.windows.retain(|_, window| {
            window.expire(cutoff);
            events = events.saturating_add(window.len());
            window.len() > 0
        });
        self.events = events;
        self.sweep_every = self.windows.len().max(MIN_EVENTS_BETWEEN_SWEEPS);
    }

    /// Removes the half of the keys whose newest event is oldest. Runs at
    /// most once per `max_keys / 2` new keys, so its cost per key is
    /// constant.
    fn evict_oldest_half(&mut self) {
        let mut ages: Vec<(u128, K)> = self
            .windows
            .iter()
            .map(|(key, window)| (window.newest(), key.clone()))
            .collect();
        let half = ages.len() / 2;
        if half == 0 {
            return;
        }
        ages.select_nth_unstable_by_key(half - 1, |(newest, _)| *newest);
        for (_, key) in ages.into_iter().take(half) {
            if let Some(window) = self.windows.remove(&key) {
                self.events = self.events.saturating_sub(window.len());
                self.evicted = self.evicted.saturating_add(1);
            }
        }
    }

    /// Adds `value` to `key`'s window without the checks of [`Self::add`].
    fn insert(&mut self, key: K, at: u128, value: T, cite: Cite) -> Result<(usize, usize), T> {
        let width = self.width;
        let window = self
            .windows
            .entry(key)
            .or_insert_with(|| Window::new(width));
        let before = window.len();
        let result = window.add(at, value, cite, None);
        let after = window.len();
        self.events = self.events.saturating_sub(before).saturating_add(after);
        result
    }

    /// Adds an event for `key`; `None` when it was not evaluated.
    pub(crate) fn add(&mut self, key: K, at: u128, value: T, cite: Cite) -> Option<(usize, usize)> {
        self.tick(at);
        self.sweep_if_due();
        if self.events >= self.max_events {
            self.dropped = self.dropped.saturating_add(1);
            return None;
        }
        let known = self.windows.contains_key(&key);
        if !known && self.windows.len() >= self.max_keys {
            self.evict_oldest_half();
        }
        let width = self.width;
        let limit = self
            .clock
            .map(|clock| clock.saturating_add(width.as_nanos()));
        let window = self
            .windows
            .entry(key.clone())
            .or_insert_with(|| Window::new(width));
        let before = window.len();
        let result = window.add(at, value, cite, limit);
        let after = window.len();
        self.events = self.events.saturating_sub(before).saturating_add(after);
        match result {
            Ok(counts) => Some(counts),
            Err(value) => {
                if after == 0 {
                    self.windows.remove(&key);
                }
                self.dropped = self.dropped.saturating_add(1);
                if limit.is_none_or(|limit| at <= limit) {
                    self.late = Some((key, at, value, cite));
                }
                None
            }
        }
    }

    #[cfg(test)]
    fn held(&self) -> (usize, usize) {
        (self.windows.len(), self.events)
    }

    /// The distinct values in `key`'s window.
    pub(crate) fn values(&self, key: &K) -> std::collections::HashSet<T> {
        self.windows
            .get(key)
            .map(|w| w.counts.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The oldest `max` events in `key`'s window.
    pub(crate) fn earliest(&self, key: &K, max: usize) -> Vec<(u128, Cite)> {
        self.windows
            .get(key)
            .map(|w| w.earliest(max))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u128 = 1_000_000_000;
    const NONE: Cite = Cite {
        reference: 0,
        flow: 0,
    };

    fn cite(reference: u64) -> Cite {
        Cite { reference, flow: 0 }
    }

    #[test]
    fn counts_events_and_distinct_values_in_the_window() {
        let mut w = Window::new(Duration::from_secs(10));
        assert_eq!(w.add(0, 1, cite(1), None), Ok((1, 1)));
        assert_eq!(w.add(S, 2, cite(2), None), Ok((2, 2)));
        assert_eq!(w.add(2 * S, 2, cite(3), None), Ok((3, 2)));
        // 11 s: the event at 0 has left the window.
        assert_eq!(w.add(11 * S, 3, cite(4), None), Ok((3, 2)));
        let refs: Vec<(u128, u64)> = w
            .earliest(10)
            .into_iter()
            .map(|(t, c)| (t, c.reference))
            .collect();
        assert_eq!(refs, [(S, 2), (2 * S, 3), (11 * S, 4)]);
        // An event older than the window is not counted.
        assert_eq!(w.add(0, 9, cite(5), None), Err(9));
        // Nor one past the believable limit.
        assert_eq!(w.add(100 * S, 9, cite(6), Some(20 * S)), Err(9));
    }

    #[test]
    fn windows_are_bounded_and_return_memory() {
        let mut w = Window::new(Duration::from_secs(1_000_000));
        for i in 0..(MAX_EVENTS_PER_WINDOW as u128 + 10) {
            let _ = w.add(i, i, NONE, None);
        }
        let (events, distinct) = w.add(u128::MAX / 2, 0, NONE, None).unwrap();
        assert!(events <= MAX_EVENTS_PER_WINDOW && distinct <= MAX_EVENTS_PER_WINDOW);
        // Once the events expire, the window gives its memory back.
        let mut big = Window::new(Duration::from_secs(10));
        for i in 0..4000u128 {
            let _ = big.add(i, i, NONE, None);
        }
        assert!(big.events.capacity() >= 4000);
        big.expire(1_000 * S);
        assert_eq!(big.len(), 0);
        assert!(
            big.events.capacity() <= MIN_SHRINK_CAPACITY * 2,
            "{}",
            big.events.capacity()
        );
        assert!(big.counts.capacity() <= MIN_SHRINK_CAPACITY * 2);

        // The event budget spans keys.
        let mut budget = Windows::with_budget(Duration::from_secs(60), 100, 3);
        for key in 0..3 {
            assert!(budget.add(key, 0, (), NONE).is_some());
        }
        assert!(budget.add(0, 1, (), NONE).is_none());
        assert_eq!(budget.held(), (3, 3));
    }

    #[test]
    fn a_full_key_table_evicts_the_least_recent_keys() {
        let mut keys = Windows::new(Duration::from_secs(60), 4);
        for (key, at) in [(1u32, 1), (2, 2), (3, 3), (4, 4)] {
            assert!(keys.add(key, at * S, (), NONE).is_some());
        }
        // Key 1 is refreshed, so keys 2 and 3 are the oldest.
        assert!(keys.add(1, 5 * S, (), NONE).is_some());
        assert!(
            keys.add(5, 6 * S, (), NONE).is_some(),
            "a new key is evaluated"
        );
        assert_eq!(keys.evicted, 2);
        assert_eq!(keys.held().0, 3);
        assert!(keys.earliest(&2, 1).is_empty() && keys.earliest(&3, 1).is_empty());
        assert!(!keys.earliest(&1, 1).is_empty());
        assert_eq!(keys.dropped, 0);
    }

    #[test]
    fn expired_keys_are_swept_so_new_keys_fit() {
        let mut w = Windows::new(Duration::from_secs(10), 300);
        // 300 keys in the first second, then one event per second for a
        // single key: the old keys expire and are swept out.
        for key in 0..300u32 {
            assert!(w.add(key, 0, (), NONE).is_some());
        }
        for second in 1..=400u128 {
            w.add(0, second * S, (), NONE);
        }
        let (keys, events) = w.held();
        assert_eq!(keys, 1, "only the active key remains");
        assert!(events <= 11, "{events}");
        assert!(w.add(9999, 400 * S, (), NONE).is_some());
        assert_eq!((w.dropped, w.evicted), (0, 0));
    }

    #[test]
    fn a_long_capture_of_distinct_keys_is_fully_evaluated() {
        let mut w = Windows::new(Duration::from_secs(300), 16_384);
        for i in 0..60_000u32 {
            assert!(w.add(i, u128::from(i) * S, (), NONE).is_some(), "event {i}");
        }
        assert_eq!((w.dropped, w.evicted), (0, 0));
        assert!(w.held().0 <= 301 + 300, "{:?}", w.held());
    }

    #[test]
    fn a_lone_outlier_does_not_move_the_clock() {
        let mut w = Windows::new(Duration::from_secs(10), 1000);
        for key in 0..600u32 {
            // Every 100th event claims to be a year later.
            let at = if key % 100 == 50 {
                365 * 86_400 * S
            } else {
                u128::from(key) * S / 100
            };
            w.add(key, at, (), NONE);
        }
        // Nothing was expired by the outliers.
        assert!(w.held().0 >= 594);
    }

    #[test]
    fn a_far_future_timestamp_does_not_blind_its_key() {
        let mut w = Windows::new(Duration::from_secs(60), 100);
        assert!(w.add(0u32, S, (), NONE).is_some());
        assert!(w.add(0, 2 * S, (), NONE).is_some());
        // One event stamped decades later, then ordinary traffic.
        assert!(w.add(0, 2_000_000_000 * S, (), NONE).is_none());
        for i in 3..400u128 {
            assert!(w.add(0, i * S / 10, (), NONE).is_some(), "event {i}");
        }
        assert_eq!(w.dropped, 1, "the outlier is counted, not silently lost");
    }

    #[test]
    fn a_confirmed_backward_jump_starts_afresh() {
        let mut w = Windows::new(Duration::from_secs(10), 1000);
        for i in 0..20u32 {
            w.add(0, 1_000 * S + u128::from(i) * S, (), NONE);
        }
        // A second capture appended, starting much earlier: its first event
        // is not counted at first, then restored once the jump is confirmed.
        assert_eq!(w.add(0, 5 * S, (), NONE), None);
        assert_eq!(
            w.add(0, 6 * S, (), NONE),
            Some((2, 1)),
            "key 0 starts afresh"
        );
        assert_eq!(w.dropped, 0);
        assert_eq!(w.add(1, 7 * S, (), NONE), Some((1, 1)));
    }
}
