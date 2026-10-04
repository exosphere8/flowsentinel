//! The flow table: matching, expiry, eviction and output.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use decoder::Layer;
use serde::Serialize;

use crate::flow::{ActiveFlow, FlowPacket};
use crate::key::FlowKey;
use crate::observe::observe;
use crate::record::{EndReason, FlowRecord};

/// Configuration for a [`FlowEngine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowConfig {
    /// Most flows tracked at once. When full, the least recently seen flow
    /// is evicted to admit a new one.
    pub max_active_flows: usize,
    /// Most finished flows kept for output; further flows are counted but
    /// not kept.
    pub max_retained_flows: usize,
    /// Idle timeout for open TCP flows.
    pub tcp_idle_timeout: Duration,
    /// Idle timeout for UDP, ICMP and other flows.
    pub idle_timeout: Duration,
    /// How long a TCP flow is kept after FIN in both directions or RST, to
    /// absorb trailing ACKs and retransmissions.
    pub tcp_finished_timeout: Duration,
}

impl FlowConfig {
    pub const DEFAULT_MAX_ACTIVE_FLOWS: usize = 65_536;
    pub const DEFAULT_MAX_RETAINED_FLOWS: usize = 100_000;
    pub const DEFAULT_TCP_IDLE_SECONDS: u64 = 300;
    pub const DEFAULT_IDLE_SECONDS: u64 = 60;
    pub const DEFAULT_TCP_FINISHED_SECONDS: u64 = 10;
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            max_active_flows: Self::DEFAULT_MAX_ACTIVE_FLOWS,
            max_retained_flows: Self::DEFAULT_MAX_RETAINED_FLOWS,
            tcp_idle_timeout: Duration::from_secs(Self::DEFAULT_TCP_IDLE_SECONDS),
            idle_timeout: Duration::from_secs(Self::DEFAULT_IDLE_SECONDS),
            tcp_finished_timeout: Duration::from_secs(Self::DEFAULT_TCP_FINISHED_SECONDS),
        }
    }
}

/// Totals over everything the engine processed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FlowSummary {
    pub packets_seen: u64,
    pub packets_in_flows: u64,
    /// Packets with no IP layer (ARP, unsupported or malformed frames).
    pub packets_without_ip: u64,
    pub flows_total: u64,
    pub flows_retained: u64,
    /// Finished flows beyond `max_retained_flows`, counted but not kept.
    pub flows_not_retained: u64,
    /// Highest number of simultaneously active flows.
    pub peak_active_flows: u64,
    pub end_reasons: BTreeMap<EndReason, u64>,
    /// Packets whose timestamp was more than a day away from the engine's
    /// clock and was not confirmed by the next timestamped packet. They did
    /// not move the clock.
    pub timestamp_outliers: u64,
    /// Times the clock moved by more than a day, forward or backward, after
    /// two consecutive packets agreed on the new time.
    pub clock_jumps: u64,
    pub max_active_flows: u64,
    pub max_retained_flows: u64,
}

/// Engine output: finished flows in `flow_id` order, plus totals.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FlowReport {
    pub summary: FlowSummary,
    pub flows: Vec<FlowRecord>,
}

/// Maps addresses to names learned from DNS answers in the capture, so later
/// flows to those addresses can be annotated. Bounded and first-in,
/// first-out.
#[derive(Debug, Default)]
struct NameCache {
    /// Names are shared with the flows they annotate, not copied.
    names: HashMap<IpAddr, Vec<Arc<str>>>,
    order: VecDeque<IpAddr>,
}

impl NameCache {
    const MAX_ADDRESSES: usize = 4096;
    const MAX_NAMES_PER_ADDRESS: usize = 4;

    fn learn(&mut self, layer: &Layer) {
        let Layer::Dns(message) = layer else {
            return;
        };
        if !message.is_response {
            return;
        }
        let question = message.questions.first().map(|q| q.name.as_str());
        for answer in &message.answers {
            let Some(ip) = answer
                .data
                .as_deref()
                .and_then(|d| d.parse::<IpAddr>().ok())
            else {
                continue;
            };
            for name in question.into_iter().chain([answer.name.as_str()]) {
                self.insert(ip, name);
            }
        }
    }

    fn insert(&mut self, ip: IpAddr, name: &str) {
        if !self.names.contains_key(&ip) {
            if self.order.len() == Self::MAX_ADDRESSES {
                if let Some(oldest) = self.order.pop_front() {
                    self.names.remove(&oldest);
                }
            }
            self.order.push_back(ip);
        }
        let names = self.names.entry(ip).or_default();
        if names.len() < Self::MAX_NAMES_PER_ADDRESS && !names.iter().any(|n| &**n == name) {
            names.push(Arc::from(name));
        }
    }

    fn lookup(&self, ip: IpAddr) -> Vec<Arc<str>> {
        self.names.get(&ip).cloned().unwrap_or_default()
    }
}

/// Largest jump in time the clock accepts without confirmation. Larger
/// jumps need the next timestamped packet to agree.
pub const MAX_UNCONFIRMED_JUMP: Duration = Duration::from_secs(86_400);

/// What the clock did with one timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The first valid timestamp.
    First,
    /// Within [`MAX_UNCONFIRMED_JUMP`] of the clock: time advances to it, or
    /// stays put if it is earlier.
    Accepted,
    /// It confirmed a pending jump; the clock moved by more than a day.
    Jumped { backward: bool },
    /// More than a day away and not (yet) confirmed: ignored for timekeeping.
    Held,
}

/// The engine's notion of "now", taken from packet timestamps but robust to
/// stray ones. Flows are timed by this clock, not by raw timestamps, so
/// reordered packets, merged captures with small clock skew and a corrupt
/// record cannot make flows expire early or never.
#[derive(Debug, Clone, Copy, Default)]
struct Clock {
    now: Option<u128>,
    candidate: Option<u128>,
    outliers: u64,
    jumps: u64,
}

impl Clock {
    fn observe(&mut self, ns: u128) -> Step {
        let tolerance = MAX_UNCONFIRMED_JUMP.as_nanos();
        let Some(now) = self.now else {
            self.now = Some(ns);
            return Step::First;
        };
        if ns.abs_diff(now) <= tolerance {
            if self.candidate.take().is_some() {
                self.outliers = self.outliers.saturating_add(1);
            }
            self.now = Some(now.max(ns));
            return Step::Accepted;
        }
        if let Some(candidate) = self.candidate.filter(|c| c.abs_diff(ns) <= tolerance) {
            let new = candidate.max(ns);
            self.now = Some(new);
            self.candidate = None;
            self.jumps = self.jumps.saturating_add(1);
            return Step::Jumped {
                backward: new < now,
            };
        }
        if self.candidate.replace(ns).is_some() {
            self.outliers = self.outliers.saturating_add(1);
        }
        Step::Held
    }
}

/// A retained record, ordered by flow ID so the heap's top is the highest.
#[derive(Debug)]
struct Retained(FlowRecord);

impl PartialEq for Retained {
    fn eq(&self, other: &Self) -> bool {
        self.0.flow_id == other.0.flow_id
    }
}

impl Eq for Retained {}

impl PartialOrd for Retained {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Retained {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.flow_id.cmp(&other.0.flow_id)
    }
}

/// Reconstructs bidirectional flows from decoded packets.
///
/// Memory is bounded by `max_active_flows` active flows and
/// `max_retained_flows` finished records, each with bounded metadata lists
/// (see `docs/flow-engine.md` for measured sizes). Results are
/// deterministic: the same packets in the same order always produce the
/// same flows, IDs and statistics.
#[derive(Debug)]
pub struct FlowEngine {
    config: FlowConfig,
    /// Boxed so the table's own allocation stays small as it grows.
    active: HashMap<FlowKey, Box<ActiveFlow>>,
    /// (deadline, flow id) -> key: flows ordered by when they expire.
    deadlines: BTreeMap<(u128, u64), FlowKey>,
    /// (packet sequence number, flow id) -> key: least recently seen first.
    recency: BTreeMap<(u64, u64), FlowKey>,
    /// Retained records, highest flow ID on top; when over the limit the
    /// highest ID is dropped, so the earliest flows are the ones kept.
    finished: BinaryHeap<Retained>,
    summary: FlowSummary,
    names: NameCache,
    next_id: u64,
    clock: Clock,
    /// The flow that received the timestamp the clock is holding.
    held_flow: Option<(FlowKey, u64)>,
}

impl FlowEngine {
    /// Creates an engine. Limits of 0 are raised to 1.
    pub fn new(config: FlowConfig) -> Self {
        let config = FlowConfig {
            max_active_flows: config.max_active_flows.max(1),
            max_retained_flows: config.max_retained_flows.max(1),
            ..config
        };
        let summary = FlowSummary {
            max_active_flows: u64::try_from(config.max_active_flows).unwrap_or(u64::MAX),
            max_retained_flows: u64::try_from(config.max_retained_flows).unwrap_or(u64::MAX),
            ..FlowSummary::default()
        };
        Self {
            config,
            active: HashMap::new(),
            deadlines: BTreeMap::new(),
            recency: BTreeMap::new(),
            finished: BinaryHeap::new(),
            summary,
            names: NameCache::default(),
            next_id: 1,
            clock: Clock::default(),
            held_flow: None,
        }
    }

    /// Number of flows currently active.
    pub fn active_flows(&self) -> usize {
        self.active.len()
    }

    /// Adds one packet and returns the ID of the flow it was assigned to, or
    /// `None` for packets without an IP layer. Packets should be given in
    /// capture order.
    pub fn process(&mut self, packet: &FlowPacket<'_>) -> Option<u64> {
        self.summary.packets_seen = self.summary.packets_seen.saturating_add(1);
        let sequence = self.summary.packets_seen;
        let step = packet
            .timestamp
            .map(|ts| self.clock.observe(ts.as_unix_nanos()));
        let held = step == Some(Step::Held);
        match (step, self.clock.now) {
            // Flows seen before the first timestamp start their idle time now.
            (Some(Step::First), Some(now)) => self.rebase(|last| last.max(now)),
            // The held timestamp was a lone outlier; forget its flow.
            (Some(Step::Accepted), _) => self.held_flow = None,
            (Some(Step::Jumped { backward }), _) => {
                self.confirm_held_flow(backward);
                if backward {
                    // Times before and after the jump cannot be compared.
                    self.end_all(EndReason::ClockReset);
                }
            }
            _ => {}
        }
        let now = self.clock.now;
        if let Some(now) = now {
            self.expire(now);
        }

        let Some(obs) = observe(packet.decoded) else {
            self.summary.packets_without_ip = self.summary.packets_without_ip.saturating_add(1);
            return None;
        };
        if let Some(layer) = obs.application {
            self.names.learn(layer);
        }
        self.summary.packets_in_flows = self.summary.packets_in_flows.saturating_add(1);

        if let Some(mut flow) = self.active.remove(&obs.key) {
            self.unindex(&flow);
            if self.starts_new_flow(&flow, &obs, packet) {
                let reason = if flow.tcp_finished() {
                    EndReason::TcpFinished
                } else {
                    EndReason::IdleTimeout
                };
                self.retire(*flow, reason);
            } else {
                flow.update(&obs, packet, now, sequence, held);
                self.index(&flow);
                let id = flow.id;
                self.active.insert(obs.key, flow);
                if held {
                    self.held_flow = Some((obs.key, id));
                }
                return Some(id);
            }
        }

        if self.active.len() >= self.config.max_active_flows {
            self.evict_least_recent();
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.summary.flows_total = self.summary.flows_total.saturating_add(1);
        let names = &self.names;
        let flow = Box::new(ActiveFlow::new(
            id,
            &obs,
            packet,
            now,
            sequence,
            held,
            |ip| names.lookup(ip),
        ));
        self.index(&flow);
        self.active.insert(obs.key, flow);
        if held {
            self.held_flow = Some((obs.key, id));
        }
        let active = u64::try_from(self.active.len()).unwrap_or(u64::MAX);
        self.summary.peak_active_flows = self.summary.peak_active_flows.max(active);
        Some(id)
    }

    /// Ends every remaining flow and returns all retained records in
    /// `flow_id` order.
    pub fn finish(mut self) -> FlowReport {
        let mut remaining: Vec<Box<ActiveFlow>> =
            self.active.drain().map(|(_, flow)| flow).collect();
        remaining.sort_by_key(|flow| flow.id);
        for flow in remaining {
            self.retire(*flow, EndReason::CaptureEnd);
        }
        self.summary.flows_retained = u64::try_from(self.finished.len()).unwrap_or(u64::MAX);
        // A timestamp still held at the end was never confirmed.
        self.summary.timestamp_outliers = self
            .clock
            .outliers
            .saturating_add(u64::from(self.clock.candidate.is_some()));
        self.summary.clock_jumps = self.clock.jumps;
        FlowReport {
            summary: self.summary,
            flows: self
                .finished
                .into_sorted_vec()
                .into_iter()
                .map(|retained| retained.0)
                .collect(),
        }
    }

    /// Whether `packet` begins a new connection on a closed flow's key: a SYN
    /// without ACK after FIN both ways or RST. (Idle flows were already
    /// ended by [`expire`](Self::expire).)
    fn starts_new_flow(
        &self,
        flow: &ActiveFlow,
        obs: &crate::observe::Observation<'_>,
        _packet: &FlowPacket<'_>,
    ) -> bool {
        flow.tcp_finished()
            && obs.tcp.is_some_and(|t| {
                t.flags.contains(decoder::TcpFlags::SYN)
                    && !t.flags.contains(decoder::TcpFlags::ACK)
            })
    }

    /// The clock confirmed the held timestamp: the flow that received it
    /// counts it after all, and after a forward jump is timed from it, so
    /// the conversation that follows a long gap is not cut off.
    fn confirm_held_flow(&mut self, backward: bool) {
        let Some((key, id)) = self.held_flow.take() else {
            return;
        };
        let Some(mut flow) = self.active.remove(&key) else {
            return;
        };
        if flow.id == id {
            self.unindex(&flow);
            if let Some(ns) = flow.confirm_held() {
                if !backward {
                    flow.last_ns = flow.last_ns.max(ns);
                }
            }
            self.index(&flow);
        }
        self.active.insert(key, flow);
    }

    /// Ends every active flow, in flow ID order.
    fn end_all(&mut self, reason: EndReason) {
        let mut flows: Vec<Box<ActiveFlow>> = self.active.drain().map(|(_, flow)| flow).collect();
        flows.sort_by_key(|flow| flow.id);
        self.deadlines.clear();
        self.recency.clear();
        for flow in flows {
            self.retire(*flow, reason);
        }
    }

    /// Re-times every active flow with `adjust(last_ns)`. Runs once, when the
    /// first timestamp arrives, over at most `max_active_flows` flows.
    fn rebase(&mut self, adjust: impl Fn(u128) -> u128) {
        let keys: Vec<FlowKey> = self.active.keys().copied().collect();
        for key in keys {
            if let Some(mut flow) = self.active.remove(&key) {
                self.unindex(&flow);
                flow.last_ns = adjust(flow.last_ns);
                self.index(&flow);
                self.active.insert(key, flow);
            }
        }
    }

    fn timeout(&self, flow: &ActiveFlow) -> Duration {
        if flow.tcp_finished() {
            self.config.tcp_finished_timeout
        } else if flow.key.protocol == 6 {
            self.config.tcp_idle_timeout
        } else {
            self.config.idle_timeout
        }
    }

    fn deadline(&self, flow: &ActiveFlow) -> u128 {
        flow.last_ns.saturating_add(self.timeout(flow).as_nanos())
    }

    fn index(&mut self, flow: &ActiveFlow) {
        self.deadlines
            .insert((self.deadline(flow), flow.id), flow.key);
        self.recency.insert((flow.last_sequence, flow.id), flow.key);
    }

    fn unindex(&mut self, flow: &ActiveFlow) {
        self.deadlines.remove(&(self.deadline(flow), flow.id));
        self.recency.remove(&(flow.last_sequence, flow.id));
    }

    /// Ends flows whose deadline is before `now`, oldest deadline first.
    fn expire(&mut self, now: u128) {
        while let Some((&(deadline, _), &key)) = self.deadlines.first_key_value() {
            if deadline >= now {
                break;
            }
            let Some(flow) = self.active.remove(&key) else {
                // Index out of sync: drop the stale entry.
                self.deadlines.pop_first();
                continue;
            };
            self.unindex(&flow);
            let reason = if flow.tcp_finished() {
                EndReason::TcpFinished
            } else {
                EndReason::IdleTimeout
            };
            self.retire(*flow, reason);
        }
    }

    fn evict_least_recent(&mut self) {
        let Some((_, &key)) = self.recency.first_key_value() else {
            return;
        };
        if let Some(flow) = self.active.remove(&key) {
            self.unindex(&flow);
            self.retire(*flow, EndReason::Evicted);
        } else {
            self.recency.pop_first();
        }
    }

    fn retire(&mut self, flow: ActiveFlow, reason: EndReason) {
        let count = self.summary.end_reasons.entry(reason).or_default();
        *count = count.saturating_add(1);
        // Keep the lowest flow IDs: only build a record that will be kept.
        let full = self.finished.len() >= self.config.max_retained_flows;
        if full
            && self
                .finished
                .peek()
                .is_none_or(|highest| flow.id > highest.0.flow_id)
        {
            self.summary.flows_not_retained = self.summary.flows_not_retained.saturating_add(1);
            return;
        }
        self.finished.push(Retained(flow.into_record(reason)));
        if self.finished.len() > self.config.max_retained_flows {
            self.finished.pop();
            self.summary.flows_not_retained = self.summary.flows_not_retained.saturating_add(1);
        }
    }
}
