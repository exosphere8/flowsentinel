//! Rules evaluated over finished flows, in order of each flow's start.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

use capture::Timestamp;
use flow_engine::{FlowRecord, InitiatorBasis, TcpState};

use crate::MAX_ALERTS_PER_RULE;
use crate::config::DetectionConfig;
use crate::model::{
    Alert, AlertStatus, BEACONING, CLEARTEXT, Confidence, Evidence, HORIZONTAL_SCAN, MAX_RELATED,
    NATURE, OUTBOUND_RATIO, PORT_SWEEP, RARE_PORT, Rule, SYN_SCAN, TCP_FAILURES, push_related,
};
use crate::networks::Networks;
use crate::window::{Cite, Window};

const TCP: u8 = 6;
const UDP: u8 = 17;

/// Service ports common enough that using one once is never "rare".
const COMMON_PORTS: [u16; 24] = [
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 161, 389, 443, 445, 465, 587, 636, 993, 995,
    3389, 5353, 8080,
];
/// Ports in the dynamic range (RFC 6335) are client ports, not services.
const DYNAMIC_PORTS_START: u16 = 49_152;

/// Builds an alert skeleton for `rule`.
pub(crate) fn alert(rule: &Rule, confidence: Confidence) -> Alert {
    Alert {
        alert_id: 0,
        rule_id: rule.id,
        rule_name: rule.name,
        severity: rule.severity,
        confidence,
        status: AlertStatus::Open,
        nature: NATURE,
        first_seen: None,
        last_seen: None,
        source: None,
        destination: None,
        destination_port: None,
        related_flow_ids: Vec::new(),
        related_packet_indexes: Vec::new(),
        evidence: Vec::new(),
        explanation: String::new(),
        uncertainty: rule.uncertainty,
        likely_false_positives: rule.likely_false_positives,
        mitre_attack: rule.mitre_attack,
    }
}

pub(crate) fn evidence(name: &'static str, value: impl ToString) -> Evidence {
    Evidence {
        name,
        value: value.to_string(),
    }
}

fn start_ns(flow: &FlowRecord) -> Option<u128> {
    flow.first_seen.map(|t| t.as_unix_nanos())
}

fn widen(alert: &mut Alert, first: Option<Timestamp>, last: Option<Timestamp>) {
    if let Some(first) = first {
        alert.first_seen = Some(alert.first_seen.map_or(first, |t| t.min(first)));
    }
    if let Some(last) = last {
        alert.last_seen = Some(alert.last_seen.map_or(last, |t| t.max(last)));
    }
}

/// A TCP connection attempt that never got going: unanswered, or refused
/// before any data moved.
fn failed_attempt(flow: &FlowRecord) -> bool {
    let Some(tcp) = &flow.tcp else {
        return false;
    };
    flow.protocol == TCP
        && flow.initiator_basis == InitiatorBasis::TcpSyn
        && match tcp.state {
            TcpState::SynSent => true,
            TcpState::Reset => {
                flow.initiator_to_responder.payload_bytes == 0
                    && flow.responder_to_initiator.payload_bytes == 0
            }
            _ => false,
        }
}

fn has_ports(flow: &FlowRecord) -> bool {
    matches!(flow.protocol, TCP | UDP) && flow.responder.port != 0
}

/// The responder answered.
fn answered(flow: &FlowRecord) -> bool {
    flow.responder_to_initiator.packets > 0 && !failed_attempt(flow)
}

/// The latest flows of one key, so an alert can cite the flows that led
/// up to it.
type Recent<'f> = VecDeque<&'f FlowRecord>;

/// One windowed "distinct values per key" rule's running state.
struct Distinct<'f, K, V> {
    windows: HashMap<K, (Window<V>, Recent<'f>)>,
    alerts: BTreeMap<K, (Alert, usize)>,
    width: Duration,
    threshold: usize,
}

impl<'f, K: Ord + Clone + std::hash::Hash, V: Eq + std::hash::Hash + Clone> Distinct<'f, K, V> {
    fn new(window_seconds: u64, threshold: u32) -> Self {
        Self {
            windows: HashMap::new(),
            alerts: BTreeMap::new(),
            width: Duration::from_secs(window_seconds),
            threshold: usize::try_from(threshold).unwrap_or(usize::MAX),
        }
    }

    /// Adds `value` for `key` at the flow's start; raises or extends the
    /// key's alert when the distinct count reaches the threshold.
    fn add(&mut self, key: &K, value: V, flow: &'f FlowRecord, rule: &Rule) {
        let Some(at) = start_ns(flow) else {
            return;
        };
        let width = self.width;
        let (window, recent) = self
            .windows
            .entry(key.clone())
            .or_insert_with(|| (Window::new(width), VecDeque::new()));
        let Ok((_, distinct)) = window.add(at, value, Cite::flow(flow.flow_id), None) else {
            return;
        };
        if recent.len() == MAX_RELATED {
            recent.pop_front();
        }
        recent.push_back(flow);
        let cutoff = at.saturating_sub(width.as_nanos());
        match self.alerts.get_mut(key) {
            Some((alert, peak)) => {
                *peak = (*peak).max(distinct);
                push_related(&mut alert.related_flow_ids, flow.flow_id);
                widen(alert, flow.first_seen, flow.last_seen);
            }
            None if distinct >= self.threshold => {
                let mut alert = alert(rule, Confidence::Medium);
                // Cite the flows in the window that reached the threshold.
                for earlier in recent
                    .iter()
                    .filter(|f| start_ns(f).is_some_and(|t| t >= cutoff))
                {
                    push_related(&mut alert.related_flow_ids, earlier.flow_id);
                    widen(&mut alert, earlier.first_seen, earlier.last_seen);
                }
                self.alerts.insert(key.clone(), (alert, distinct));
            }
            None => {}
        }
    }

    fn finish(self) -> impl Iterator<Item = (K, Alert, usize)> {
        let threshold = self.threshold;
        self.alerts
            .into_iter()
            .map(move |(key, (mut alert, peak))| {
                alert.confidence = Confidence::from_ratio(peak as u64, threshold as u64);
                (key, alert, peak)
            })
    }
}

/// Evaluates every flow rule. `flows` must be sorted by start time.
pub(crate) fn evaluate(
    flows: &[&FlowRecord],
    config: &DetectionConfig,
    internal: &Networks,
    at_limit: &mut BTreeSet<&'static str>,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let window_text = |seconds: u64| format!("{seconds} s");

    // Scans and failures, all windowed over flow start times.
    let mut syn = Distinct::<(IpAddr, IpAddr), u16>::new(
        config.syn_scan.window_seconds,
        config.syn_scan.min_ports,
    );
    let mut ports = Distinct::<(IpAddr, IpAddr), (u8, u16)>::new(
        config.port_sweep.window_seconds,
        config.port_sweep.min_ports,
    );
    let mut hosts = Distinct::<(IpAddr, u8, u16), IpAddr>::new(
        config.horizontal_scan.window_seconds,
        config.horizontal_scan.min_hosts,
    );
    let mut failures = Distinct::<IpAddr, u64>::new(
        config.tcp_failures.window_seconds,
        config.tcp_failures.min_failures,
    );
    for flow in flows {
        let (src, dst, port) = (flow.initiator.ip, flow.responder.ip, flow.responder.port);
        if config.syn_scan.enabled && failed_attempt(flow) {
            syn.add(&(src, dst), port, flow, &SYN_SCAN);
        }
        if config.port_sweep.enabled && has_ports(flow) {
            ports.add(&(src, dst), (flow.protocol, port), flow, &PORT_SWEEP);
        }
        // Only unanswered or refused attempts: answered connections to one
        // port on many hosts are ordinary browsing.
        if config.horizontal_scan.enabled && has_ports(flow) && !answered(flow) {
            hosts.add(&(src, flow.protocol, port), dst, flow, &HORIZONTAL_SCAN);
        }
        if config.tcp_failures.enabled && failed_attempt(flow) {
            failures.add(&src, flow.flow_id, flow, &TCP_FAILURES);
        }
    }
    for ((src, dst), mut alert, peak) in syn.finish() {
        alert.source = Some(src);
        alert.destination = Some(dst);
        alert.evidence = vec![
            evidence("distinct_ports_unanswered_or_refused", peak),
            evidence("threshold", config.syn_scan.min_ports),
            evidence("window", window_text(config.syn_scan.window_seconds)),
        ];
        alert.explanation = format!(
            "{src} sent TCP connection attempts to {peak} distinct ports on {dst} within {} s, \
             and they were refused or never answered. This is consistent with a SYN port scan, \
             but it is a heuristic indicator that needs review.",
            config.syn_scan.window_seconds
        );
        alerts.push(alert);
    }
    for ((src, dst), mut alert, peak) in ports.finish() {
        alert.source = Some(src);
        alert.destination = Some(dst);
        alert.evidence = vec![
            evidence("distinct_destination_ports", peak),
            evidence("threshold", config.port_sweep.min_ports),
            evidence("window", window_text(config.port_sweep.window_seconds)),
        ];
        alert.explanation = format!(
            "{src} contacted {peak} distinct TCP/UDP ports on {dst} within {} s. Many ports on \
             one host can indicate service discovery or a port scan; review whether this host \
             is expected to do so.",
            config.port_sweep.window_seconds
        );
        alerts.push(alert);
    }
    for ((src, protocol, port), mut alert, peak) in hosts.finish() {
        alert.source = Some(src);
        alert.destination_port = Some(port);
        let name = if protocol == TCP { "TCP" } else { "UDP" };
        alert.evidence = vec![
            evidence("distinct_hosts_unanswered_or_refused", peak),
            evidence("protocol", name),
            evidence("threshold", config.horizontal_scan.min_hosts),
            evidence("window", window_text(config.horizontal_scan.window_seconds)),
        ];
        alert.explanation = format!(
            "{src} tried {name} port {port} on {peak} distinct hosts within {} s, and the \
             attempts were refused or never answered. This is consistent with a horizontal scan \
             for one service, and also with discovery or monitoring software, or a client whose \
             servers are unreachable.",
            config.horizontal_scan.window_seconds
        );
        alerts.push(alert);
    }
    for (src, mut alert, peak) in failures.finish() {
        alert.source = Some(src);
        alert.evidence = vec![
            evidence("failed_connection_attempts", peak),
            evidence("threshold", config.tcp_failures.min_failures),
            evidence("window", window_text(config.tcp_failures.window_seconds)),
        ];
        alert.explanation = format!(
            "{src} made {peak} TCP connection attempts within {} s that were refused or never \
             answered. Scanning produces this pattern, but so do clients retrying an \
             unreachable service.",
            config.tcp_failures.window_seconds
        );
        alerts.push(alert);
    }

    if config.beaconing.enabled {
        alerts.extend(beaconing(flows, config));
    }
    if config.rare_destination_port.enabled {
        alerts.extend(rare_ports(flows, config, at_limit));
    }
    if config.outbound_ratio.enabled {
        alerts.extend(outbound(flows, config, internal, at_limit));
    }
    if config.cleartext.enabled {
        alerts.extend(cleartext(flows, config, at_limit));
    }
    alerts
}

/// Mean and population standard deviation.
fn mean_stddev(values: &[f64]) -> Option<(f64, f64)> {
    if values.is_empty() {
        return None;
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    Some((mean, variance.max(0.0).sqrt()))
}

fn beaconing(flows: &[&FlowRecord], config: &DetectionConfig) -> Vec<Alert> {
    let c = &config.beaconing;
    let mut groups: BTreeMap<(IpAddr, IpAddr, u8, u16), Vec<&FlowRecord>> = BTreeMap::new();
    for flow in flows
        .iter()
        .filter(|f| has_ports(f) && f.first_seen.is_some())
    {
        let key = (
            flow.initiator.ip,
            flow.responder.ip,
            flow.protocol,
            flow.responder.port,
        );
        groups.entry(key).or_default().push(flow);
    }
    let min = usize::try_from(c.min_connections.max(3)).unwrap_or(usize::MAX);
    let mut alerts = Vec::new();
    for ((src, dst, _, port), group) in groups {
        if group.len() < min {
            continue;
        }
        let starts: Vec<f64> = group
            .iter()
            .filter_map(|f| start_ns(f))
            .map(|ns| ns as f64 / 1e9)
            .collect();
        let intervals: Vec<f64> = starts.windows(2).map(|w| (w[1] - w[0]).max(0.0)).collect();
        let Some((mean, stddev)) = mean_stddev(&intervals) else {
            continue;
        };
        if mean < c.min_interval_seconds || !mean.is_finite() || mean <= 0.0 {
            continue;
        }
        let jitter = stddev / mean;
        if jitter > c.max_jitter_ratio {
            continue;
        }
        let confidence =
            if group.len() >= min.saturating_mul(2) && jitter <= c.max_jitter_ratio / 2.0 {
                Confidence::High
            } else {
                Confidence::Medium
            };
        let mut alert = alert(&BEACONING, confidence);
        alert.source = Some(src);
        alert.destination = Some(dst);
        alert.destination_port = Some(port);
        for flow in &group {
            push_related(&mut alert.related_flow_ids, flow.flow_id);
            widen(&mut alert, flow.first_seen, flow.last_seen);
        }
        alert.evidence = vec![
            evidence("connections", group.len()),
            evidence("mean_interval_seconds", format!("{mean:.3}")),
            evidence("interval_stddev_seconds", format!("{stddev:.3}")),
            evidence("jitter_ratio", format!("{jitter:.3}")),
            evidence("max_jitter_ratio", c.max_jitter_ratio),
        ];
        alert.explanation = format!(
            "{src} connected to {dst} port {port} {} times at intervals of {mean:.1} s with \
             little variation (jitter {jitter:.3}). Regular check-ins are typical of update and \
             monitoring software and can also be command-and-control beaconing; review what \
             the destination is.",
            group.len()
        );
        alerts.push(alert);
    }
    alerts
}

/// The earliest start time of a group of flows (`None` sorts last).
fn group_start(flows: &[&FlowRecord]) -> (bool, Option<u128>) {
    let start = flows.iter().filter_map(|f| start_ns(f)).min();
    (start.is_none(), start)
}

/// Keeps the [`MAX_ALERTS_PER_RULE`] groups that start earliest, so a rule
/// never builds more alerts than can be reported, and records the rule when
/// groups are left out.
fn earliest_groups<'f, K: Ord>(
    groups: BTreeMap<K, Vec<&'f FlowRecord>>,
    rule: &'static str,
    at_limit: &mut BTreeSet<&'static str>,
) -> Vec<(K, Vec<&'f FlowRecord>)> {
    let mut groups: Vec<(K, Vec<&FlowRecord>)> = groups.into_iter().collect();
    if groups.len() > MAX_ALERTS_PER_RULE {
        // Stable: equal start times keep key order.
        groups.sort_by_key(|(_, flows)| group_start(flows));
        groups.truncate(MAX_ALERTS_PER_RULE);
        at_limit.insert(rule);
    }
    groups
}

/// Whether a UDP flow's initiator looks like a client: its port is not a
/// well-known or common service port. Without a handshake, a capture that
/// starts with a server's reply would otherwise make the client's port look
/// like the service.
fn client_like_udp(flow: &FlowRecord) -> bool {
    flow.initiator.port >= 1024 && !COMMON_PORTS.contains(&flow.initiator.port)
}

fn rare_ports(
    flows: &[&FlowRecord],
    config: &DetectionConfig,
    at_limit: &mut BTreeSet<&'static str>,
) -> Vec<Alert> {
    let c = &config.rare_destination_port;
    let candidates: Vec<&FlowRecord> = flows.iter().copied().filter(|f| has_ports(f)).collect();
    if candidates.len() < usize::try_from(c.min_flows).unwrap_or(usize::MAX) {
        return Vec::new();
    }
    let mut usage: BTreeMap<(u8, u16), Vec<&FlowRecord>> = BTreeMap::new();
    for flow in &candidates {
        usage
            .entry((flow.protocol, flow.responder.port))
            .or_default()
            .push(flow);
    }
    let max = usize::try_from(c.max_occurrences).unwrap_or(usize::MAX);
    usage.retain(|&(_, port), users| {
        users.len() <= max
            && !COMMON_PORTS.contains(&port)
            && port < DYNAMIC_PORTS_START
            // The direction must be known for the port to be a service:
            // from the TCP handshake, or a client-like UDP source port.
            && users.iter().all(|f| {
                if f.protocol == UDP {
                    client_like_udp(f)
                } else {
                    f.initiator_basis != InitiatorBasis::FirstPacket
                }
            })
            && users.iter().any(|f| answered(f))
    });
    let mut alerts = Vec::new();
    for ((protocol, port), users) in earliest_groups(usage, RARE_PORT.id, at_limit) {
        let mut alert = alert(&RARE_PORT, Confidence::Low);
        let first = users.first().copied();
        alert.source = first.map(|f| f.initiator.ip);
        alert.destination = first.map(|f| f.responder.ip);
        alert.destination_port = Some(port);
        for flow in &users {
            push_related(&mut alert.related_flow_ids, flow.flow_id);
            widen(&mut alert, flow.first_seen, flow.last_seen);
        }
        let name = if protocol == TCP { "TCP" } else { "UDP" };
        alert.evidence = vec![
            evidence("flows_to_port", users.len()),
            evidence("protocol", name),
            evidence("flows_in_capture", candidates.len()),
        ];
        alert.explanation = format!(
            "{name} port {port} was used by {} of {} flows in this capture and was answered. A \
             rarely used port can be a service on a non-standard port; rarity is judged within \
             this capture only.",
            users.len(),
            candidates.len()
        );
        alerts.push(alert);
    }
    alerts
}

fn outbound(
    flows: &[&FlowRecord],
    config: &DetectionConfig,
    internal: &Networks,
    at_limit: &mut BTreeSet<&'static str>,
) -> Vec<Alert> {
    let c = &config.outbound_ratio;
    let ratio_of = |flow: &FlowRecord| {
        let out = flow.initiator_to_responder.bytes;
        let back = flow.responder_to_initiator.bytes;
        if back == 0 {
            f64::INFINITY
        } else {
            out as f64 / back as f64
        }
    };
    let mut pairs: BTreeMap<(IpAddr, IpAddr), Vec<&FlowRecord>> = BTreeMap::new();
    for flow in flows {
        let (src, dst) = (flow.initiator.ip, flow.responder.ip);
        if !internal.contains(src) || internal.contains(dst) {
            continue;
        }
        if flow.initiator_to_responder.bytes < c.min_bytes_out || ratio_of(flow) < c.min_ratio {
            continue;
        }
        pairs.entry((src, dst)).or_default().push(flow);
    }
    let mut alerts = Vec::new();
    for ((src, dst), group) in earliest_groups(pairs, OUTBOUND_RATIO.id, at_limit) {
        let mut alert = alert(&OUTBOUND_RATIO, Confidence::Medium);
        alert.source = Some(src);
        alert.destination = Some(dst);
        let (mut out, mut back, mut lowest) = (0u64, 0u64, f64::INFINITY);
        for flow in &group {
            push_related(&mut alert.related_flow_ids, flow.flow_id);
            widen(&mut alert, flow.first_seen, flow.last_seen);
            out = out.saturating_add(flow.initiator_to_responder.bytes);
            back = back.saturating_add(flow.responder_to_initiator.bytes);
            lowest = lowest.min(ratio_of(flow));
        }
        if out >= c.min_bytes_out.saturating_mul(10) {
            alert.confidence = Confidence::High;
        }
        let ratio_text = if lowest.is_finite() {
            format!("{lowest:.1}")
        } else {
            "no reply bytes".to_owned()
        };
        alert.evidence = vec![
            evidence("bytes_sent", out),
            evidence("bytes_received", back),
            evidence("flows", group.len()),
            evidence("lowest_flow_ratio", ratio_text),
            evidence("min_bytes_out", c.min_bytes_out),
            evidence("min_ratio", c.min_ratio),
        ];
        alert.explanation = format!(
            "Internal host {src} sent {out} bytes to external host {dst} and received {back} \
             in {} flow(s). Large one-sided transfers include backups and uploads as well as \
             data exfiltration; confirm the destination is expected.",
            group.len()
        );
        alerts.push(alert);
    }
    alerts
}

fn cleartext(
    flows: &[&FlowRecord],
    config: &DetectionConfig,
    at_limit: &mut BTreeSet<&'static str>,
) -> Vec<Alert> {
    let mut by_service: BTreeMap<(IpAddr, IpAddr, u16), Vec<&FlowRecord>> = BTreeMap::new();
    for flow in flows {
        let port = flow.responder.port;
        if flow.protocol != TCP || !config.cleartext.ports.contains(&port) || !answered(flow) {
            continue;
        }
        by_service
            .entry((flow.initiator.ip, flow.responder.ip, port))
            .or_default()
            .push(flow);
    }
    let mut alerts = Vec::new();
    for ((src, dst, port), group) in earliest_groups(by_service, CLEARTEXT.id, at_limit) {
        let mut alert = alert(&CLEARTEXT, Confidence::Medium);
        alert.source = Some(src);
        alert.destination = Some(dst);
        alert.destination_port = Some(port);
        for flow in &group {
            push_related(&mut alert.related_flow_ids, flow.flow_id);
            widen(&mut alert, flow.first_seen, flow.last_seen);
        }
        let service = match port {
            21 => "FTP",
            23 => "Telnet",
            110 => "POP3",
            143 => "IMAP",
            513 => "rlogin",
            514 => "rsh",
            _ => "a configured cleartext protocol",
        };
        alert.evidence = vec![
            evidence("service", service),
            evidence("destination_port", port),
            evidence("connections", group.len()),
        ];
        alert.explanation = format!(
            "{src} connected to {service} on {dst} port {port} and the server answered. \
             This protocol sends credentials without encryption unless upgraded; the \
             decision is based on the port only."
        );
        alerts.push(alert);
    }
    alerts
}
