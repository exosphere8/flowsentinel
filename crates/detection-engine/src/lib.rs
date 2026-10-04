//! Explainable, rule-based detection over packet and flow metadata.
//!
//! Every alert is a **heuristic indicator**: an observed pattern worth a
//! human's review, never proof of compromise. Each one carries the rule,
//! severity, confidence, time range, endpoints, related flow and packet
//! references, measured evidence, a plain-language explanation, what makes
//! it uncertain, and likely benign causes. MITRE ATT&CK techniques appear as
//! contextual tags only.
//!
//! Thresholds come from [`DetectionConfig`] (TOML). State is bounded: sliding
//! windows keep at most a fixed number of events per key, keys per rule and
//! events per rule, and each rule raises at most [`MAX_ALERTS_PER_RULE`]
//! alerts. Results are deterministic for the same input.

mod config;
mod flows;
mod model;
mod networks;
mod packets;
mod window;

use std::collections::{BTreeMap, BTreeSet};

use capture::Timestamp;
use decoder::DecodedPacket;
use flow_engine::FlowRecord;
use serde::Serialize;

pub use config::{ConfigError, DetectionConfig, MAX_CONFIG_BYTES, in_network, parse_cidr};
pub use model::{
    Alert, AlertStatus, Confidence, Evidence, MAX_RELATED, NATURE, RULES, Rule, Severity,
};
pub use packets::MAX_KEYS_PER_RULE;
pub use window::{MAX_EVENTS_PER_RULE, MAX_EVENTS_PER_WINDOW};

use networks::Networks;
use packets::PacketRules;

/// Alert IDs recorded per flow record.
pub const MAX_ALERTS_PER_FLOW: usize = 16;
/// Alerts kept per rule; the earliest are kept.
pub const MAX_ALERTS_PER_RULE: usize = 1_000;

/// Totals over one detection run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DetectionSummary {
    pub alerts_total: u64,
    pub alerts_by_rule: BTreeMap<&'static str, u64>,
    pub alerts_by_severity: BTreeMap<&'static str, u64>,
    /// Flows the flow rules looked at (the retained flows).
    pub flows_evaluated: u64,
    /// Flows without a valid start time, skipped by windowed rules.
    pub flows_without_time: u64,
    /// DNS and ARP packets without a valid timestamp, skipped.
    pub packets_without_time: u64,
    /// DNS and ARP events not evaluated because a rule's key or event limit
    /// was reached.
    pub events_not_evaluated: u64,
    /// Clients, domains or addresses whose DNS/ARP history was discarded to
    /// make room for new ones when a rule's key table was full.
    pub keys_evicted: u64,
    /// Rules that reached [`MAX_ALERTS_PER_RULE`]; further alerts of these
    /// rules were not raised.
    pub rules_at_alert_limit: BTreeSet<&'static str>,
}

/// Alerts and totals.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DetectionReport {
    pub summary: DetectionSummary,
    pub alerts: Vec<Alert>,
}

/// Runs the rules over one capture. Feed every packet with
/// [`observe_packet`](Self::observe_packet) in capture order, then call
/// [`finish`](Self::finish) with the finished flows.
pub struct Detector {
    config: DetectionConfig,
    internal: Networks,
    packets: PacketRules,
}

impl Detector {
    /// Creates a detector; the configuration is validated first.
    pub fn new(config: DetectionConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        let internal = Networks::parse(&config.internal_networks);
        let packets = PacketRules::new(&config);
        Ok(Self {
            config,
            internal,
            packets,
        })
    }

    /// Feeds one decoded packet (DNS and ARP rules).
    /// `flow` is the flow the packet was assigned to, if any; DNS alerts
    /// cite it, so flows can be found by their alerts.
    pub fn observe_packet(
        &mut self,
        index: u64,
        timestamp: Option<Timestamp>,
        packet: &DecodedPacket,
        flow: Option<u64>,
    ) {
        self.packets
            .observe(&self.config, index, timestamp, packet, flow);
    }

    /// Evaluates the flow rules, numbers every alert from 1, and records
    /// alert IDs on the related flows (at most [`MAX_ALERTS_PER_FLOW`] each).
    pub fn finish(self, flows: &mut [FlowRecord]) -> DetectionReport {
        let mut summary = DetectionSummary {
            packets_without_time: self.packets.packets_without_time,
            events_not_evaluated: self.packets.events_not_evaluated(),
            keys_evicted: self.packets.keys_evicted(),
            rules_at_alert_limit: self.packets.at_limit.clone(),
            flows_evaluated: u64::try_from(flows.len()).unwrap_or(u64::MAX),
            ..DetectionSummary::default()
        };
        let mut ordered: Vec<&FlowRecord> = flows.iter().collect();
        summary.flows_without_time =
            u64::try_from(ordered.iter().filter(|f| f.first_seen.is_none()).count())
                .unwrap_or(u64::MAX);
        ordered.sort_by(|a, b| {
            a.first_seen
                .cmp(&b.first_seen)
                .then(a.flow_id.cmp(&b.flow_id))
        });
        let mut alerts = flows::evaluate(
            &ordered,
            &self.config,
            &self.internal,
            &mut summary.rules_at_alert_limit,
        );
        alerts.extend(self.packets.finish(&self.config));
        // Number in catalog order, then by time (alerts without one last);
        // the sort is stable, so ties keep key order.
        alerts.sort_by_key(|a| {
            let rule = RULES
                .iter()
                .position(|r| r.id == a.rule_id)
                .unwrap_or(usize::MAX);
            (rule, a.first_seen.is_none(), a.first_seen)
        });
        let mut per_rule: BTreeMap<&'static str, usize> = BTreeMap::new();
        alerts.retain(|a| {
            let count = per_rule.entry(a.rule_id).or_default();
            *count += 1;
            if *count > MAX_ALERTS_PER_RULE {
                summary.rules_at_alert_limit.insert(a.rule_id);
                return false;
            }
            true
        });
        let mut by_flow: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for (i, alert) in alerts.iter_mut().enumerate() {
            alert.alert_id = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
            *summary.alerts_by_rule.entry(alert.rule_id).or_default() += 1;
            *summary
                .alerts_by_severity
                .entry(alert.severity.as_str())
                .or_default() += 1;
            for &flow_id in &alert.related_flow_ids {
                by_flow.entry(flow_id).or_default().push(alert.alert_id);
            }
        }
        summary.alerts_total = u64::try_from(alerts.len()).unwrap_or(u64::MAX);
        for flow in flows.iter_mut() {
            if let Some(ids) = by_flow.get(&flow.flow_id) {
                flow.alert_ids = ids.iter().copied().take(MAX_ALERTS_PER_FLOW).collect();
            }
        }
        DetectionReport { summary, alerts }
    }
}
