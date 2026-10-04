//! Rules evaluated packet by packet: DNS and ARP.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use std::hash::Hash;

use capture::{Timestamp, TimestampResolution};
use decoder::{DecodedPacket, Layer, MacAddr};

use crate::MAX_ALERTS_PER_RULE;
use crate::config::DetectionConfig;
use crate::flows::{alert, evidence};
use crate::model::{
    ARP_CONFLICT, ARP_FLOOD, Alert, Confidence, DNS_TUNNELING, DNS_VOLUME, MAX_RELATED,
    push_related,
};
use crate::window::{Cite, Windows};

/// Keys tracked per rule (clients, domains, addresses). Events for further
/// keys are not evaluated and are counted in the summary.
pub const MAX_KEYS_PER_RULE: usize = 16_384;
/// DNS record types used to carry arbitrary data: NULL and TXT.
const DATA_TYPES: [u16; 2] = [10, 16];

/// Shannon entropy in bits per character.
pub(crate) fn entropy(text: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for byte in text.bytes() {
        if let Some(count) = counts.get_mut(usize::from(byte)) {
            *count = count.saturating_add(1);
            total = total.saturating_add(1);
        }
    }
    if total == 0 {
        return 0.0;
    }
    let total = f64::from(total);
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / total;
            -p * p.log2()
        })
        .sum()
}

/// `(parent domain, subdomain part)`: the parent is the last two labels.
pub(crate) fn split_name(name: &str) -> Option<(String, String)> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = name.split('.').collect();
    let cut = labels.len().checked_sub(2).filter(|&cut| cut > 0)?;
    Some((labels.get(cut..)?.join("."), labels.get(..cut)?.join(".")))
}

/// A fixed 64-bit digest of a subdomain, so windows count distinct names
/// without holding them. The hasher has fixed keys, so results are
/// deterministic.
fn digest(text: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(text.as_bytes());
    hasher.finish()
}

/// Whether another alert of `rule` may be started; records the rule as
/// limited when not.
fn room<V>(
    pending: &BTreeMap<String, V>,
    rule: &'static str,
    at_limit: &mut BTreeSet<&'static str>,
) -> bool {
    if pending.len() < MAX_ALERTS_PER_RULE {
        true
    } else {
        at_limit.insert(rule);
        false
    }
}

/// Per-key alert under construction.
struct Pending {
    alert: Alert,
    peak: usize,
}

/// Rebuilds a timestamp from nanoseconds, in the capture's resolution.
fn timestamp_from_nanos(nanos: u128, like: Timestamp) -> Option<Timestamp> {
    let seconds = u32::try_from(nanos / 1_000_000_000).ok()?;
    let fraction = u32::try_from(nanos % 1_000_000_000).ok()?;
    match like.resolution() {
        TimestampResolution::Microsecond if fraction % 1000 == 0 => {
            Timestamp::from_record(seconds, fraction / 1000, TimestampResolution::Microsecond)
        }
        _ => Timestamp::from_record(seconds, fraction, TimestampResolution::Nanosecond),
    }
}

/// Cites one packet, and its flow when it has one.
fn cite_on(alert: &mut Alert, cite: Cite) {
    push_related(&mut alert.related_packet_indexes, cite.reference);
    if cite.flow != 0 {
        push_related(&mut alert.related_flow_ids, cite.flow);
    }
}

/// Starts an alert from the packets that are in the window when the
/// threshold is reached, so it cites the whole pattern, not just its end.
fn start<K: Eq + Hash + Clone, T: Eq + Hash + Clone>(
    mut alert: Alert,
    windows: &Windows<K, T>,
    key: &K,
    at: Timestamp,
) -> Alert {
    let earliest = windows.earliest(key, MAX_RELATED);
    for &(_, cite) in &earliest {
        cite_on(&mut alert, cite);
    }
    // Packets may arrive out of time order, so take the extremes.
    let now = at.as_unix_nanos();
    let times = earliest.iter().map(|&(nanos, _)| nanos);
    let first = times.clone().chain([now]).min().unwrap_or(now);
    let last = times.chain([now]).max().unwrap_or(now);
    alert.first_seen = timestamp_from_nanos(first, at).or(Some(at));
    alert.last_seen = timestamp_from_nanos(last, at).or(Some(at));
    alert
}

#[allow(clippy::too_many_arguments)]
fn record<K: Eq + Hash + Clone, T: Eq + Hash + Clone>(
    pending: &mut BTreeMap<String, Pending>,
    at_limit: &mut BTreeSet<&'static str>,
    rule: &'static str,
    alert_key: String,
    reached: Option<(usize, usize)>,
    threshold: usize,
    windows: &Windows<K, T>,
    key: &K,
    make: impl FnOnce() -> Alert,
    cite: Cite,
    at: Timestamp,
) {
    let Some((value, _)) = reached else {
        return;
    };
    if let Some(p) = pending.get_mut(&alert_key) {
        p.peak = p.peak.max(value);
        cite_on(&mut p.alert, cite);
        p.alert.last_seen = Some(p.alert.last_seen.map_or(at, |t| t.max(at)));
    } else if value >= threshold && room(pending, rule, at_limit) {
        let alert = start(make(), windows, key, at);
        pending.insert(alert_key, Pending { alert, peak: value });
    }
}

/// State of the packet rules.
pub(crate) struct PacketRules {
    dns_volume: Windows<IpAddr, ()>,
    dns_suspicious: Windows<(IpAddr, String), ()>,
    dns_subdomains: Windows<(IpAddr, String), u64>,
    arp_owners: Windows<Ipv4Addr, MacAddr>,
    arp_gratuitous: Windows<MacAddr, ()>,
    volume_alerts: BTreeMap<String, Pending>,
    tunnel_alerts: BTreeMap<String, (Pending, usize)>,
    /// With the conflicting MAC addresses, at most [`MAX_RELATED`].
    conflict_alerts: BTreeMap<String, (Pending, BTreeSet<MacAddr>)>,
    flood_alerts: BTreeMap<String, Pending>,
    pub packets_without_time: u64,
    /// Rules that reached [`MAX_ALERTS_PER_RULE`].
    pub at_limit: BTreeSet<&'static str>,
}

fn window(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}

impl PacketRules {
    pub(crate) fn new(config: &DetectionConfig) -> Self {
        let keys = MAX_KEYS_PER_RULE;
        Self {
            dns_volume: Windows::new(window(config.dns_volume.window_seconds), keys),
            dns_suspicious: Windows::new(window(config.dns_tunneling.window_seconds), keys),
            dns_subdomains: Windows::new(window(config.dns_tunneling.window_seconds), keys),
            arp_owners: Windows::new(window(config.arp.window_seconds), keys),
            arp_gratuitous: Windows::new(window(config.arp.window_seconds), keys),
            volume_alerts: BTreeMap::new(),
            tunnel_alerts: BTreeMap::new(),
            conflict_alerts: BTreeMap::new(),
            flood_alerts: BTreeMap::new(),
            packets_without_time: 0,
            at_limit: BTreeSet::new(),
        }
    }

    /// Keys evicted from full key tables.
    pub(crate) fn keys_evicted(&self) -> u64 {
        self.dns_volume.evicted
            + self.dns_suspicious.evicted
            + self.dns_subdomains.evicted
            + self.arp_owners.evicted
            + self.arp_gratuitous.evicted
    }

    /// Events not evaluated because a rule's key or event limit was reached.
    pub(crate) fn events_not_evaluated(&self) -> u64 {
        self.dns_volume.dropped
            + self.dns_suspicious.dropped
            + self.dns_subdomains.dropped
            + self.arp_owners.dropped
            + self.arp_gratuitous.dropped
    }

    pub(crate) fn observe(
        &mut self,
        config: &DetectionConfig,
        index: u64,
        timestamp: Option<Timestamp>,
        packet: &DecodedPacket,
        flow: Option<u64>,
    ) {
        let relevant = packet
            .layers
            .iter()
            .any(|l| matches!(l, Layer::Dns(_) | Layer::Arp(_)));
        if !relevant {
            return;
        }
        let Some(at) = timestamp else {
            self.packets_without_time = self.packets_without_time.saturating_add(1);
            return;
        };
        let ns = at.as_unix_nanos();
        let cite = Cite::packet(index, flow);
        let source = packet.layers.iter().find_map(|l| match l {
            Layer::Ipv4(h) => Some(IpAddr::V4(h.source)),
            Layer::Ipv6(h) => Some(IpAddr::V6(h.source)),
            _ => None,
        });
        for layer in &packet.layers {
            match layer {
                Layer::Dns(m) if !m.is_response => {
                    if let Some(client) = source {
                        self.dns_query(config, cite, at, ns, client, m);
                    }
                }
                Layer::Arp(a) => self.arp(config, cite, at, ns, a),
                _ => {}
            }
        }
    }

    fn dns_query(
        &mut self,
        config: &DetectionConfig,
        cite: Cite,
        at: Timestamp,
        ns: u128,
        client: IpAddr,
        message: &decoder::app::dns::DnsMessage,
    ) {
        if config.dns_volume.enabled {
            let reached = self.dns_volume.add(client, ns, (), cite);
            let threshold = usize::try_from(config.dns_volume.min_queries).unwrap_or(usize::MAX);
            record(
                &mut self.volume_alerts,
                &mut self.at_limit,
                DNS_VOLUME.id,
                client.to_string(),
                reached,
                threshold,
                &self.dns_volume,
                &client,
                || {
                    let mut a = alert(&DNS_VOLUME, Confidence::Medium);
                    a.source = Some(client);
                    a
                },
                cite,
                at,
            );
        }
        if !config.dns_tunneling.enabled {
            return;
        }
        let c = &config.dns_tunneling;
        for question in &message.questions {
            let Some((parent, sub)) = split_name(&question.name) else {
                continue;
            };
            let longest = sub.split('.').map(str::len).max().unwrap_or(0);
            let high_entropy = sub
                .split('.')
                .any(|l| l.len() >= 16 && entropy(l) >= c.min_entropy_bits);
            let suspicious = longest >= c.min_label_length as usize
                || question.name.len() >= c.min_name_length as usize
                || high_entropy
                || DATA_TYPES.contains(&question.record_type);
            let key = (client, parent.clone());
            let (_, subdomains) = self
                .dns_subdomains
                .add(key.clone(), ns, digest(&sub), cite)
                .unwrap_or((0, 0));
            let suspicious_count = if suspicious {
                self.dns_suspicious
                    .add(key.clone(), ns, (), cite)
                    .map_or(0, |(n, _)| n)
            } else {
                0
            };
            let alert_key = format!("{client} {parent}");
            if let Some((pending, peak_subdomains)) = self.tunnel_alerts.get_mut(&alert_key) {
                pending.peak = pending.peak.max(suspicious_count);
                *peak_subdomains = (*peak_subdomains).max(subdomains);
                cite_on(&mut pending.alert, cite);
                pending.alert.last_seen = Some(pending.alert.last_seen.map_or(at, |t| t.max(at)));
                continue;
            }
            let by_count = suspicious_count >= c.min_long_queries as usize;
            let by_spread = subdomains >= c.min_unique_subdomains as usize && suspicious_count > 0;
            if (by_count || by_spread)
                && room(&self.tunnel_alerts, DNS_TUNNELING.id, &mut self.at_limit)
            {
                let mut a = alert(
                    &DNS_TUNNELING,
                    if by_count && by_spread {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    },
                );
                a.source = Some(client);
                let mut a = start(a, &self.dns_suspicious, &key, at);
                cite_on(&mut a, cite);
                a.evidence.push(evidence("parent_domain", &parent));
                self.tunnel_alerts.insert(
                    alert_key,
                    (
                        Pending {
                            alert: a,
                            peak: suspicious_count,
                        },
                        subdomains,
                    ),
                );
            }
        }
    }

    fn arp(
        &mut self,
        config: &DetectionConfig,
        cite: Cite,
        at: Timestamp,
        ns: u128,
        arp: &decoder::ArpPacket,
    ) {
        if !config.arp.enabled {
            return;
        }
        let (Some(mac), Some(ip)) = (arp.sender_mac, arp.sender_ip) else {
            return;
        };
        if ip.is_unspecified() {
            // ARP probes (RFC 5227) claim no address.
            return;
        }
        if let Some((_, owners)) = self.arp_owners.add(ip, ns, mac, cite) {
            let key = ip.to_string();
            if let Some((pending, macs)) = self.conflict_alerts.get_mut(&key) {
                if macs.len() < MAX_RELATED {
                    macs.insert(mac);
                }
                pending.peak = pending.peak.max(owners);
                cite_on(&mut pending.alert, cite);
                pending.alert.last_seen = Some(pending.alert.last_seen.map_or(at, |t| t.max(at)));
            } else if owners >= 2
                && room(&self.conflict_alerts, ARP_CONFLICT.id, &mut self.at_limit)
            {
                let mut a = alert(&ARP_CONFLICT, Confidence::Medium);
                a.source = Some(IpAddr::V4(ip));
                let a = start(a, &self.arp_owners, &ip, at);
                // Every MAC address seen for the IP in the window.
                let macs: BTreeSet<MacAddr> = self
                    .arp_owners
                    .values(&ip)
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .take(MAX_RELATED)
                    .collect();
                self.conflict_alerts.insert(
                    key,
                    (
                        Pending {
                            alert: a,
                            peak: owners,
                        },
                        macs,
                    ),
                );
            }
        }
        let gratuitous = arp.target_ip == Some(ip);
        if gratuitous {
            let reached = self.arp_gratuitous.add(mac, ns, (), cite);
            let threshold = usize::try_from(config.arp.min_gratuitous).unwrap_or(usize::MAX);
            record(
                &mut self.flood_alerts,
                &mut self.at_limit,
                ARP_FLOOD.id,
                mac.to_string(),
                reached,
                threshold,
                &self.arp_gratuitous,
                &mac,
                || {
                    let mut a = alert(&ARP_FLOOD, Confidence::Medium);
                    a.source = Some(IpAddr::V4(ip));
                    a
                },
                cite,
                at,
            );
        }
    }

    /// Finished alerts, in rule order then key order.
    pub(crate) fn finish(self, config: &DetectionConfig) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for (client, mut p) in self.volume_alerts {
            let threshold = u64::from(config.dns_volume.min_queries);
            p.alert.confidence = Confidence::from_ratio(p.peak as u64, threshold);
            p.alert.evidence = vec![
                evidence("queries_in_window", p.peak),
                evidence("threshold", threshold),
                evidence("window", format!("{} s", config.dns_volume.window_seconds)),
            ];
            p.alert.explanation = format!(
                "{client} sent {} DNS queries within {} s. High query volume is normal for \
                 resolvers and busy hosts and can also accompany tunneling or malware; review \
                 what this host is.",
                p.peak, config.dns_volume.window_seconds
            );
            alerts.push(p.alert);
        }
        for (key, (mut p, subdomains)) in self.tunnel_alerts {
            let client = key.split(' ').next().unwrap_or_default().to_owned();
            let parent = p
                .alert
                .evidence
                .first()
                .map(|e| e.value.clone())
                .unwrap_or_default();
            let c = &config.dns_tunneling;
            // Either threshold raises the alert; both together raise confidence.
            let by_count = p.peak >= c.min_long_queries as usize;
            let by_spread = subdomains >= c.min_unique_subdomains as usize;
            let reached = match (by_count, by_spread) {
                (true, true) => "both",
                (false, true) => "min_distinct_subdomains",
                _ => "min_suspicious_queries",
            };
            p.alert.confidence = if by_count && by_spread {
                Confidence::High
            } else {
                Confidence::Medium
            };
            p.alert.evidence = vec![
                evidence("parent_domain", &parent),
                evidence("suspicious_queries_in_window", p.peak),
                evidence("distinct_subdomains_in_window", subdomains),
                evidence("min_suspicious_queries", c.min_long_queries),
                evidence("min_distinct_subdomains", c.min_unique_subdomains),
                evidence("threshold_reached", reached),
            ];
            p.alert.explanation = format!(
                "{client} sent {} queries under {parent} with long, high-entropy or TXT/NULL \
                 names, across {subdomains} distinct subdomains, within {} s. Encoding data in \
                 query names is how DNS tunneling works, but some legitimate services generate \
                 similar names.",
                p.peak, c.window_seconds
            );
            alerts.push(p.alert);
        }
        for (ip, (mut p, macs)) in self.conflict_alerts {
            let mut shown: Vec<String> = macs.iter().take(8).map(ToString::to_string).collect();
            let more = macs.len() - shown.len();
            // At most MAX_RELATED addresses are tracked; beyond that the
            // total is only known to be at least this.
            if macs.len() >= MAX_RELATED {
                shown.push(format!("and at least {more} more"));
            } else if more > 0 {
                shown.push(format!("and {more} more"));
            }
            p.alert.confidence = if p.peak >= 3 {
                Confidence::High
            } else {
                Confidence::Medium
            };
            p.alert.evidence = vec![
                evidence("ip_address", &ip),
                evidence("mac_addresses_in_window", p.peak),
                evidence("mac_addresses", shown.join(", ")),
                evidence("window", format!("{} s", config.arp.window_seconds)),
            ];
            p.alert.explanation = format!(
                "ARP messages claimed {ip} for {} different MAC addresses within {} s. ARP \
                 spoofing looks like this, and so do address conflicts and failover.",
                p.peak, config.arp.window_seconds
            );
            alerts.push(p.alert);
        }
        for (mac, mut p) in self.flood_alerts {
            let threshold = u64::from(config.arp.min_gratuitous);
            p.alert.confidence = Confidence::from_ratio(p.peak as u64, threshold);
            p.alert.evidence = vec![
                evidence("mac_address", &mac),
                evidence("gratuitous_arp_in_window", p.peak),
                evidence("threshold", threshold),
            ];
            p.alert.explanation = format!(
                "{mac} sent {} gratuitous ARP announcements within {} s. Repeated announcements \
                 can be used to poison ARP caches, and are also sent by some devices on link \
                 changes.",
                p.peak, config.arp.window_seconds
            );
            alerts.push(p.alert);
        }
        alerts
    }
}
