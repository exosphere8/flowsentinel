//! Alerts and the rule catalog.

use std::net::IpAddr;

use capture::Timestamp;
use serde::Serialize;

/// How much attention an alert deserves if it is a true positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// How strongly the evidence supports the rule's interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Medium at the threshold, high at twice the threshold or more.
    pub(crate) fn from_ratio(observed: u64, threshold: u64) -> Self {
        if observed >= threshold.saturating_mul(2) {
            Self::High
        } else {
            Self::Medium
        }
    }
}

/// Triage state, changed by analysts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Open,
    Acknowledged,
    Resolved,
    FalsePositive,
}

impl AlertStatus {
    pub const ALL: [Self; 4] = [
        Self::Open,
        Self::Acknowledged,
        Self::Resolved,
        Self::FalsePositive,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Resolved => "resolved",
            Self::FalsePositive => "false_positive",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == text)
    }
}

/// One measured fact behind an alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    pub name: &'static str,
    pub value: String,
}

/// Every alert says what it is: a heuristic indicator, not a verdict.
pub const NATURE: &str =
    "heuristic indicator: an observed pattern that deserves review, not proof of compromise";

/// A rule's fixed description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Rule {
    /// Stable identifier, for example `FS-SCAN-SYN`.
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    /// Why the alert may be wrong.
    pub uncertainty: &'static str,
    pub likely_false_positives: &'static [&'static str],
    /// MITRE ATT&CK techniques the pattern can relate to. Contextual tags
    /// only: an alert never claims a technique was used.
    pub mitre_attack: &'static [&'static str],
}

/// A raised alert.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Alert {
    /// Sequential from 1 within one analysis, in rule then key order.
    pub alert_id: u64,
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: AlertStatus,
    pub nature: &'static str,
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
    /// The endpoint whose behavior triggered the rule.
    pub source: Option<IpAddr>,
    /// The endpoint the behavior was directed at, when there is one.
    pub destination: Option<IpAddr>,
    pub destination_port: Option<u16>,
    /// At most [`MAX_RELATED`] flow IDs.
    pub related_flow_ids: Vec<u64>,
    /// At most [`MAX_RELATED`] packet indexes.
    pub related_packet_indexes: Vec<u64>,
    pub evidence: Vec<Evidence>,
    pub explanation: String,
    pub uncertainty: &'static str,
    pub likely_false_positives: &'static [&'static str],
    pub mitre_attack: &'static [&'static str],
}

/// Related IDs kept per alert.
pub const MAX_RELATED: usize = 50;

pub(crate) fn push_related(list: &mut Vec<u64>, id: u64) {
    if list.len() < MAX_RELATED && !list.contains(&id) {
        list.push(id);
    }
}

pub const SYN_SCAN: Rule = Rule {
    id: "FS-SCAN-SYN",
    name: "Possible SYN scan",
    severity: Severity::Medium,
    description: "One host sent connection attempts to many TCP ports of another host, and most \
                  were refused or never answered.",
    uncertainty: "Port counts come from reconstructed flows; a capture that misses the replies \
                  makes successful connections look unanswered.",
    likely_false_positives: &[
        "authorized vulnerability or inventory scanners",
        "monitoring that probes many service ports",
        "a client retrying through a list of fallback ports",
    ],
    mitre_attack: &["T1046 Network Service Discovery"],
};

pub const PORT_SWEEP: Rule = Rule {
    id: "FS-SCAN-PORTS",
    name: "Many ports contacted on one host",
    severity: Severity::Medium,
    description: "One host contacted many distinct TCP or UDP ports on a single other host \
                  within a short window.",
    uncertainty: "Busy clients of services that use dynamic ports (RPC, media, games) can reach \
                  the threshold without scanning.",
    likely_false_positives: &[
        "authorized scanners",
        "RPC or media protocols that negotiate ephemeral server ports",
        "load tests",
    ],
    mitre_attack: &["T1046 Network Service Discovery"],
};

pub const HORIZONTAL_SCAN: Rule = Rule {
    id: "FS-SCAN-HOSTS",
    name: "Same port tried on many hosts",
    severity: Severity::Medium,
    description: "One host's connection attempts to the same port on many distinct hosts were \
                  refused or never answered within a short window.",
    uncertainty: "Service discovery, monitoring and peer-to-peer software try many hosts on one \
                  port by design, and a capture that misses replies makes answered attempts look \
                  unanswered.",
    likely_false_positives: &[
        "network monitoring and inventory tools",
        "service discovery (mDNS, SSDP, NetBIOS)",
        "peer-to-peer applications",
        "clients retrying servers that are down or filtered",
    ],
    mitre_attack: &[
        "T1046 Network Service Discovery",
        "T1018 Remote System Discovery",
    ],
};

pub const DNS_VOLUME: Rule = Rule {
    id: "FS-DNS-VOLUME",
    name: "High DNS query volume",
    severity: Severity::Low,
    description: "One client sent an unusually large number of DNS queries within a short window.",
    uncertainty: "Resolvers, mail servers and hosts behind NAT legitimately send many queries.",
    likely_false_positives: &[
        "DNS resolvers or forwarders",
        "mail servers checking blocklists",
        "many clients behind one NAT address",
        "software start-up bursts",
    ],
    mitre_attack: &["T1071.004 Application Layer Protocol: DNS"],
};

pub const DNS_TUNNELING: Rule = Rule {
    id: "FS-DNS-TUNNEL",
    name: "Possible DNS tunneling",
    severity: Severity::High,
    description: "One client queried many long, high-entropy or TXT/NULL names under a single \
                  parent domain, a pattern used to carry data inside DNS.",
    uncertainty: "Entropy and length are rough signals; the parent domain is the last two labels \
                  of the name, so multi-label public suffixes (for example co.uk) are grouped \
                  too broadly.",
    likely_false_positives: &[
        "anti-virus and reputation services that encode hashes in DNS names",
        "CDN or cloud services with long generated host names",
        "DKIM and other TXT lookups by mail servers",
    ],
    mitre_attack: &[
        "T1071.004 Application Layer Protocol: DNS",
        "T1048 Exfiltration Over Alternative Protocol",
    ],
};

pub const BEACONING: Rule = Rule {
    id: "FS-BEACON",
    name: "Regular repeated connections",
    severity: Severity::Medium,
    description: "One host connected to the same destination and port at very regular intervals.",
    uncertainty: "Regularity alone is common: update checks, health checks and telemetry all \
                  beacon. Few connections give an unreliable estimate.",
    likely_false_positives: &[
        "software update and licence checks",
        "monitoring agents and health checks",
        "NTP, telemetry and keep-alive traffic",
    ],
    mitre_attack: &["T1071 Application Layer Protocol"],
};

pub const RARE_PORT: Rule = Rule {
    id: "FS-RARE-PORT",
    name: "Rarely used destination port",
    severity: Severity::Low,
    description: "A connection was answered on a destination port that almost no other flow in \
                  the capture used.",
    uncertainty: "Rarity is relative to this capture only; any short or narrow capture makes \
                  ordinary services look rare.",
    likely_false_positives: &[
        "legitimate services on non-standard ports",
        "short captures",
        "development and test servers",
    ],
    mitre_attack: &["T1571 Non-Standard Port"],
};

pub const OUTBOUND_RATIO: Rule = Rule {
    id: "FS-OUTBOUND-RATIO",
    name: "Large outbound transfer",
    severity: Severity::Medium,
    description: "An internal host sent much more data to an external host than it received, \
                  in a single flow.",
    uncertainty: "Internal and external are decided by the configured internal networks; uploads \
                  and backups are indistinguishable from exfiltration by metadata alone.",
    likely_false_positives: &[
        "cloud backup and file synchronization",
        "video calls and uploads",
        "software builds pushing artifacts",
    ],
    mitre_attack: &[
        "T1048 Exfiltration Over Alternative Protocol",
        "T1041 Exfiltration Over C2 Channel",
    ],
};

pub const TCP_FAILURES: Rule = Rule {
    id: "FS-TCP-FAIL",
    name: "Many failed TCP connections",
    severity: Severity::Low,
    description: "One host made many TCP connection attempts that were refused (RST) or never \
                  answered, across any destinations.",
    uncertainty: "Firewalls that silently drop traffic, and captures that miss replies, also \
                  produce unanswered attempts.",
    likely_false_positives: &[
        "misconfigured clients retrying a dead service",
        "a service that is down",
        "asymmetric routing that hides the replies from the capture",
    ],
    mitre_attack: &["T1046 Network Service Discovery"],
};

pub const CLEARTEXT: Rule = Rule {
    id: "FS-CLEARTEXT",
    name: "Cleartext login protocol in use",
    severity: Severity::Low,
    description: "A connection to a port of a cleartext login protocol (FTP, Telnet, POP3, IMAP, \
                  rlogin, rsh) was answered. Credentials on such protocols travel unencrypted.",
    uncertainty: "Decided by port only; the service may use STARTTLS or be something else on \
                  that port.",
    likely_false_positives: &[
        "STARTTLS-upgraded sessions",
        "anonymous FTP",
        "lab or legacy equipment on an isolated network",
    ],
    mitre_attack: &["T1040 Network Sniffing", "T1552 Unsecured Credentials"],
};

pub const ARP_CONFLICT: Rule = Rule {
    id: "FS-ARP-CONFLICT",
    name: "IP address claimed by several MAC addresses",
    severity: Severity::High,
    description: "ARP traffic mapped the same IPv4 address to more than one MAC address within a \
                  short window, which happens in ARP spoofing.",
    uncertainty: "Address conflicts, failover pairs (VRRP, HSRP) and virtual machines that move \
                  between hosts produce the same pattern.",
    likely_false_positives: &[
        "duplicate IP address misconfiguration",
        "high-availability failover",
        "VM migration or NIC replacement",
    ],
    mitre_attack: &["T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning"],
};

pub const ARP_FLOOD: Rule = Rule {
    id: "FS-ARP-GRATUITOUS",
    name: "Many gratuitous ARP replies",
    severity: Severity::Low,
    description: "One MAC address sent many gratuitous ARP announcements within a short window.",
    uncertainty: "Some devices announce repeatedly on link changes or start-up.",
    likely_false_positives: &[
        "devices booting or changing links",
        "high-availability failover",
        "some wireless or virtualization stacks",
    ],
    mitre_attack: &["T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning"],
};

/// Every rule, in evaluation and alert-numbering order.
pub const RULES: [Rule; 12] = [
    SYN_SCAN,
    PORT_SWEEP,
    HORIZONTAL_SCAN,
    TCP_FAILURES,
    BEACONING,
    RARE_PORT,
    OUTBOUND_RATIO,
    CLEARTEXT,
    DNS_VOLUME,
    DNS_TUNNELING,
    ARP_CONFLICT,
    ARP_FLOOD,
];
