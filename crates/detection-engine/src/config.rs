//! Rule thresholds, loaded from TOML. Every field has a documented default,
//! and every value is range-checked when loaded.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Thresholds for every rule. Missing sections and fields take defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionConfig {
    /// Networks treated as internal for direction-aware rules, in CIDR form.
    /// Defaults to RFC 1918, RFC 4193, loopback, link-local and the
    /// documentation ranges used by synthetic fixtures.
    pub internal_networks: Vec<String>,
    pub syn_scan: SynScan,
    pub port_sweep: PortSweep,
    pub horizontal_scan: HorizontalScan,
    pub dns_volume: DnsVolume,
    pub dns_tunneling: DnsTunneling,
    pub beaconing: Beaconing,
    pub rare_destination_port: RareDestinationPort,
    pub outbound_ratio: OutboundRatio,
    pub tcp_failures: TcpFailures,
    pub cleartext: Cleartext,
    pub arp: Arp,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            internal_networks: [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "192.0.2.0/24",
                "fc00::/7",
                "fe80::/10",
                "::1/128",
            ]
            .map(str::to_owned)
            .to_vec(),
            syn_scan: SynScan::default(),
            port_sweep: PortSweep::default(),
            horizontal_scan: HorizontalScan::default(),
            dns_volume: DnsVolume::default(),
            dns_tunneling: DnsTunneling::default(),
            beaconing: Beaconing::default(),
            rare_destination_port: RareDestinationPort::default(),
            outbound_ratio: OutboundRatio::default(),
            tcp_failures: TcpFailures::default(),
            cleartext: Cleartext::default(),
            arp: Arp::default(),
        }
    }
}

macro_rules! rule_section {
    ($name:ident { $($field:ident : $ty:ty = $default:expr, $doc:literal;)* }) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct $name {
            /// Whether the rule runs.
            pub enabled: bool,
            $(#[doc = $doc] pub $field: $ty,)*
        }

        impl Default for $name {
            fn default() -> Self {
                Self { enabled: true, $($field: $default,)* }
            }
        }
    };
}

rule_section!(SynScan {
    window_seconds: u64 = 60, "Sliding window length.";
    min_ports: u32 = 20, "Distinct destination ports on one host with unanswered or refused handshakes.";
});

rule_section!(PortSweep {
    window_seconds: u64 = 60, "Sliding window length.";
    min_ports: u32 = 50, "Distinct destination ports contacted on one host, any outcome.";
});

rule_section!(HorizontalScan {
    window_seconds: u64 = 60, "Sliding window length.";
    min_hosts: u32 = 20, "Distinct destination hosts contacted on the same port.";
});

rule_section!(DnsVolume {
    window_seconds: u64 = 60, "Sliding window length.";
    min_queries: u32 = 200, "DNS queries sent by one client.";
});

rule_section!(DnsTunneling {
    window_seconds: u64 = 300, "Sliding window length.";
    min_long_queries: u32 = 10, "Suspicious queries (long or high-entropy labels, TXT/NULL types) under one parent domain.";
    min_label_length: u32 = 40, "Label length considered long.";
    min_name_length: u32 = 100, "Full name length considered long.";
    min_entropy_bits: f64 = 3.8, "Shannon entropy per character considered high (labels of 16+ characters).";
    min_unique_subdomains: u32 = 30, "Distinct subdomains of one parent domain.";
});

rule_section!(Beaconing {
    min_connections: u32 = 6, "Connections from one source to the same destination and port.";
    max_jitter_ratio: f64 = 0.1, "Highest allowed ratio of interval standard deviation to mean.";
    min_interval_seconds: f64 = 10.0, "Shortest mean interval considered (shorter is normal polling or bulk traffic).";
});

rule_section!(RareDestinationPort {
    min_flows: u32 = 50, "Flows the capture must contain before rarity is judged.";
    max_occurrences: u32 = 1, "A destination port used by at most this many flows is rare.";
});

rule_section!(OutboundRatio {
    min_bytes_out: u64 = 1_000_000, "Bytes sent from an internal initiator to an external responder.";
    min_ratio: f64 = 10.0, "Outbound to inbound byte ratio.";
});

rule_section!(TcpFailures {
    window_seconds: u64 = 60, "Sliding window length.";
    min_failures: u32 = 30, "Reset or unanswered connection attempts from one source.";
});

rule_section!(Cleartext {
    ports: Vec<u16> = vec![21, 23, 110, 143, 513, 514], "Destination ports of cleartext login protocols (FTP, Telnet, POP3, IMAP, rlogin, rsh).";
});

rule_section!(Arp {
    window_seconds: u64 = 60, "Sliding window length.";
    min_gratuitous: u32 = 20, "Gratuitous ARP replies from one MAC address.";
});

/// A configuration problem, with the offending setting named.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read the detection configuration: {0}")]
    Read(String),
    #[error("the detection configuration is larger than {max} bytes")]
    TooLarge { max: u64 },
    #[error("invalid detection configuration: {0}")]
    Parse(String),
    #[error("invalid value for {setting}: {reason}")]
    Value {
        setting: &'static str,
        reason: &'static str,
    },
}

/// Largest accepted configuration file.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;

impl DetectionConfig {
    /// Reads, parses and validates a TOML file of at most
    /// [`MAX_CONFIG_BYTES`].
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        use std::io::Read;
        let file = std::fs::File::open(path).map_err(|e| ConfigError::Read(e.to_string()))?;
        let mut text = String::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| ConfigError::Read(e.to_string()))?;
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                max: MAX_CONFIG_BYTES,
            });
        }
        Self::from_toml(&text)
    }

    /// Parses and validates TOML. Unknown keys are rejected.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self =
            toml::from_str(text).map_err(|e| ConfigError::Parse(e.message().to_owned()))?;
        config.validate()?;
        Ok(config)
    }

    /// Checks every value is within its sensible range.
    pub fn validate(&self) -> Result<(), ConfigError> {
        fn window(setting: &'static str, seconds: u64) -> Result<(), ConfigError> {
            if (1..=86_400).contains(&seconds) {
                Ok(())
            } else {
                Err(ConfigError::Value {
                    setting,
                    reason: "must be between 1 and 86400 seconds",
                })
            }
        }
        fn count(setting: &'static str, value: u32) -> Result<(), ConfigError> {
            if (1..=1_000_000).contains(&value) {
                Ok(())
            } else {
                Err(ConfigError::Value {
                    setting,
                    reason: "must be between 1 and 1000000",
                })
            }
        }
        // A window holds at most MAX_EVENTS_PER_WINDOW events, so a larger
        // threshold could never be reached.
        fn windowed(setting: &'static str, value: u32) -> Result<(), ConfigError> {
            if (1..=4096).contains(&value) {
                Ok(())
            } else {
                Err(ConfigError::Value {
                    setting,
                    reason: "must be between 1 and 4096",
                })
            }
        }
        fn positive(setting: &'static str, value: f64) -> Result<(), ConfigError> {
            if value.is_finite() && value > 0.0 {
                Ok(())
            } else {
                Err(ConfigError::Value {
                    setting,
                    reason: "must be a positive number",
                })
            }
        }
        if self.internal_networks.len() > 256 {
            return Err(ConfigError::Value {
                setting: "internal_networks",
                reason: "at most 256 networks",
            });
        }
        if self
            .internal_networks
            .iter()
            .any(|n| parse_cidr(n).is_none())
        {
            return Err(ConfigError::Value {
                setting: "internal_networks",
                reason: "each entry must be an IP network in CIDR form",
            });
        }
        window("syn_scan.window_seconds", self.syn_scan.window_seconds)?;
        windowed("syn_scan.min_ports", self.syn_scan.min_ports)?;
        window("port_sweep.window_seconds", self.port_sweep.window_seconds)?;
        windowed("port_sweep.min_ports", self.port_sweep.min_ports)?;
        window(
            "horizontal_scan.window_seconds",
            self.horizontal_scan.window_seconds,
        )?;
        windowed("horizontal_scan.min_hosts", self.horizontal_scan.min_hosts)?;
        window("dns_volume.window_seconds", self.dns_volume.window_seconds)?;
        windowed("dns_volume.min_queries", self.dns_volume.min_queries)?;
        window(
            "dns_tunneling.window_seconds",
            self.dns_tunneling.window_seconds,
        )?;
        windowed(
            "dns_tunneling.min_long_queries",
            self.dns_tunneling.min_long_queries,
        )?;
        count(
            "dns_tunneling.min_label_length",
            self.dns_tunneling.min_label_length,
        )?;
        count(
            "dns_tunneling.min_name_length",
            self.dns_tunneling.min_name_length,
        )?;
        windowed(
            "dns_tunneling.min_unique_subdomains",
            self.dns_tunneling.min_unique_subdomains,
        )?;
        positive(
            "dns_tunneling.min_entropy_bits",
            self.dns_tunneling.min_entropy_bits,
        )?;
        // Regularity needs at least two intervals.
        if !(3..=1_000_000).contains(&self.beaconing.min_connections) {
            return Err(ConfigError::Value {
                setting: "beaconing.min_connections",
                reason: "must be between 3 and 1000000",
            });
        }
        positive(
            "beaconing.max_jitter_ratio",
            self.beaconing.max_jitter_ratio,
        )?;
        positive(
            "beaconing.min_interval_seconds",
            self.beaconing.min_interval_seconds,
        )?;
        count(
            "rare_destination_port.min_flows",
            self.rare_destination_port.min_flows,
        )?;
        count(
            "rare_destination_port.max_occurrences",
            self.rare_destination_port.max_occurrences,
        )?;
        if self.outbound_ratio.min_bytes_out == 0 {
            return Err(ConfigError::Value {
                setting: "outbound_ratio.min_bytes_out",
                reason: "must be at least 1",
            });
        }
        positive("outbound_ratio.min_ratio", self.outbound_ratio.min_ratio)?;
        window(
            "tcp_failures.window_seconds",
            self.tcp_failures.window_seconds,
        )?;
        windowed("tcp_failures.min_failures", self.tcp_failures.min_failures)?;
        if self.cleartext.ports.len() > 64 {
            return Err(ConfigError::Value {
                setting: "cleartext.ports",
                reason: "at most 64 ports",
            });
        }
        window("arp.window_seconds", self.arp.window_seconds)?;
        windowed("arp.min_gratuitous", self.arp.min_gratuitous)?;
        Ok(())
    }

    /// Whether `ip` is in one of the internal networks.
    pub fn is_internal(&self, ip: IpAddr) -> bool {
        self.internal_networks
            .iter()
            .filter_map(|n| parse_cidr(n))
            .any(|(network, prefix)| in_network(ip, network, prefix))
    }
}

/// Parses `address/prefix` (or a bare address as a host network).
pub fn parse_cidr(text: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = text.split_once('/').unwrap_or((text, ""));
    let ip: IpAddr = address.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = if prefix.is_empty() {
        max
    } else {
        prefix.trim().parse::<u8>().ok()?
    };
    (prefix <= max).then_some((ip, prefix))
}

/// Whether `ip` lies in `network/prefix` (same address family only).
pub fn in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_round_trip_through_toml() {
        let config = DetectionConfig::default();
        config.validate().unwrap();
        let text = toml::to_string(&config).unwrap();
        assert_eq!(DetectionConfig::from_toml(&text).unwrap(), config);
    }

    #[test]
    fn example_file_matches_the_defaults() {
        let text = include_str!("../../../config/detection.example.toml");
        assert_eq!(
            DetectionConfig::from_toml(text).unwrap(),
            DetectionConfig::default()
        );
    }

    #[test]
    fn partial_files_use_defaults() {
        let config = DetectionConfig::from_toml("[syn_scan]\nmin_ports = 5\n").unwrap();
        assert_eq!(config.syn_scan.min_ports, 5);
        assert_eq!(config.syn_scan.window_seconds, 60);
        assert!(config.beaconing.enabled);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values() {
        assert!(DetectionConfig::from_toml("[syn_scan]\nmin_portz = 5\n").is_err());
        assert!(DetectionConfig::from_toml("[syn_scan]\nwindow_seconds = 0\n").is_err());
        assert!(DetectionConfig::from_toml("internal_networks = [\"not a net\"]\n").is_err());
        assert!(DetectionConfig::from_toml("[beaconing]\nmax_jitter_ratio = -1.0\n").is_err());
        assert!(DetectionConfig::from_toml("[beaconing]\nmax_jitter_ratio = nan\n").is_err());
        let err = DetectionConfig::from_toml("[dns_volume]\nmin_queries = 5000\n").unwrap_err();
        assert!(err.to_string().contains("between 1 and 4096"), "{err}");
        for bad in [0, 2] {
            let err =
                DetectionConfig::from_toml(&format!("[beaconing]\nmin_connections = {bad}\n"))
                    .unwrap_err();
            assert!(
                err.to_string().contains("beaconing.min_connections"),
                "{err}"
            );
        }
        assert!(DetectionConfig::from_toml("[beaconing]\nmin_connections = 3\n").is_ok());
    }

    #[test]
    fn internal_network_matching() {
        let config = DetectionConfig::default();
        assert!(config.is_internal("192.168.1.5".parse().unwrap()));
        assert!(config.is_internal("192.0.2.10".parse().unwrap()));
        assert!(!config.is_internal("198.51.100.20".parse().unwrap()));
        assert!(config.is_internal("fd00::1".parse().unwrap()));
        assert!(!config.is_internal("2001:db8::1".parse().unwrap()));
        assert!(in_network(
            "10.1.2.3".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            0
        ));
    }
}
