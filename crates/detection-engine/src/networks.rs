//! Parsed internal networks.

use std::net::IpAddr;

use crate::config::{in_network, parse_cidr};

/// The configured internal networks, parsed once.
#[derive(Debug, Clone, Default)]
pub(crate) struct Networks(Vec<(IpAddr, u8)>);

impl Networks {
    pub(crate) fn parse(cidrs: &[String]) -> Self {
        Self(cidrs.iter().filter_map(|c| parse_cidr(c)).collect())
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        self.0
            .iter()
            .any(|&(network, prefix)| in_network(ip, network, prefix))
    }
}
