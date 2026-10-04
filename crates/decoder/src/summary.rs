//! Capture-wide aggregation of decode results.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::model::{DecodeStatus, DecodeWarningCode, DecodedPacket, Protocol};

/// A decode warning aggregated across packets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecodeWarningSummary {
    pub code: DecodeWarningCode,
    pub protocol: Option<Protocol>,
    pub count: u64,
    /// 1-based index of the first packet that produced it.
    pub first_packet_index: u64,
}

/// Counts of statuses, protocols and warnings over a capture. Its size is
/// bounded by the number of distinct enum values, not by packet count.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DecodeSummary {
    pub packets_decoded: u64,
    /// Packets per decode status.
    pub status_counts: BTreeMap<DecodeStatus, u64>,
    /// Packets containing each protocol.
    pub protocol_counts: BTreeMap<Protocol, u64>,
    pub warnings: Vec<DecodeWarningSummary>,
}

impl DecodeSummary {
    /// Adds one decoded packet with its 1-based index.
    pub fn add(&mut self, packet_index: u64, packet: &DecodedPacket) {
        self.packets_decoded = self.packets_decoded.saturating_add(1);
        bump(self.status_counts.entry(packet.status).or_default());

        let mut seen: Vec<Protocol> = Vec::new();
        for layer in &packet.layers {
            let protocol = layer.protocol();
            if !seen.contains(&protocol) {
                seen.push(protocol);
                bump(self.protocol_counts.entry(protocol).or_default());
            }
        }

        for warning in &packet.warnings {
            match self
                .warnings
                .iter_mut()
                .find(|w| w.code == warning.code && w.protocol == warning.protocol)
            {
                Some(existing) => bump(&mut existing.count),
                None => self.warnings.push(DecodeWarningSummary {
                    code: warning.code,
                    protocol: warning.protocol,
                    count: 1,
                    first_packet_index: packet_index,
                }),
            }
        }
    }
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}
