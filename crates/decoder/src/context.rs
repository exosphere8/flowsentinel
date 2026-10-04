//! Per-packet decoding state shared by the protocol parsers.

use crate::model::{
    DecodeStatus, DecodeWarning, DecodeWarningCode, DecodedPacket, Layer, Protocol,
};

/// Upper bound on warnings kept per packet. Parsers add at most a handful;
/// the cap guarantees it regardless.
const MAX_WARNINGS_PER_PACKET: usize = 8;

/// Collects layers and warnings while a packet is decoded.
#[derive(Debug)]
pub(crate) struct Context {
    layers: Vec<Layer>,
    warnings: Vec<DecodeWarning>,
    status: DecodeStatus,
    snapped: bool,
}

impl Context {
    /// `snapped` says the capture saved fewer bytes than were on the wire.
    pub(crate) fn new(snapped: bool) -> Self {
        Self {
            layers: Vec::new(),
            warnings: Vec::new(),
            status: DecodeStatus::Complete,
            snapped,
        }
    }

    /// Whether the frame was cut short by the capture's snapshot length.
    /// When it was not, a header that declares more bytes than the frame
    /// holds is lying rather than truncated.
    pub(crate) fn snapped(&self) -> bool {
        self.snapped
    }

    pub(crate) fn push(&mut self, layer: Layer) {
        self.layers.push(layer);
    }

    /// Records a warning that does not stop decoding.
    pub(crate) fn warn(
        &mut self,
        code: DecodeWarningCode,
        protocol: Option<Protocol>,
        detail: &'static str,
    ) {
        let duplicate = self
            .warnings
            .iter()
            .any(|w| w.code == code && w.protocol == protocol);
        if !duplicate && self.warnings.len() < MAX_WARNINGS_PER_PACKET {
            self.warnings.push(DecodeWarning {
                code,
                protocol,
                detail,
            });
        }
    }

    /// Records why decoding stopped. Callers return immediately afterwards.
    pub(crate) fn stop(
        &mut self,
        status: DecodeStatus,
        code: DecodeWarningCode,
        protocol: Option<Protocol>,
        detail: &'static str,
    ) {
        if self.status == DecodeStatus::Complete {
            self.status = status;
        }
        self.warn(code, protocol, detail);
    }

    pub(crate) fn truncated(&mut self, protocol: Protocol, detail: &'static str) {
        self.stop(
            DecodeStatus::Truncated,
            DecodeWarningCode::TruncatedHeader,
            Some(protocol),
            detail,
        );
    }

    pub(crate) fn malformed(&mut self, protocol: Protocol, detail: &'static str) {
        self.stop(
            DecodeStatus::Malformed,
            DecodeWarningCode::InvalidHeaderField,
            Some(protocol),
            detail,
        );
    }

    pub(crate) fn finish(self) -> DecodedPacket {
        DecodedPacket {
            status: self.status,
            layers: self.layers,
            warnings: self.warnings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_stop_reason_wins_and_warnings_are_deduplicated() {
        let mut ctx = Context::new(false);
        ctx.warn(DecodeWarningCode::Fragment, Some(Protocol::Ipv4), "a");
        ctx.warn(DecodeWarningCode::Fragment, Some(Protocol::Ipv4), "b");
        ctx.truncated(Protocol::Tcp, "short");
        ctx.malformed(Protocol::Tcp, "bad");
        let packet = ctx.finish();
        assert_eq!(packet.status, DecodeStatus::Truncated);
        assert_eq!(packet.warnings.len(), 3);
    }

    #[test]
    fn warnings_are_capped() {
        let mut ctx = Context::new(false);
        for code in DecodeWarningCode::ALL {
            for protocol in [Protocol::Ipv4, Protocol::Ipv6] {
                ctx.warn(code, Some(protocol), "x");
            }
        }
        assert_eq!(ctx.finish().warnings.len(), MAX_WARNINGS_PER_PACKET);
    }
}
