//! Bidirectional flow reconstruction with bounded memory.
//!
//! [`FlowEngine`] groups decoded packets into flows keyed by IP protocol and
//! the two endpoints in canonical order ([`FlowKey`]), so both directions of
//! a conversation land in the same flow. Which side started the flow is
//! inferred from the TCP handshake when one is seen, and otherwise from the
//! first packet; it is never inferred from address or port order.
//!
//! Each flow tracks per-direction packet and byte counts, packet-size and
//! inter-arrival statistics, TCP flags and an approximate TCP state,
//! application metadata (DNS names, HTTP hosts and paths, TLS server names)
//! and warnings. Flows end on idle timeout, after TCP closes, when evicted
//! from a full table, or at the end of the capture.
//!
//! The engine is deterministic: given the same packets in the same order it
//! produces identical output.

mod engine;
mod flow;
mod key;
mod observe;
mod record;
mod stats;

pub use engine::{FlowConfig, FlowEngine, FlowReport, FlowSummary, MAX_UNCONFIRMED_JUMP};
pub use flow::FlowPacket;
pub use key::{Endpoint, FlowKey};
pub use record::{
    ApplicationSummary, DirectionCounters, Dominance, EndReason, FlowRecord, FlowWarning,
    FlowWarningCode, InitiatorBasis, InterArrivalSummary, SizeSummary, TcpState, TcpSummary,
};
pub use stats::Summary;
