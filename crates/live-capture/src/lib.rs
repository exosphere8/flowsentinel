//! Authorized live capture.
//!
//! A [`PacketSource`] yields packets: from a network interface through
//! libpcap (feature `libpcap`), or from a capture file ([`ReplaySource`],
//! used by tests and demonstrations). [`session::start`] runs one bounded
//! capture: a capture thread reads the source and hands packets through a
//! bounded channel to a writer thread, which writes a classic pcap file. When
//! the writer cannot keep up, packets are dropped and counted instead of
//! queueing without limit. The caller analyzes the finished file as an
//! import (metadata only) and deletes it.
//!
//! Nothing here sends packets, changes interfaces beyond the requested
//! promiscuous mode (off by default), or decrypts anything.

pub mod bpf;
pub mod limits;
pub mod replay;
pub mod session;
pub mod source;
pub mod writer;

#[cfg(feature = "libpcap")]
pub mod libpcap;

pub use limits::{LimitError, LiveLimits};
pub use replay::{ReplayFactory, ReplaySource};
pub use session::{CounterSnapshot, Counters, Finished, LiveError, Running, StopReason};
pub use source::{
    InterfaceInfo, Next, OpenRequest, PacketSource, SourceError, SourceFactory, SourcePacket,
    SourceStats, Unavailable,
};

/// The factory for this build: libpcap when compiled in, otherwise one that
/// reports live capture as unavailable.
pub fn default_factory() -> Box<dyn SourceFactory> {
    #[cfg(feature = "libpcap")]
    {
        Box::new(libpcap::LibpcapFactory)
    }
    #[cfg(not(feature = "libpcap"))]
    {
        Box::new(Unavailable)
    }
}
