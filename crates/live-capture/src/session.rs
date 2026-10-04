//! One bounded capture: a capture thread reads the source and hands packets
//! through a bounded channel to a writer thread.
//!
//! The capture thread never waits for the writer. When the channel is full
//! (the writer, usually the disk, is slower than the network), the packet is
//! dropped and counted in `dropped_backpressure`, so memory stays bounded by
//! [`CHANNEL_CAPACITY`] packets of at most the snapshot length each.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::Instant;

use crate::limits::LiveLimits;
use crate::source::{Next, PacketSource, SourceError, SourcePacket};
use crate::writer::{FILE_HEADER_LEN, PcapWriter};

/// Packets buffered between the capture and writer threads.
pub const CHANNEL_CAPACITY: usize = 1024;
/// How often (in packets seen) the operating system's drop counts are read.
const STATS_EVERY: u64 = 256;

/// Live counters, readable while the capture runs.
#[derive(Debug, Default)]
pub struct Counters {
    /// Packets the source delivered.
    pub seen: AtomicU64,
    /// Packets written to the file.
    pub written: AtomicU64,
    /// Bytes written to the file, headers included.
    pub bytes: AtomicU64,
    /// Packets dropped because the writer was behind.
    pub dropped_backpressure: AtomicU64,
    /// Packets the kernel dropped (buffer full).
    pub kernel_dropped: AtomicU64,
    /// Packets the interface or driver dropped.
    pub interface_dropped: AtomicU64,
}

/// A copy of [`Counters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CounterSnapshot {
    pub seen: u64,
    pub written: u64,
    pub bytes: u64,
    pub dropped_backpressure: u64,
    pub kernel_dropped: u64,
    pub interface_dropped: u64,
}

impl Counters {
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            seen: self.seen.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            dropped_backpressure: self.dropped_backpressure.load(Ordering::Relaxed),
            kernel_dropped: self.kernel_dropped.load(Ordering::Relaxed),
            interface_dropped: self.interface_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Why a capture stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// An operator stopped it.
    Requested,
    PacketLimit,
    ByteLimit,
    TimeLimit,
    /// The source ran out of packets (replay sources).
    SourceEnded,
}

impl StopReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PacketLimit => "packet_limit_reached",
            Self::ByteLimit => "byte_limit_reached",
            Self::TimeLimit => "time_limit_reached",
            Self::SourceEnded => "source_ended",
        }
    }
}

/// A finished capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    pub reason: StopReason,
    pub counters: CounterSnapshot,
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
}

/// A capture that failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LiveError {
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error("writing the capture file failed: {0}")]
    Write(String),
    #[error("a capture thread stopped unexpectedly")]
    Thread,
}

/// A running capture.
#[derive(Debug)]
pub struct Running {
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
    handle: JoinHandle<Result<Finished, LiveError>>,
}

impl Running {
    /// Asks the capture to stop; it does at the source's next return, within
    /// a fraction of a second.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn counters(&self) -> CounterSnapshot {
        self.counters.snapshot()
    }

    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    /// Waits for the capture to end. Blocks; call it off the async runtime.
    pub fn join(self) -> Result<Finished, LiveError> {
        self.handle.join().unwrap_or(Err(LiveError::Thread))
    }
}

/// Starts capturing from `source` into `out` within `limits`.
pub fn start<W: Write + Send + 'static>(
    source: Box<dyn PacketSource>,
    limits: LiveLimits,
    out: W,
) -> std::io::Result<Running> {
    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Counters::default());
    let handle = std::thread::Builder::new()
        .name("live-capture".to_owned())
        .spawn({
            let stop = Arc::clone(&stop);
            let counters = Arc::clone(&counters);
            move || capture(source, limits, out, &stop, &counters)
        })?;
    Ok(Running {
        stop,
        counters,
        handle,
    })
}

fn record_stats(source: &mut dyn PacketSource, counters: &Counters) {
    let stats = source.stats();
    counters
        .kernel_dropped
        .store(stats.kernel_dropped, Ordering::Relaxed);
    counters
        .interface_dropped
        .store(stats.interface_dropped, Ordering::Relaxed);
}

fn capture<W: Write + Send + 'static>(
    mut source: Box<dyn PacketSource>,
    limits: LiveLimits,
    out: W,
    stop: &AtomicBool,
    counters: &Arc<Counters>,
) -> Result<Finished, LiveError> {
    let (sender, receiver) = sync_channel::<SourcePacket>(CHANNEL_CAPACITY);
    let link_type = source.link_type();
    let snaplen = source.snaplen();
    let writer = std::thread::Builder::new()
        .name("live-capture-writer".to_owned())
        .spawn({
            let counters = Arc::clone(counters);
            move || -> Result<String, LiveError> {
                let write = |e: std::io::Error| LiveError::Write(e.to_string());
                let mut file = PcapWriter::new(out, link_type, snaplen).map_err(write)?;
                counters.bytes.store(file.bytes(), Ordering::Relaxed);
                for packet in receiver {
                    file.write_packet(&packet).map_err(write)?;
                    counters.written.fetch_add(1, Ordering::Relaxed);
                    counters.bytes.store(file.bytes(), Ordering::Relaxed);
                }
                file.finish().map_err(write)
            }
        })
        .map_err(|e| LiveError::Write(e.to_string()))?;

    let started = Instant::now();
    let mut accepted_packets: u64 = 0;
    let mut accepted_bytes: u64 = FILE_HEADER_LEN;
    let outcome = loop {
        if stop.load(Ordering::Relaxed) {
            break Ok(StopReason::Requested);
        }
        if started.elapsed() >= limits.max_duration {
            break Ok(StopReason::TimeLimit);
        }
        let packet = match source.next_packet() {
            Ok(Next::Packet(packet)) => packet,
            Ok(Next::Idle) => continue,
            Ok(Next::End) => break Ok(StopReason::SourceEnded),
            Err(err) => break Err(LiveError::Source(err)),
        };
        let seen = counters
            .seen
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if seen % STATS_EVERY == 0 {
            record_stats(source.as_mut(), counters);
        }
        let size = PcapWriter::<W>::record_len(&packet);
        if accepted_bytes.saturating_add(size) > limits.max_bytes {
            break Ok(StopReason::ByteLimit);
        }
        match sender.try_send(packet) {
            Ok(()) => {
                accepted_packets += 1;
                accepted_bytes = accepted_bytes.saturating_add(size);
            }
            Err(TrySendError::Full(_)) => {
                counters
                    .dropped_backpressure
                    .fetch_add(1, Ordering::Relaxed);
            }
            // The writer failed; its error is reported below.
            Err(TrySendError::Disconnected(_)) => break Ok(StopReason::Requested),
        }
        if accepted_packets >= limits.max_packets {
            break Ok(StopReason::PacketLimit);
        }
    };
    record_stats(source.as_mut(), counters);
    drop(source);
    drop(sender);
    let written = writer.join().unwrap_or(Err(LiveError::Thread));
    let reason = outcome?;
    let sha256 = written?;
    Ok(Finished {
        reason,
        counters: counters.snapshot(),
        sha256,
    })
}
