//! Capture sessions with replay sources: limits, stopping, backpressure,
//! failures, and files that the offline reader reads back exactly.

use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use capture::PcapReader;
use live_capture::session::{self, CHANNEL_CAPACITY};
use live_capture::{
    LiveError, LiveLimits, Next, PacketSource, ReplaySource, SourceError, SourcePacket, StopReason,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pcap")
        .join(name)
}

const ROOMY: LiveLimits = LiveLimits {
    max_packets: 1_000_000,
    max_bytes: 512 * 1024 * 1024,
    max_duration: Duration::from_secs(60),
    snaplen: 262_144,
};

fn replay(name: &str, repeats: u32, pace: Option<Duration>) -> Box<dyn PacketSource> {
    Box::new(ReplaySource::open(&fixture(name), 262_144, repeats, pace).unwrap())
}

/// Every record of a pcap file: (captured bytes, original length).
fn records(path: &Path) -> Vec<(Vec<u8>, u32)> {
    let mut reader = PcapReader::new(BufReader::new(File::open(path).unwrap())).unwrap();
    let mut out = Vec::new();
    let mut data = Vec::new();
    while let Some(record) = reader.next_packet(&mut data).unwrap() {
        out.push((data.clone(), record.original_length));
    }
    out
}

#[test]
fn a_replayed_capture_is_written_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.pcap");
    let running = session::start(
        replay("detect-mixed.pcap", 0, None),
        ROOMY,
        File::create(&path).unwrap(),
    )
    .unwrap();
    let finished = running.join().unwrap();
    assert_eq!(finished.reason, StopReason::SourceEnded);
    let original = records(&fixture("detect-mixed.pcap"));
    let copy = records(&path);
    assert_eq!(copy, original);
    assert_eq!(finished.counters.written, 138);
    assert_eq!(finished.counters.seen, 138);
    assert_eq!(finished.counters.dropped_backpressure, 0);
    assert_eq!(
        finished.counters.bytes,
        std::fs::metadata(&path).unwrap().len()
    );
    assert_eq!(finished.sha256.len(), 64);
}

#[test]
fn captures_stop_at_the_first_limit() {
    let dir = tempfile::tempdir().unwrap();
    let packets = LiveLimits {
        max_packets: 10,
        ..ROOMY
    };
    let path = dir.path().join("packets.pcap");
    let finished = session::start(
        replay("detect-mixed.pcap", 5, None),
        packets,
        File::create(&path).unwrap(),
    )
    .unwrap()
    .join()
    .unwrap();
    assert_eq!(finished.reason, StopReason::PacketLimit);
    assert_eq!(records(&path).len(), 10);

    let bytes = LiveLimits {
        max_bytes: 2_000,
        ..ROOMY
    };
    let path = dir.path().join("bytes.pcap");
    let finished = session::start(
        replay("detect-mixed.pcap", 5, None),
        bytes,
        File::create(&path).unwrap(),
    )
    .unwrap()
    .join()
    .unwrap();
    assert_eq!(finished.reason, StopReason::ByteLimit);
    let size = std::fs::metadata(&path).unwrap().len();
    assert!(size <= 2_000 && size > 1_000, "{size}");
    assert_eq!(size, finished.counters.bytes);

    let time = LiveLimits {
        max_duration: Duration::from_millis(600),
        ..ROOMY
    };
    let started = Instant::now();
    let finished = session::start(
        replay("detect-mixed.pcap", 1_000, Some(Duration::from_millis(20))),
        time,
        io::sink(),
    )
    .unwrap()
    .join()
    .unwrap();
    assert_eq!(finished.reason, StopReason::TimeLimit);
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(600) && took < Duration::from_secs(5),
        "{took:?}"
    );
}

#[test]
fn a_capture_stops_when_asked() {
    let running = session::start(
        replay("detect-mixed.pcap", 1_000, Some(Duration::from_millis(5))),
        ROOMY,
        io::sink(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(running.counters().seen > 0);
    assert!(!running.is_finished());
    running.stop();
    let finished = running.join().unwrap();
    assert_eq!(finished.reason, StopReason::Requested);
}

/// A writer slower than the source.
struct Slow(Vec<u8>);

impl Write for Slow {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        std::thread::sleep(Duration::from_micros(200));
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_slow_writer_drops_packets_instead_of_queueing_them() {
    // 138 packets x 101 passes, read as fast as the CPU allows.
    let finished = session::start(
        replay("detect-mixed.pcap", 100, None),
        ROOMY,
        Slow(Vec::new()),
    )
    .unwrap()
    .join()
    .unwrap();
    let c = finished.counters;
    assert_eq!(c.seen, 138 * 101);
    assert!(c.dropped_backpressure > 0, "{c:?}");
    assert_eq!(c.seen, c.written + c.dropped_backpressure, "{c:?}");
    // The writer kept up with at least a channel's worth.
    assert!(c.written >= CHANNEL_CAPACITY as u64, "{c:?}");
}

/// A writer that fails after some bytes.
struct Failing(usize);

impl Write for Failing {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.0 < buf.len() {
            return Err(io::Error::other("disk full"));
        }
        self.0 -= buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_failing_writer_ends_the_capture_with_its_error() {
    let err = session::start(replay("detect-mixed.pcap", 100, None), ROOMY, Failing(4096))
        .unwrap()
        .join()
        .unwrap_err();
    assert_eq!(err, LiveError::Write("disk full".into()));
}

/// A source that fails after a few packets.
struct Broken(u32);

impl PacketSource for Broken {
    fn link_type(&self) -> u32 {
        1
    }

    fn snaplen(&self) -> u32 {
        65_535
    }

    fn next_packet(&mut self) -> Result<Next, SourceError> {
        if self.0 == 0 {
            return Err(SourceError::Failed("interface went down".into()));
        }
        self.0 -= 1;
        Ok(Next::Packet(SourcePacket {
            ts_seconds: 1,
            ts_micros: 0,
            original_length: 60,
            data: vec![0; 60],
        }))
    }
}

#[test]
fn a_source_error_ends_the_capture() {
    let err = session::start(Box::new(Broken(3)), ROOMY, Vec::new())
        .unwrap()
        .join()
        .unwrap_err();
    assert_eq!(
        err,
        LiveError::Source(SourceError::Failed("interface went down".into()))
    );
}

#[test]
fn the_snapshot_length_cuts_packets_but_keeps_their_wire_length() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap.pcap");
    let source = Box::new(ReplaySource::open(&fixture("detect-mixed.pcap"), 64, 0, None).unwrap());
    session::start(source, ROOMY, File::create(&path).unwrap())
        .unwrap()
        .join()
        .unwrap();
    let original = records(&fixture("detect-mixed.pcap"));
    let cut = records(&path);
    assert_eq!(cut.len(), original.len());
    for ((data, wire), (full, full_wire)) in cut.iter().zip(&original) {
        assert!(data.len() <= 64);
        assert_eq!(data.as_slice(), &full[..full.len().min(64)]);
        assert_eq!(wire, full_wire);
    }
}

/// Captures real loopback traffic. Needs the `libpcap` feature, capture
/// permission, and `FLOWSENTINEL_LIVE_TEST_INTERFACE` (for example `lo`).
#[cfg(feature = "libpcap")]
#[test]
fn captures_loopback_traffic_when_permitted() {
    use live_capture::SourceFactory;
    use live_capture::libpcap::LibpcapFactory;

    let Ok(interface) = std::env::var("FLOWSENTINEL_LIVE_TEST_INTERFACE") else {
        eprintln!("FLOWSENTINEL_LIVE_TEST_INTERFACE is not set; skipping");
        return;
    };
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = receiver.local_addr().unwrap().port();
    let source = LibpcapFactory
        .open(&live_capture::OpenRequest {
            interface,
            filter: format!("udp dst port {port}"),
            promiscuous: false,
            snaplen: 65_535,
        })
        .unwrap();
    let limits = LiveLimits {
        max_packets: 5,
        max_duration: Duration::from_secs(10),
        ..ROOMY
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lo.pcap");
    let running = session::start(source, limits, File::create(&path).unwrap()).unwrap();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    // Ordinary datagrams to our own socket: test traffic on loopback only.
    for _ in 0..5 {
        sender
            .send_to(b"flowsentinel live capture test", ("127.0.0.1", port))
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
    let finished = running.join().unwrap();
    assert_eq!(finished.reason, StopReason::PacketLimit);
    assert_eq!(records(&path).len(), 5);
}

/// An idle interface must not hold a capture open past its time limit or a
/// stop request: reads time out. Needs the same setup as the test above.
#[cfg(feature = "libpcap")]
#[test]
fn an_idle_interface_still_stops_on_time() {
    use live_capture::SourceFactory;
    use live_capture::libpcap::LibpcapFactory;

    let Ok(interface) = std::env::var("FLOWSENTINEL_LIVE_TEST_INTERFACE") else {
        eprintln!("FLOWSENTINEL_LIVE_TEST_INTERFACE is not set; skipping");
        return;
    };
    let open = || {
        LibpcapFactory
            .open(&live_capture::OpenRequest {
                interface: interface.clone(),
                // Matches nothing on loopback.
                filter: "udp dst port 9 and src host 192.0.2.99".to_owned(),
                promiscuous: false,
                snaplen: 65_535,
            })
            .unwrap()
    };
    let limits = LiveLimits {
        max_duration: Duration::from_secs(2),
        ..ROOMY
    };
    let started = Instant::now();
    let finished = session::start(open(), limits, io::sink())
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(finished.reason, StopReason::TimeLimit);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );

    let running = session::start(open(), ROOMY, io::sink()).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let asked = Instant::now();
    running.stop();
    let finished = running.join().unwrap();
    assert_eq!(finished.reason, StopReason::Requested);
    assert!(
        asked.elapsed() < Duration::from_secs(3),
        "{:?}",
        asked.elapsed()
    );
}

#[test]
fn an_empty_file_ends_the_replay_however_many_repeats() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.pcap");
    // The classic header alone: no packets.
    let mut header = Vec::new();
    for part in [
        0xa1b2_c3d4u32.to_le_bytes().to_vec(),
        2u16.to_le_bytes().to_vec(),
        4u16.to_le_bytes().to_vec(),
        vec![0; 8],
        65_535u32.to_le_bytes().to_vec(),
        1u32.to_le_bytes().to_vec(),
    ] {
        header.extend(part);
    }
    std::fs::write(&path, header).unwrap();
    let source = Box::new(ReplaySource::open(&path, 65_535, u32::MAX, None).unwrap());
    let finished = session::start(source, ROOMY, io::sink())
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(finished.reason, StopReason::SourceEnded);
    assert_eq!(finished.counters.seen, 0);
}
