//! A packet source that replays a classic pcap file, for tests and
//! demonstrations without network access or capture privileges. It applies
//! no capture filter.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::Duration;

use capture::PcapReader;

use crate::bpf;
use crate::source::{
    InterfaceInfo, Next, OpenRequest, PacketSource, SourceError, SourceFactory, SourcePacket,
};

/// Replays the packets of a file, optionally several times and paced.
pub struct ReplaySource {
    path: PathBuf,
    reader: PcapReader<BufReader<File>>,
    link_type: u32,
    snaplen: u32,
    /// Further passes over the file after this one.
    repeats_left: u32,
    pace: Option<Duration>,
    buffer: Vec<u8>,
    /// Packets read in the current pass; an empty file ends the replay.
    this_pass: u64,
}

fn open_reader(path: &Path) -> Result<PcapReader<BufReader<File>>, SourceError> {
    let file = File::open(path).map_err(|e| SourceError::Failed(e.to_string()))?;
    PcapReader::new(BufReader::new(file)).map_err(|e| SourceError::Failed(e.to_string()))
}

impl ReplaySource {
    /// Replays `path` `1 + repeats` times, keeping at most `snaplen` bytes of
    /// each packet and sleeping `pace` before each one.
    pub fn open(
        path: &Path,
        snaplen: u32,
        repeats: u32,
        pace: Option<Duration>,
    ) -> Result<Self, SourceError> {
        let reader = open_reader(path)?;
        let link_type = u32::from(reader.header().link_type.0);
        Ok(Self {
            path: path.to_owned(),
            reader,
            link_type,
            snaplen,
            repeats_left: repeats,
            pace,
            buffer: Vec::new(),
            this_pass: 0,
        })
    }
}

impl PacketSource for ReplaySource {
    fn link_type(&self) -> u32 {
        self.link_type
    }

    fn snaplen(&self) -> u32 {
        self.snaplen
    }

    fn next_packet(&mut self) -> Result<Next, SourceError> {
        loop {
            let record = self
                .reader
                .next_packet(&mut self.buffer)
                .map_err(|e| SourceError::Failed(e.to_string()))?;
            let Some(record) = record else {
                if self.repeats_left == 0 || self.this_pass == 0 {
                    return Ok(Next::End);
                }
                self.repeats_left -= 1;
                self.this_pass = 0;
                self.reader = open_reader(&self.path)?;
                continue;
            };
            self.this_pass += 1;
            if let Some(pace) = self.pace {
                std::thread::sleep(pace);
            }
            let nanos = record.timestamp.map_or(0, |ts| ts.as_unix_nanos());
            let keep = usize::try_from(self.snaplen).unwrap_or(usize::MAX);
            self.buffer.truncate(keep);
            return Ok(Next::Packet(SourcePacket {
                ts_seconds: u32::try_from(nanos / 1_000_000_000).unwrap_or(0),
                ts_micros: u32::try_from((nanos % 1_000_000_000) / 1_000).unwrap_or(0),
                original_length: record.original_length,
                data: std::mem::take(&mut self.buffer),
            }));
        }
    }
}

/// Offers one pretend interface that replays a file.
#[derive(Debug, Clone)]
pub struct ReplayFactory {
    pub interface: String,
    pub path: PathBuf,
    pub repeats: u32,
    pub pace: Option<Duration>,
}

impl SourceFactory for ReplayFactory {
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, SourceError> {
        Ok(vec![InterfaceInfo {
            name: self.interface.clone(),
            description: Some("replays a capture file".to_owned()),
            addresses: Vec::new(),
            loopback: false,
            up: true,
        }])
    }

    fn check_filter(&self, filter: &str) -> Result<(), SourceError> {
        bpf::check_text(filter).map_err(|e| SourceError::InvalidFilter(e.to_string()))
    }

    fn open(&self, request: &OpenRequest) -> Result<Box<dyn PacketSource>, SourceError> {
        if request.interface != self.interface {
            return Err(SourceError::NoSuchInterface(request.interface.clone()));
        }
        Ok(Box::new(ReplaySource::open(
            &self.path,
            request.snaplen,
            self.repeats,
            self.pace,
        )?))
    }
}
