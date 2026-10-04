//! Capture from network interfaces through libpcap (feature `libpcap`).
//!
//! Interfaces are opened with promiscuous mode off unless requested and the
//! requested snapshot length, in non-blocking mode: libpcap's read timeout
//! does not start on some platforms (Linux with TPACKET_V3) until a packet
//! arrives, so an idle interface would otherwise never return and a stop
//! request or time limit would go unnoticed. When nothing is waiting, the
//! source sleeps briefly instead. Filters are compiled by
//! libpcap without capturing first. Nothing is ever sent on the network.

use pcap::{Active, Capture, Device, Linktype};

use crate::bpf;
use crate::source::{
    InterfaceInfo, Next, OpenRequest, PacketSource, SourceError, SourceFactory, SourcePacket,
    SourceStats, clean_message,
};

/// Kernel-side batching timeout, in milliseconds.
const READ_TIMEOUT_MS: i32 = 100;
/// Pause when no packet is waiting.
const IDLE_SLEEP: std::time::Duration = std::time::Duration::from_millis(20);
/// Kernel buffer for one capture.
const BUFFER_BYTES: i32 = 4 * 1024 * 1024;

/// Maps libpcap's errors to [`SourceError`], recognizing missing privileges
/// by their message (libpcap reports them as text).
fn source_error(err: &pcap::Error) -> SourceError {
    let text = err.to_string();
    let lower = text.to_ascii_lowercase();
    if lower.contains("permission") || lower.contains("not permitted") {
        SourceError::PermissionDenied
    } else if lower.contains("no such device") {
        SourceError::NoSuchInterface(String::new())
    } else {
        SourceError::Failed(clean_message(&text))
    }
}

/// libpcap's view of the machine's interfaces.
#[derive(Debug, Clone, Copy, Default)]
pub struct LibpcapFactory;

impl SourceFactory for LibpcapFactory {
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, SourceError> {
        let devices = Device::list().map_err(|e| source_error(&e))?;
        Ok(devices
            .into_iter()
            .map(|device| InterfaceInfo {
                loopback: device.flags.is_loopback(),
                up: device.flags.is_up(),
                addresses: device
                    .addresses
                    .iter()
                    .map(|address| address.addr.to_string())
                    .collect(),
                description: device.desc.map(|d| clean_message(&d)),
                name: device.name,
            })
            .collect())
    }

    fn check_filter(&self, filter: &str) -> Result<(), SourceError> {
        bpf::check_text(filter).map_err(|e| SourceError::InvalidFilter(e.to_string()))?;
        if filter.is_empty() {
            return Ok(());
        }
        // A "dead" handle compiles filters without opening an interface or
        // needing privileges.
        let dead = Capture::dead(Linktype::ETHERNET).map_err(|e| source_error(&e))?;
        dead.compile(filter, true)
            .map(|_| ())
            .map_err(|e| SourceError::InvalidFilter(clean_message(&e.to_string())))
    }

    fn open(&self, request: &OpenRequest) -> Result<Box<dyn PacketSource>, SourceError> {
        let known = self
            .interfaces()?
            .into_iter()
            .any(|interface| interface.name == request.interface);
        if !known {
            return Err(SourceError::NoSuchInterface(request.interface.clone()));
        }
        let snaplen = i32::try_from(request.snaplen).unwrap_or(i32::MAX);
        let mut capture = Capture::from_device(request.interface.as_str())
            .map_err(|e| source_error(&e))?
            .promisc(request.promiscuous)
            .snaplen(snaplen)
            .timeout(READ_TIMEOUT_MS)
            .buffer_size(BUFFER_BYTES)
            .open()
            .map_err(|e| match source_error(&e) {
                SourceError::NoSuchInterface(_) => {
                    SourceError::NoSuchInterface(request.interface.clone())
                }
                other => other,
            })?
            .setnonblock()
            .map_err(|e| source_error(&e))?;
        if !request.filter.is_empty() {
            capture
                .filter(&request.filter, true)
                .map_err(|e| SourceError::InvalidFilter(clean_message(&e.to_string())))?;
        }
        let link_type = u32::try_from(capture.get_datalink().0).unwrap_or(0);
        Ok(Box::new(LibpcapSource {
            capture,
            link_type,
            snaplen: request.snaplen,
        }))
    }
}

/// An open interface.
pub struct LibpcapSource {
    capture: Capture<Active>,
    link_type: u32,
    snaplen: u32,
}

impl PacketSource for LibpcapSource {
    fn link_type(&self) -> u32 {
        self.link_type
    }

    fn snaplen(&self) -> u32 {
        self.snaplen
    }

    fn next_packet(&mut self) -> Result<Next, SourceError> {
        match self.capture.next_packet() {
            Ok(packet) => {
                let ts = packet.header.ts;
                // `timeval` fields are 32-bit on Windows and (tv_usec) macOS.
                #[allow(clippy::useless_conversion)]
                let (seconds, micros) = (i64::from(ts.tv_sec), i64::from(ts.tv_usec));
                Ok(Next::Packet(SourcePacket {
                    ts_seconds: u32::try_from(seconds).unwrap_or(0),
                    ts_micros: u32::try_from(micros).unwrap_or(0).min(999_999),
                    original_length: packet.header.len,
                    data: packet.data.to_vec(),
                }))
            }
            Err(pcap::Error::TimeoutExpired) => {
                std::thread::sleep(IDLE_SLEEP);
                Ok(Next::Idle)
            }
            Err(pcap::Error::NoMorePackets) => Ok(Next::End),
            Err(err) => Err(source_error(&err)),
        }
    }

    fn stats(&mut self) -> SourceStats {
        self.capture
            .stats()
            .map(|stat| SourceStats {
                kernel_dropped: u64::from(stat.dropped),
                interface_dropped: u64::from(stat.if_dropped),
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_are_compiled_without_capturing() {
        let factory = LibpcapFactory;
        assert!(factory.check_filter("").is_ok());
        assert!(
            factory
                .check_filter("tcp port 443 and not host 192.0.2.1")
                .is_ok()
        );
        assert!(
            factory
                .check_filter("udp and (port 53 or port 5353)")
                .is_ok()
        );
        for bad in ["tcp port", "host 999.1.1.1", "nonsense words", "port 99999"] {
            let err = factory.check_filter(bad).unwrap_err();
            assert_eq!(err.code(), "invalid_capture_filter", "{bad}");
        }
        assert_eq!(
            factory.check_filter("tcp\nport 80").unwrap_err().code(),
            "invalid_capture_filter"
        );
    }

    #[test]
    fn permission_errors_are_recognized() {
        let err = source_error(&pcap::Error::PcapError(
            "eth0: You don't have permission to perform this capture on that device".into(),
        ));
        assert_eq!(err, SourceError::PermissionDenied);
        let err = source_error(&pcap::Error::PcapError(
            "socket: Operation not permitted".into(),
        ));
        assert_eq!(err, SourceError::PermissionDenied);
        let err = source_error(&pcap::Error::PcapError("something else\n".into()));
        assert_eq!(
            err,
            SourceError::Failed("libpcap error: something else".into())
        );
    }
}
