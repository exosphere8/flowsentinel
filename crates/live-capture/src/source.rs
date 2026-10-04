//! Where packets come from.

/// One captured packet. `data` holds at most the snapshot length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePacket {
    /// Seconds since the Unix epoch.
    pub ts_seconds: u32,
    /// Microseconds within the second (0-999,999).
    pub ts_micros: u32,
    /// Length of the packet on the wire.
    pub original_length: u32,
    pub data: Vec<u8>,
}

/// What a source produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    Packet(SourcePacket),
    /// Nothing is waiting; ask again.
    Idle,
    /// The source has no more packets (replay sources only).
    End,
}

/// Packets the source lost, as reported by the operating system.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceStats {
    /// Dropped because the kernel buffer was full.
    pub kernel_dropped: u64,
    /// Dropped by the interface or its driver.
    pub interface_dropped: u64,
}

/// An open packet source. Implementations must return from
/// [`next_packet`](Self::next_packet) within a fraction of a second even
/// when no packet arrives, so stop requests and time limits are noticed.
pub trait PacketSource: Send {
    /// The pcap link-layer type number (1 for Ethernet).
    fn link_type(&self) -> u32;
    fn snaplen(&self) -> u32;
    fn next_packet(&mut self) -> Result<Next, SourceError>;
    fn stats(&mut self) -> SourceStats {
        SourceStats::default()
    }
}

/// A network interface that can be captured on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub loopback: bool,
    pub up: bool,
}

/// How to open a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    pub interface: String,
    /// BPF filter text, already checked with [`crate::bpf::check_text`].
    pub filter: String,
    /// Off unless explicitly requested.
    pub promiscuous: bool,
    pub snaplen: u32,
}

/// Lists interfaces and opens sources.
pub trait SourceFactory: Send + Sync {
    /// Whether live capture is possible at all in this build.
    fn available(&self) -> bool {
        true
    }
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, SourceError>;
    /// Compiles a filter without capturing, so a bad one is refused early.
    fn check_filter(&self, filter: &str) -> Result<(), SourceError>;
    fn open(&self, request: &OpenRequest) -> Result<Box<dyn PacketSource>, SourceError>;
}

/// Source errors, with a stable [`code`](Self::code).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    #[error(
        "live capture is not available in this build; build the server with \
         `--features live-capture` and libpcap"
    )]
    Unavailable,
    #[error(
        "the server is not permitted to capture on this interface; grant it the \
         capture capability as described in docs/permissions.md (never run it as root)"
    )]
    PermissionDenied,
    #[error("no interface named {0:?}")]
    NoSuchInterface(String),
    #[error("invalid capture filter: {0}")]
    InvalidFilter(String),
    #[error("capture failed: {0}")]
    Failed(String),
}

impl SourceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unavailable => "live_capture_unavailable",
            Self::PermissionDenied => "capture_permission_denied",
            Self::NoSuchInterface(_) => "unknown_interface",
            Self::InvalidFilter(_) => "invalid_capture_filter",
            Self::Failed(_) => "capture_failed",
        }
    }
}

/// Longest message kept from libpcap or the operating system.
pub const MAX_MESSAGE_CHARS: usize = 200;

/// Cuts an external message and removes control characters.
pub fn clean_message(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_MESSAGE_CHARS)
        .collect()
}

/// The factory of a build without libpcap.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unavailable;

impl SourceFactory for Unavailable {
    fn available(&self) -> bool {
        false
    }

    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, SourceError> {
        Err(SourceError::Unavailable)
    }

    fn check_filter(&self, _filter: &str) -> Result<(), SourceError> {
        Err(SourceError::Unavailable)
    }

    fn open(&self, _request: &OpenRequest) -> Result<Box<dyn PacketSource>, SourceError> {
        Err(SourceError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_messages_are_cleaned() {
        assert_eq!(clean_message("syntax error\n\u{7}"), "syntax error");
        assert_eq!(clean_message(&"x".repeat(500)).len(), MAX_MESSAGE_CHARS);
    }

    #[test]
    fn unavailable_builds_say_so() {
        let factory = Unavailable;
        assert!(!factory.available());
        assert_eq!(
            factory.interfaces().unwrap_err().code(),
            "live_capture_unavailable"
        );
        assert!(
            SourceError::PermissionDenied
                .to_string()
                .contains("docs/permissions.md")
        );
    }
}
