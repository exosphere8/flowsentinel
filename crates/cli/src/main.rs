//! `flowsentinel` command-line interface.

mod decode_view;
mod exit;
mod flows;
mod inspect;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use capture::CaptureLimits;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use flow_engine::FlowConfig;

/// Defensive, metadata-first network packet and flow analyzer.
///
/// Analyze only networks and traffic you own or are explicitly authorized
/// to inspect.
#[derive(Debug, Parser)]
#[command(name = "flowsentinel", bin_name = "flowsentinel", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect an offline classic PCAP file and print metadata only.
    ///
    /// Reads the PCAP global header and per-record headers. With --decode,
    /// also decodes Ethernet, ARP, IPv4, IPv6, ICMP, ICMPv6, TCP and UDP
    /// headers, plus DNS, DHCP, HTTP/1.x and visible TLS handshake metadata.
    /// Packet contents are never printed; credentials are redacted.
    ///
    /// Exit codes: 0 success (including partial results at a limit),
    /// 2 usage error, 3 rejected input, 4 malformed capture, 5 I/O error.
    Inspect(InspectArgs),

    /// Reconstruct bidirectional flows from an offline classic PCAP file.
    ///
    /// Decodes every packet, groups both directions of each conversation
    /// into one flow and prints per-flow statistics and application
    /// metadata. Packet contents are never printed. Memory is bounded by
    /// --max-active-flows and --max-flows.
    ///
    /// Exit codes: 0 success (including partial results at a limit),
    /// 2 usage error, 3 rejected input, 4 malformed capture, 5 I/O error.
    Flows(FlowsArgs),
}

/// Input file and processing limits shared by every command.
#[derive(Debug, Args)]
struct CaptureArgs {
    /// Classic libpcap (.pcap) file you are authorized to analyze.
    #[arg(long, value_name = "PATH")]
    pcap: PathBuf,

    /// Reject files larger than this many MiB (1-65536).
    #[arg(
        long,
        value_name = "MB",
        default_value_t = CaptureLimits::DEFAULT_MAX_FILE_SIZE_MB,
        value_parser = clap::value_parser!(u64).range(CaptureLimits::MAX_FILE_SIZE_MB_RANGE),
    )]
    max_file_size_mb: u64,

    /// Stop after this many packets (1-1000000); the result is marked partial.
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = CaptureLimits::DEFAULT_MAX_PACKETS,
        value_parser = clap::value_parser!(u64).range(CaptureLimits::MAX_PACKETS_RANGE),
    )]
    max_packets: u64,

    /// Stop after this many seconds of processing (1-3600); the result is
    /// marked partial.
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = CaptureLimits::DEFAULT_MAX_DURATION_SECONDS,
        value_parser = clap::value_parser!(u64).range(CaptureLimits::MAX_DURATION_SECONDS_RANGE),
    )]
    max_duration_seconds: u64,
}

impl CaptureArgs {
    fn limits(&self) -> CaptureLimits {
        CaptureLimits::from_cli_units(
            self.max_file_size_mb,
            self.max_packets,
            self.max_duration_seconds,
        )
    }
}

#[derive(Debug, Args)]
struct InspectArgs {
    #[command(flatten)]
    capture: CaptureArgs,

    /// Decode protocol headers (Ethernet, ARP, IPv4, IPv6, ICMP, ICMPv6, TCP,
    /// UDP) and application metadata (DNS, DHCP, HTTP/1.x, TLS handshakes).
    /// Payloads are measured, never shown. The file is read twice so memory
    /// stays constant; --max-duration-seconds limits the first pass.
    #[arg(long)]
    decode: bool,

    /// With --decode, print each packet's protocol tree and decode warnings.
    #[arg(long, requires = "decode")]
    verbose: bool,

    /// Print one JSON object on stdout instead of tables. Capture errors are
    /// also printed as JSON on stdout; invalid options are reported as text
    /// on stderr.
    #[arg(long)]
    json: bool,
}

impl InspectArgs {
    fn limits(&self) -> CaptureLimits {
        self.capture.limits()
    }
}

/// Order of the flow list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FlowSort {
    /// By first packet (flow ID).
    Start,
    /// Most bytes first.
    Bytes,
    /// Most packets first.
    Packets,
    /// Longest first.
    Duration,
}

#[derive(Debug, Args)]
struct FlowsArgs {
    #[command(flatten)]
    capture: CaptureArgs,

    /// Most flows tracked at once (1-1000000). When the table is full the
    /// least recently seen flow is ended early ("evicted").
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = FlowConfig::DEFAULT_MAX_ACTIVE_FLOWS as u64,
        value_parser = clap::value_parser!(u64).range(1..=1_000_000),
    )]
    max_active_flows: u64,

    /// Most finished flows listed (1-1000000); further flows are counted
    /// but not listed.
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = FlowConfig::DEFAULT_MAX_RETAINED_FLOWS as u64,
        value_parser = clap::value_parser!(u64).range(1..=1_000_000),
    )]
    max_flows: u64,

    /// Idle timeout for open TCP flows, in seconds (1-86400).
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = FlowConfig::DEFAULT_TCP_IDLE_SECONDS,
        value_parser = clap::value_parser!(u64).range(1..=86_400),
    )]
    tcp_idle_timeout_seconds: u64,

    /// Idle timeout for UDP, ICMP and other flows, in seconds (1-86400).
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = FlowConfig::DEFAULT_IDLE_SECONDS,
        value_parser = clap::value_parser!(u64).range(1..=86_400),
    )]
    idle_timeout_seconds: u64,

    /// Order of the flow list.
    #[arg(long, value_enum, default_value_t = FlowSort::Start)]
    sort: FlowSort,

    /// Print one JSON object on stdout instead of tables. Capture errors are
    /// also printed as JSON on stdout; invalid options are reported as text
    /// on stderr.
    #[arg(long)]
    json: bool,
}

impl FlowsArgs {
    fn flow_config(&self) -> FlowConfig {
        FlowConfig {
            max_active_flows: usize::try_from(self.max_active_flows).unwrap_or(usize::MAX),
            max_retained_flows: usize::try_from(self.max_flows).unwrap_or(usize::MAX),
            tcp_idle_timeout: Duration::from_secs(self.tcp_idle_timeout_seconds),
            idle_timeout: Duration::from_secs(self.idle_timeout_seconds),
            ..FlowConfig::default()
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Inspect(args)) => inspect::run(&args),
        Some(Command::Flows(args)) => flows::run(&args),
        None => match Cli::command().print_help() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                inspect::report_to_stderr(&format!("error: failed to write help: {err}"));
                ExitCode::FAILURE
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn version_flag_displays_version() {
        let err = Cli::try_parse_from(["flowsentinel", "--version"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
    }

    #[test]
    fn help_flag_displays_help() {
        let err = Cli::try_parse_from(["flowsentinel", "--help"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayHelp);
    }

    #[test]
    fn unknown_argument_is_rejected() {
        let err = Cli::try_parse_from(["flowsentinel", "--capture-everything"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }

    fn inspect_args(extra: &[&str]) -> Result<InspectArgs, clap::Error> {
        let mut argv = vec!["flowsentinel", "inspect"];
        argv.extend_from_slice(extra);
        match Cli::try_parse_from(argv)?.command {
            Some(Command::Inspect(args)) => Ok(args),
            _ => panic!("expected inspect"),
        }
    }

    #[test]
    fn inspect_defaults_match_library_defaults() {
        let args = inspect_args(&["--pcap", "a.pcap"]).unwrap();
        assert_eq!(args.limits(), CaptureLimits::default());
        assert!(!args.json);
    }

    #[test]
    fn verbose_requires_decode() {
        let err = inspect_args(&["--pcap", "a.pcap", "--verbose"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        let args = inspect_args(&["--pcap", "a.pcap", "--decode", "--verbose", "--json"]).unwrap();
        assert!(args.decode && args.verbose && args.json);
    }

    #[test]
    fn inspect_requires_pcap() {
        let err = inspect_args(&[]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn inspect_limits_are_range_checked() {
        for bad in [
            ["--max-file-size-mb", "0"],
            ["--max-file-size-mb", "65537"],
            ["--max-packets", "0"],
            ["--max-packets", "1000001"],
            ["--max-duration-seconds", "0"],
            ["--max-duration-seconds", "3601"],
            ["--max-packets", "-5"],
            ["--max-packets", "ten"],
        ] {
            let mut argv = vec!["--pcap", "a.pcap"];
            argv.extend_from_slice(&bad);
            assert!(inspect_args(&argv).is_err(), "{bad:?} should be rejected");
        }
        let ok = inspect_args(&[
            "--pcap",
            "a.pcap",
            "--max-file-size-mb",
            "65536",
            "--max-packets",
            "1000000",
            "--max-duration-seconds",
            "3600",
        ]);
        assert!(ok.is_ok());
    }
}
