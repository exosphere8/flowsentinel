//! `flowsentinel` command-line interface.

mod decode_view;
mod exit;
mod inspect;

use std::path::PathBuf;
use std::process::ExitCode;

use capture::CaptureLimits;
use clap::{Args, CommandFactory, Parser, Subcommand};

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
    /// headers. Packet contents are never printed.
    ///
    /// Exit codes: 0 success (including partial results at a limit),
    /// 2 usage error, 3 rejected input, 4 malformed capture, 5 I/O error.
    Inspect(InspectArgs),
}

#[derive(Debug, Args)]
struct InspectArgs {
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

    /// Decode protocol headers (Ethernet, ARP, IPv4, IPv6, ICMP, ICMPv6, TCP,
    /// UDP) into metadata. Payloads are measured, never shown.
    #[arg(long)]
    decode: bool,

    /// With --decode, print each packet's protocol tree and decode warnings.
    #[arg(long, requires = "decode")]
    verbose: bool,

    /// Print one JSON object on stdout instead of tables. Errors are also
    /// printed as JSON on stdout.
    #[arg(long)]
    json: bool,
}

impl InspectArgs {
    fn limits(&self) -> CaptureLimits {
        CaptureLimits::from_cli_units(
            self.max_file_size_mb,
            self.max_packets,
            self.max_duration_seconds,
        )
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Inspect(args)) => inspect::run(&args),
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
            None => panic!("expected inspect"),
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
