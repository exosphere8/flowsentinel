//! `flowsentinel` command-line interface.
//!
//! Milestone 0 provides only `--version` and `--help`. Subcommands such as
//! `inspect` arrive in later milestones.

use std::process::ExitCode;

use clap::{CommandFactory, Parser};

/// Defensive, metadata-first network packet and flow analyzer.
///
/// Analyze only networks and traffic you own or are explicitly authorized
/// to inspect.
#[derive(Debug, Parser)]
#[command(name = "flowsentinel", bin_name = "flowsentinel", version)]
struct Cli {}

fn main() -> ExitCode {
    let _cli = Cli::parse();

    // No subcommands exist yet, so a bare invocation shows usage.
    match Cli::command().print_help() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: failed to write help: {err}");
            ExitCode::FAILURE
        }
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
}
