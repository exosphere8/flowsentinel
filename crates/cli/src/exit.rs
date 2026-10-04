//! Process exit codes shared by all subcommands.

use std::process::ExitCode;

use capture::ErrorCategory;

/// Command-line usage error, emitted by `clap` itself, and an invalid
/// `detect --config` file.
pub const USAGE: u8 = 2;
/// The input was rejected: wrong path, type, extension, format or size.
pub const INPUT: u8 = 3;
/// The capture file is malformed.
pub const MALFORMED: u8 = 4;
/// An I/O error occurred, including failure to write output.
pub const IO: u8 = 5;

/// Exit code for a capture error category.
pub fn for_category(category: ErrorCategory) -> ExitCode {
    ExitCode::from(match category {
        ErrorCategory::Input => INPUT,
        ErrorCategory::Malformed => MALFORMED,
        ErrorCategory::Io => IO,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_distinct() {
        let codes = [USAGE, INPUT, MALFORMED, IO];
        for (i, a) in codes.iter().enumerate() {
            for b in &codes[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
