//! Runs the compiled `flowsentinel` binary end to end.

use std::process::{Command, Output};

fn flowsentinel(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_flowsentinel"))
        .args(args)
        .output()
        .expect("failed to run flowsentinel binary")
}

#[test]
fn version_prints_name_and_version() {
    let out = flowsentinel(&["--version"]);
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim_end(),
        format!("flowsentinel {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_describes_usage_and_authorized_use() {
    let out = flowsentinel(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Usage: flowsentinel"));
    assert!(stdout.contains("explicitly authorized"));
}

#[test]
fn bare_invocation_prints_usage() {
    let out = flowsentinel(&[]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Usage: flowsentinel"));
}

#[test]
fn unknown_flag_fails_with_usage_error() {
    let out = flowsentinel(&["--bogus"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unexpected argument"));
}
