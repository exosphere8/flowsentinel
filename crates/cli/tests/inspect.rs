//! Runs `flowsentinel inspect` end to end against the committed fixtures.

use std::path::PathBuf;
use std::process::{Command, Output};

/// Must match PAYLOAD_MARKER in scripts/generate_pcap_fixtures.py.
const PAYLOAD_MARKER: &str = "FLOWSENTINEL-SYNTHETIC-PAYLOAD-MARKER";

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pcap")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn inspect(name: &str, extra: &[&str]) -> Output {
    let path = fixture(name);
    let mut args = vec!["inspect", "--pcap", path.as_str()];
    args.extend_from_slice(extra);
    Command::new(env!("CARGO_BIN_EXE_flowsentinel"))
        .args(&args)
        .output()
        .expect("failed to run flowsentinel binary")
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).expect("stderr is UTF-8")
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).expect("stdout is one JSON value")
}

#[test]
fn human_output_shows_summary_and_packet_table() {
    let out = inspect("le-usec.pcap", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("Capture summary"));
    assert!(text.contains("le-usec.pcap (309 bytes)"));
    assert!(text.contains("pcap 2.4, little-endian, microsecond timestamps"));
    assert!(text.contains("Packets processed  3"));
    assert!(text.contains("Completion         complete"));
    assert!(text.contains("Limits             512 MiB, 100000 packets, 60 s"));
    assert!(text.contains("2026-01-01T00:00:00.500000Z"));
    assert!(stderr(&out).is_empty());
}

#[test]
fn json_output_is_a_single_metadata_object() {
    let out = inspect("be-nsec.pcap", &["--json"]);
    assert_eq!(out.status.code(), Some(0));
    let value = json(&out);
    assert_eq!(value["summary"]["header"]["endianness"], "big");
    assert_eq!(
        value["summary"]["header"]["timestamp_resolution"],
        "nanosecond"
    );
    assert_eq!(value["summary"]["packets_processed"], 3);
    assert_eq!(value["completion_state"], "complete");
    assert_eq!(
        value["packets"][1]["timestamp"]["rfc3339"],
        "2026-01-01T00:00:00.250000000Z"
    );
    assert_eq!(value["packets"].as_array().map(Vec::len), Some(3));
    // No packet record exposes anything beyond the documented fields.
    let keys: Vec<_> = value["packets"][0]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        keys,
        [
            "captured_length",
            "file_offset",
            "index",
            "original_length",
            "timestamp"
        ]
    );
}

#[test]
fn no_output_mode_ever_contains_payload() {
    for name in [
        "le-usec.pcap",
        "be-usec.pcap",
        "many-packets.pcap",
        "record-warnings.pcap",
    ] {
        for extra in [&[][..], &["--json"][..]] {
            let out = inspect(name, extra);
            assert!(!stdout(&out).contains(PAYLOAD_MARKER), "{name} {extra:?}");
            assert!(!stderr(&out).contains(PAYLOAD_MARKER), "{name} {extra:?}");
        }
    }
}

#[test]
fn packet_limit_is_partial_success() {
    let out = inspect("many-packets.pcap", &["--max-packets", "5", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let value = json(&out);
    assert_eq!(value["completion_state"], "packet_limit_reached");
    assert_eq!(value["summary"]["packets_processed"], 5);
    assert_eq!(value["summary"]["limits"]["max_packets"], 5);

    let text = stdout(&inspect("many-packets.pcap", &["--max-packets", "5"]));
    assert!(text.contains("partial (packet limit reached)"));
}

#[test]
fn warnings_are_listed() {
    let value = json(&inspect("record-warnings.pcap", &["--json"]));
    let codes: Vec<_> = value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap().to_owned())
        .collect();
    assert!(codes.contains(&"timestamp_out_of_order".to_owned()));
    assert_eq!(value["packets"][3]["timestamp"], serde_json::Value::Null);
}

#[test]
fn errors_map_to_exit_codes() {
    let cases = [
        ("missing.pcap", 3, "missing_path"),
        ("minimal.pcapng", 3, "pcapng_not_supported"),
        ("pcapng-content.pcap", 3, "unsupported_format"),
        ("invalid-magic.pcap", 4, "invalid_magic"),
        ("truncated-global-header.pcap", 4, "truncated_global_header"),
        ("bad-version.pcap", 4, "invalid_version"),
        ("bad-version-minor.pcap", 4, "invalid_version"),
        ("zero-snaplen.pcap", 4, "invalid_snap_length"),
        ("reserved-linktype-bits.pcap", 4, "corrupt_global_header"),
        ("truncated-record-header.pcap", 4, "truncated_record_header"),
        ("truncated-record-data.pcap", 4, "truncated_record_data"),
        ("huge-captured-length.pcap", 4, "unsafe_captured_length"),
    ];
    for (name, exit_code, code) in cases {
        let human = inspect(name, &[]);
        assert_eq!(human.status.code(), Some(exit_code), "{name}");
        assert!(stdout(&human).is_empty(), "{name}: errors go to stderr");
        assert!(stderr(&human).starts_with("error: "), "{name}");

        let machine = inspect(name, &["--json"]);
        assert_eq!(machine.status.code(), Some(exit_code), "{name}");
        let value = json(&machine);
        assert_eq!(value["error"]["code"], code, "{name}");
        assert!(
            stderr(&machine).is_empty(),
            "{name}: JSON errors go to stdout"
        );
    }
}

#[test]
fn errors_name_the_file_but_not_its_directory() {
    let out = inspect("missing.pcap", &[]);
    let message = stderr(&out);
    assert!(message.contains("missing.pcap"));
    assert!(!message.contains("fixtures"));
}

#[test]
fn directory_is_rejected() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pcap");
    let out = Command::new(env!("CARGO_BIN_EXE_flowsentinel"))
        .args(["inspect", "--pcap"])
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(stderr(&out).contains("not a regular file"));
}

#[test]
fn file_size_limit_is_enforced_before_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.pcap");
    std::fs::write(&path, vec![0u8; 1024 * 1024 + 1]).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_flowsentinel"))
        .args(["inspect", "--json", "--max-file-size-mb", "1", "--pcap"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(json(&out)["error"]["code"], "file_too_large");
}

#[test]
fn out_of_range_limits_are_usage_errors() {
    for args in [
        ["--max-packets", "0"],
        ["--max-file-size-mb", "70000"],
        ["--max-duration-seconds", "0"],
    ] {
        let out = inspect("le-usec.pcap", &args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn usage_errors_are_plain_text_even_with_json() {
    let out = inspect("le-usec.pcap", &["--json", "--max-packets", "0"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stdout(&out).is_empty());
    assert!(stderr(&out).contains("--max-packets"));
}
