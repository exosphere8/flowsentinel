//! Runs `flowsentinel detect` end to end against the fixtures in fixtures/pcap.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const PAYLOAD_MARKER: &str = "FLOWSENTINEL-SYNTHETIC-PAYLOAD-MARKER";
const SECRET_MARKER: &str = "FLOWSENTINEL-SECRET";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pcap")
        .join(name)
}

fn run(pcap: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_flowsentinel"))
        .arg("detect")
        .arg("--pcap")
        .arg(pcap)
        .args(extra)
        .output()
        .expect("failed to run flowsentinel binary")
}

fn json(extra: &[&str]) -> Value {
    let mut args = vec!["--json"];
    args.extend_from_slice(extra);
    let out = run(&fixture("detect-mixed.pcap"), &args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("one JSON object")
}

fn rule_ids(report: &Value) -> Vec<String> {
    report["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["rule_id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn finds_the_planted_patterns_and_explains_them() {
    let r = json(&[]);
    assert_eq!(
        rule_ids(&r),
        [
            "FS-SCAN-SYN",
            "FS-BEACON",
            "FS-CLEARTEXT",
            "FS-DNS-TUNNEL",
            "FS-ARP-CONFLICT"
        ]
    );
    assert!(
        r["nature"]
            .as_str()
            .unwrap()
            .contains("heuristic indicator")
    );
    let summary = &r["detection_summary"];
    assert_eq!(summary["alerts_total"], 5);
    assert_eq!(summary["flows_evaluated"], 47);
    for (i, alert) in r["alerts"].as_array().unwrap().iter().enumerate() {
        assert_eq!(alert["alert_id"], i + 1);
        assert_eq!(alert["status"], "open");
        assert!(!alert["evidence"].as_array().unwrap().is_empty());
        assert!(!alert["explanation"].as_str().unwrap().is_empty());
        assert!(
            !alert["likely_false_positives"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let cited = alert["related_flow_ids"].as_array().unwrap().len()
            + alert["related_packet_indexes"].as_array().unwrap().len();
        assert!(cited > 0, "{alert}");
    }
    let scan = &r["alerts"][0];
    assert_eq!(scan["source"], "192.0.2.66");
    assert_eq!(scan["related_flow_ids"].as_array().unwrap().len(), 25);
}

#[test]
fn human_output_says_alerts_are_indicators() {
    let out = run(&fixture("detect-mixed.pcap"), &[]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Alerts             5"), "{text}");
    assert!(text.contains("not proof of compromise"));
    assert!(text.contains("[1] Possible SYN scan (FS-SCAN-SYN)"));
    assert!(text.contains("Benign causes"));
    for forbidden in ["malware detected", "compromised", "attack detected"] {
        assert!(
            !text.to_ascii_lowercase().contains(forbidden),
            "{forbidden}"
        );
    }
}

#[test]
fn quiet_traffic_raises_nothing() {
    let out = run(&fixture("flows-mixed.pcap"), &["--json"]);
    assert_eq!(out.status.code(), Some(0));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["detection_summary"]["alerts_total"], 0);
    assert_eq!(r["alerts"], serde_json::json!([]));
    let out = run(&fixture("flows-mixed.pcap"), &[]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("No alerts."), "{text}");
}

#[test]
fn thresholds_come_from_the_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("detection.toml");
    std::fs::write(
        &path,
        "[beaconing]\nenabled = false\n\n[syn_scan]\nmin_ports = 30\n",
    )
    .unwrap();
    let r = json(&["--config", path.to_str().unwrap()]);
    assert_eq!(
        rule_ids(&r),
        ["FS-CLEARTEXT", "FS-DNS-TUNNEL", "FS-ARP-CONFLICT"]
    );
}

#[test]
fn invalid_configs_are_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    let cases = [
        (
            "unknown.toml",
            "[syn_scan]\nmin_portz = 3\n".to_owned(),
            "min_portz",
        ),
        (
            "range.toml",
            "[beaconing]\nmin_connections = 0\n".to_owned(),
            "beaconing.min_connections",
        ),
        (
            "cidr.toml",
            "internal_networks = [\"10.0.0.0/33\"]\n".to_owned(),
            "internal_networks",
        ),
        (
            "big.toml",
            format!("# {}\n", "x".repeat(70_000)),
            "larger than",
        ),
    ];
    for (name, text, expected) in cases {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        let out = run(
            &fixture("detect-mixed.pcap"),
            &["--json", "--config", path.to_str().unwrap()],
        );
        assert_eq!(out.status.code(), Some(2), "{name}");
        assert!(out.stdout.is_empty(), "{name}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains(expected), "{name}: {stderr}");
        // Only the file's name is shown, not the directory.
        assert!(stderr.contains(name), "{name}: {stderr}");
        assert!(!stderr.contains(dir.path().to_str().unwrap()), "{stderr}");
    }
    let missing = dir.path().join("missing.toml");
    let out = run(
        &fixture("detect-mixed.pcap"),
        &["--config", missing.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn capture_errors_keep_their_exit_codes() {
    let out = run(&fixture("invalid-magic.pcap"), &["--json"]);
    assert_eq!(out.status.code(), Some(4));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(r["error"]["code"].is_string(), "{r}");
    let out = run(&fixture("does-not-exist.pcap"), &[]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn output_never_contains_payload_or_secrets() {
    for name in [
        "detect-mixed.pcap",
        "app-http.pcap",
        "app-dns.pcap",
        "app-tls.pcap",
    ] {
        for extra in [&["--json"][..], &[][..]] {
            let out = run(&fixture(name), extra);
            assert_eq!(out.status.code(), Some(0), "{name}");
            let text = String::from_utf8_lossy(&out.stdout).to_ascii_uppercase();
            assert!(!text.contains(PAYLOAD_MARKER), "{name}");
            assert!(!text.contains(SECRET_MARKER), "{name}");
        }
    }
}
