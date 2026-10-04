//! Runs `flowsentinel flows` end to end against the fixtures in fixtures/pcap.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

const PAYLOAD_MARKER: &str = "FLOWSENTINEL-SYNTHETIC-PAYLOAD-MARKER";
const SECRET_MARKER: &str = "FLOWSENTINEL-SECRET";

fn run(name: &str, extra: &[&str]) -> Output {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pcap")
        .join(name);
    Command::new(env!("CARGO_BIN_EXE_flowsentinel"))
        .arg("flows")
        .arg("--pcap")
        .arg(path)
        .args(extra)
        .output()
        .expect("failed to run flowsentinel binary")
}

fn report(extra: &[&str]) -> Value {
    let mut args = vec!["--json"];
    args.extend_from_slice(extra);
    let out = run("flows-mixed.pcap", &args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("one JSON object")
}

#[test]
fn reconstructs_every_flow_in_the_fixture() {
    let r = report(&[]);
    let summary = &r["flow_summary"];
    assert_eq!(summary["packets_seen"], 19);
    assert_eq!(summary["packets_without_ip"], 1);
    assert_eq!(summary["flows_total"], 6);
    assert_eq!(
        summary["end_reasons"],
        json!({"idle_timeout": 3, "tcp_finished": 2, "capture_end": 1})
    );

    let flows = r["flows"].as_array().unwrap();
    let ids: Vec<u64> = flows
        .iter()
        .map(|f| f["flow_id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, [1, 2, 3, 4, 5, 6]);

    let dns = &flows[0];
    assert_eq!(dns["protocol_name"], "UDP");
    assert_eq!(
        dns["application"]["dns_queries"],
        json!(["www.example.com"])
    );
    assert_eq!(dns["packets_total"], 2);

    let tls = &flows[1];
    assert_eq!(tls["initiator"], json!({"ip": "192.0.2.10", "port": 40500}));
    assert_eq!(
        tls["responder"],
        json!({"ip": "198.51.100.80", "port": 443})
    );
    assert_eq!(tls["initiator_basis"], "tcp_syn");
    assert_eq!(tls["tcp"]["state"], "closed");
    assert_eq!(tls["tcp"]["duplicate_segments"], 1);
    assert_eq!(tls["end_reason"], "tcp_finished");
    assert_eq!(
        tls["application"]["tls_server_names"],
        json!(["www.example.com"])
    );
    assert_eq!(
        tls["application"]["responder_dns_names"],
        json!(["www.example.com"])
    );
    assert_eq!(tls["initiator_to_responder"]["packets"], 6);
    assert_eq!(tls["responder_to_initiator"]["packets"], 3);

    let refused = &flows[2];
    assert_eq!(refused["tcp"]["state"], "reset");
    assert_eq!(refused["responder"]["port"], 8080);

    let v6 = &flows[3];
    assert_eq!(v6["ip_version"], 6);
    assert_eq!(
        v6["warnings"],
        json!([{"code": "out_of_order_timestamp", "count": 1}])
    );

    assert_eq!(flows[4]["end_reason"], "idle_timeout");
    assert_eq!(flows[4]["packets_total"], 2);
    assert_eq!(flows[5]["packets_total"], 1);
    assert_eq!(flows[5]["initiator"]["port"], 40700);
}

#[test]
fn sorting_and_limits() {
    let by_bytes = report(&["--sort", "bytes"]);
    let first = &by_bytes["flows"][0];
    assert_eq!(first["flow_id"], 2, "the TLS flow carries the most bytes");

    let capped = report(&["--max-flows", "2"]);
    assert_eq!(capped["flows"].as_array().unwrap().len(), 2);
    assert_eq!(capped["flow_summary"]["flows_not_retained"], 4);

    let tiny = report(&["--max-active-flows", "1"]);
    assert!(
        tiny["flow_summary"]["end_reasons"]["evicted"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert_eq!(tiny["flow_summary"]["peak_active_flows"], 1);

    let short_idle = report(&["--idle-timeout-seconds", "1"]);
    assert_eq!(short_idle["flow_summary"]["flows_total"], 6);
}

#[test]
fn human_output_lists_flows() {
    let out = run("flows-mixed.pcap", &[]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Flow summary"));
    assert!(text.contains("6 total"));
    assert!(text.contains("192.0.2.10:40500"));
    assert!(text.contains("TLS www.example.com"));
    assert!(text.contains("[2001:db8::a00]:40600"));
}

#[test]
fn output_contains_no_payload_or_secrets() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pcap");
    let mut checked = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        for extra in [&[][..], &["--json"], &["--sort", "bytes"]] {
            let out = run(&name, extra);
            for stream in [&out.stdout, &out.stderr] {
                let text = String::from_utf8_lossy(stream).to_ascii_lowercase();
                assert!(
                    !text.contains(&PAYLOAD_MARKER.to_ascii_lowercase()),
                    "{name}"
                );
                assert!(
                    !text.contains(&SECRET_MARKER.to_ascii_lowercase()),
                    "{name}"
                );
            }
            checked += 1;
        }
    }
    assert!(checked >= 90, "every fixture is checked");
}

#[test]
fn invalid_options_are_usage_errors() {
    for args in [
        ["--max-active-flows", "0"],
        ["--max-flows", "0"],
        ["--idle-timeout-seconds", "0"],
        ["--sort", "random"],
    ] {
        assert_eq!(
            run("flows-mixed.pcap", &args).status.code(),
            Some(2),
            "{args:?}"
        );
    }
}

#[test]
fn capture_errors_use_inspect_exit_codes() {
    assert_eq!(run("missing.pcap", &[]).status.code(), Some(3));
    let out = run("truncated-record-data.pcap", &["--json"]);
    assert_eq!(out.status.code(), Some(4));
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["error"]["code"], "truncated_record_data");
}
