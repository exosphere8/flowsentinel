# Cross-crate tests

Unit and integration tests live next to the code they cover:

| Location | What it covers |
| --- | --- |
| `crates/api-server/tests/health.rs` | `GET /health` in-process and over a real TCP socket |
| `crates/capture/src/*.rs` | PCAP header, record, timestamp, limit and path validation units |
| `crates/capture/tests/fixtures.rs` | Every committed fixture in `fixtures/pcap/` |
| `crates/capture/tests/properties.rs` | Property tests: arbitrary bytes never panic; valid captures round-trip |
| `crates/decoder/src/*.rs` | Byte accessors, warning bookkeeping, checksum, model serialization |
| `crates/decoder/tests/packets.rs` | Every protocol, VLAN, fragment, extension-header, malformed and truncated case, built byte by byte |
| `crates/decoder/tests/properties.rs` | Property tests: arbitrary bytes never panic; valid UDP round-trips |
| `crates/decoder/src/app/*.rs` | DNS names and compression loops, DHCP options, HTTP parsing and redaction, TLS hello parsing |
| `crates/decoder/tests/application.rs` | Application recognition rules, truncation vs segmentation, redaction, property tests on every application port |
| `fuzz/` | cargo-fuzz targets for the decoder, application parsers, flow engine and whole captures (nightly, run manually) |
| `crates/cli/src/*.rs` | Argument definitions, limit ranges and output rendering |
| `crates/cli/tests/cli.rs` | The compiled `flowsentinel` binary end to end |
| `crates/cli/tests/inspect.rs` | `flowsentinel inspect` output, exit codes and payload privacy |
| `crates/cli/tests/decode.rs` | `inspect --decode` against the decoder fixtures, including payload privacy |
| `crates/cli/tests/application.rs` | `inspect --decode` against the application fixtures; no secret marker in any output mode |
| `crates/flow-engine/src/*.rs` | Flow keys, running statistics |
| `crates/flow-engine/tests/flows.rs` | Direction, initiator inference, TCP states, expiry, eviction, retention, statistics, timestamps, determinism; property test that packet and byte totals are conserved |
| `crates/cli/tests/flows.rs` | `flowsentinel flows` against `flows-mixed.pcap`: every flow, sorting, limits, exit codes, payload privacy |
| `crates/api-server/src/*.rs` | Configuration parsing, `Host` checks, upload rate and stale-file cleanup |
| `crates/analysis/tests/pipeline.rs` | Both analysis passes agree; packets carry flow IDs; a file changed between passes is detected; detection runs in the first pass and links alerts to flows |
| `crates/filter-language/src/*.rs` | Lexer, parser precedence and limits, translation, type errors with positions, injection attempts, catalog documented |
| `crates/filter-language/tests/properties.rs` | Property tests: arbitrary text never panics; generated filters compile and round-trip; quoted text is always one parameter |
| `crates/detection-engine/src/*.rs` | Configuration parsing and ranges (the example file equals the defaults), sliding windows: limits, sweeps, outlier and backward-jump handling |
| `crates/detection-engine/tests/rules.rs` | Every rule with a matching and a benign trace, cited flows and packets, tuning and disabling, alert limits, determinism, property test that arbitrary packets never panic |
| `crates/cli/tests/detect.rs` | `flowsentinel detect` against `detect-mixed.pcap`: the five expected alerts, human and JSON output, configuration errors, exit codes, payload privacy |

Tests that need PostgreSQL create a disposable database per test (see
[CONTRIBUTING.md](../CONTRIBUTING.md#database-tests)):

| Location | What it covers |
| --- | --- |
| `crates/storage/tests/storage.rs` | Imports, pagination, sorting, bound-parameter conditions, rollback, retention and purge, alerts with flow links and triage, no secrets stored |
| `crates/api-server/tests/api.rs` | Every `/api/v1` endpoint in-process: imports, structured errors, upload validation (long and Windows-style names, bodies far above the JSON limit), partial imports, `Host` checks, retention, display filters against real data, alerts and triage, OpenAPI, no secrets in any response |

This directory is reserved for end-to-end tests that span several processes, such as the
dashboard against a running API (Milestone 8).
