# Cross-crate tests

Unit and integration tests live next to the code they cover:

| Location | What it covers |
| --- | --- |
| `crates/api-server/src/lib.rs` | Configuration parsing |
| `crates/api-server/tests/health.rs` | `GET /health` in-process and over a real TCP socket |
| `crates/capture/src/*.rs` | PCAP header, record, timestamp, limit and path validation units |
| `crates/capture/tests/fixtures.rs` | Every committed fixture in `fixtures/pcap/` |
| `crates/capture/tests/properties.rs` | Property tests: arbitrary bytes never panic; valid captures round-trip |
| `crates/decoder/src/*.rs` | Byte accessors, warning bookkeeping, checksum, model serialization |
| `crates/decoder/tests/packets.rs` | Every protocol, VLAN, fragment, extension-header, malformed and truncated case, built byte by byte |
| `crates/decoder/tests/properties.rs` | Property tests: arbitrary bytes never panic; valid UDP round-trips |
| `fuzz/` | cargo-fuzz targets for the decoder and whole captures (nightly, run manually) |
| `crates/cli/src/*.rs` | Argument definitions, limit ranges and output rendering |
| `crates/cli/tests/cli.rs` | The compiled `flowsentinel` binary end to end |
| `crates/cli/tests/inspect.rs` | `flowsentinel inspect` output, exit codes and payload privacy |
| `crates/cli/tests/decode.rs` | `inspect --decode` against the decoder fixtures, including payload privacy |

This directory is reserved for end-to-end tests that span several services,
such as the API with PostgreSQL. Those arrive with persistence in Milestone 5.
