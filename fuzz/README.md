# Fuzz targets

Coverage-guided fuzzing for the hostile-input parsers, using
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). This crate is not part of the
main workspace, so stable builds and CI do not need a nightly toolchain.

| Target | Input | Exercises |
| --- | --- | --- |
| `decode_packet` | One packet; the first byte selects Ethernet or another link type | `decoder::decode_packet`, `info`, `endpoints`, `Layer::describe` |
| `pcap_reader` | A whole capture file | `capture` header/record parsing and limits, plus decoding of every record |
| `application` | A transport payload; the first byte selects TCP/UDP, a port (53, 5353, 5355, 67, 68, 80, 443, 9) and whether the frame is snapshot-cut halfway through the payload | DNS, DHCP, HTTP and TLS parsers behind a valid frame, complete and cut |

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run decode_packet -- -max_total_time=60
cargo +nightly fuzz run pcap_reader -- -max_total_time=60
```

Seed a corpus from the synthetic fixtures for faster coverage:

```bash
mkdir -p corpus/pcap_reader && cp ../fixtures/pcap/*.pcap corpus/pcap_reader/
```

`corpus/`, `artifacts/` and `target/` are git-ignored. If a crash is found, turn the artifact into
a regular unit test in the affected crate before fixing it.

The stable test suites also include property tests (`proptest`) with the same goals:
`crates/capture/tests/properties.rs` and `crates/decoder/tests/properties.rs`.
