# Architecture

This document describes how FlowSentinel is structured today and where each future capability
will live. It is updated at the end of every milestone.

## Design principles

1. **Metadata first.** Packet bytes are interpreted transiently and only structured metadata is
   kept. Payload retention, if it is ever added, will be explicit and opt-in.
2. **Bounded everything.** Every queue, table, buffer and input has a configured upper limit.
   Hostile input must never cause unbounded memory or CPU use.
3. **Fail soft on data, fail loud on configuration.** A malformed packet produces a warning and
   processing continues. An invalid configuration stops startup with an actionable message.
4. **Explainable output.** Every derived result (flow, alert) carries the evidence it was built from.
5. **Least privilege.** Offline analysis needs no special privileges. Live capture (Milestone 10)
   will be isolated so the rest of the system never runs elevated.

## Current components (Milestone 3)

```
                +--------------------+
  curl -------> | api-server (Axum)  |  GET /health -> {"status":"ok","service":"flowsentinel-api"}
                +--------------------+
  shell ------> | cli (flowsentinel) |  --version, --help, inspect --pcap [--decode [--verbose]]
                +----+-----------+---+
                     |           |
                +----v-------+   |  PacketSink: borrowed bytes, one packet at a time
  .pcap file -> |  capture   +---+------------------+
                +------------+   |                  |
                     CaptureReport            +-----v------+
                                              |  decoder   |  bytes -> DecodedPacket (layers incl. DNS/DHCP/HTTP/TLS, status, warnings)
                                              +------------+

  docker compose: PostgreSQL 16, Redis 7 (started and health-checked; not yet used by code)
```

### `crates/api-server`

- `lib.rs` holds the router (`app()`) and `Config`. Keeping these in a library lets tests drive
  the real router in-process (`tower::ServiceExt::oneshot`) and over a real socket.
- `main.rs` initializes structured JSON logging (`tracing-subscriber`), loads configuration from
  the environment, binds the listener and serves with graceful shutdown on Ctrl+C or SIGTERM.
- Configuration is read through an injectable lookup (`Config::from_lookup`), so tests never
  mutate process-global environment variables.
- The default bind address is `127.0.0.1:8080`. Binding elsewhere logs a warning until
  authentication exists.

### `crates/capture`

Reads the classic libpcap container and nothing inside it. See
[docs/pcap-ingestion.md](docs/pcap-ingestion.md).

- `inspect::open_capture` validates the path in a fixed order (exists, regular file, `.pcap`
  extension, size limit), opens non-blocking on Unix and re-checks the opened handle. Exactly the
  validated number of bytes is read.
- `PcapGlobalHeader::parse` identifies the magic number (byte order, timestamp resolution) and
  validates version, snapshot length and reserved link-type bits.
- `PcapReader` streams over any `BufRead`. `next_record` reads one 16-byte record header,
  validates the captured length against libpcap's per-link-type maximum (262,144 bytes for most
  types) and skips the packet data without
  copying it. `at_eof` peeks without consuming, which separates "stopped at a limit" from "end of
  file".
- `inspect_reader` drives the reader under `CaptureLimits` (file size, packet count, duration;
  clamped to their documented ranges) with
  an injectable `Clock`, and returns a `CaptureReport`: summary, per-record metadata, completion
  state and deduplicated warnings.
- Errors carry a stable `code()` and a `category()` (input, malformed, io) that front ends map to
  exit codes or HTTP statuses. No public type can hold packet bytes.
- Packet bytes leave the crate only transiently. `PcapReader::next_packet` copies a record's
  bytes (at most 262,144) into a caller-owned buffer that is overwritten by the next call, and
  `inspect_*_with_sink` uses it to lend each record's bytes to a `PacketSink` for the duration
  of one call. Without a sink, data is skipped instead of copied.

### `crates/decoder`

Turns one packet's bytes into metadata. See [docs/protocol-decoding.md](docs/protocol-decoding.md).

- `decode_packet(link_type, bytes, wire_length)` returns a `DecodedPacket`: a `Vec<Layer>` protocol tree
  (Ethernet, ARP, IPv4, IPv6, ICMP, ICMPv6, TCP, UDP), a `DecodeStatus` (complete, unsupported,
  truncated, malformed) and per-packet warnings. It never fails and never panics.
- Parsers live in `link.rs` (Ethernet, VLAN, ARP), `network.rs` (IPv4, IPv6 extension-header
  walk) and `transport.rs` (TCP, UDP, ICMP). All field access goes through `bytes.rs`, whose
  accessors return `Option` instead of indexing.
- A per-packet `Context` collects layers and warnings and records the first stop reason.
  The context also knows whether the frame was cut by the snapshot length, which separates
  `truncated` (snapped) from `length_mismatch` (a header declaring bytes that a complete frame
  lacks). Network layers pass transport parsers an `Encapsulation` (declared payload length,
  fragment flag, capture cut) so length checks use the IP-declared size, not the captured size.
- `DecodeSummary` aggregates statuses, protocols and warnings over a capture in memory bounded by
  the number of enum values.
- `describe.rs` renders one-line summaries (`info`, `endpoints`, `Layer::describe`) for front ends.
- `app/` decodes application metadata from TCP/UDP payloads (see
  [docs/application-metadata.md](docs/application-metadata.md)). `app::decode` picks parsers by
  port hint (UDP DNS/DHCP, TCP DNS) or by structure (TLS, HTTP on any TCP port) and gives each
  at most 8 KiB. Parsers return `None` unless the structure is valid, plus a list of issues found
  after recognition. The dispatcher maps "ran out of bytes" to `truncated` (snapshot length),
  `application_limit_reached` (8 KiB cap) or `incomplete_application_data` (TCP segmentation).
  Transport parsers call it only for non-fragmented packets with consistent lengths.
- Each application model (`DnsMessage`, `DhcpMessage`, `HttpMessage`, `TlsHandshake`) holds
  only bounded, sanitized fields. Credential-bearing HTTP headers are matched by name and their
  values are never read; TLS randoms, key shares and certificates are skipped, not copied.
- The crate does not depend on `capture`; it takes a raw link-type number so live capture
  (Milestone 10) can reuse it.

### `crates/cli`

- A `clap` derive parser producing the `flowsentinel` binary. A bare invocation prints help.
- `inspect` renders a `CaptureReport` as tables or one JSON object. Exit codes: 0 success
  (including partial results), 2 usage, 3 rejected input, 4 malformed capture, 5 I/O.
- With `--decode`, the file is read twice so memory stays constant. Pass 1 passes
  `decode_view::SummaryCollector` to `capture` as a `PacketSink`; it decodes each packet and keeps
  only the running `DecodeSummary` and the widest endpoint text. Pass 2 decodes the same packets
  again and writes each row, tree or JSON element as soon as it is decoded, so the summaries can
  be printed first without keeping any packet.

### Infrastructure

- `docker-compose.yml` runs PostgreSQL and Redis bound to loopback, with health checks and
  passwords required from `.env`.
- CI (`.github/workflows/ci.yml`) runs format, clippy (`-D warnings`), tests and build on Linux
  and Windows. A second job boots the Compose services and waits for them to report healthy.

## Planned components

| Crate (planned) | Milestone | Responsibility |
| --- | --- | --- |
| `capture` | 10 | Live capture via libpcap (offline reading is done) |
| `flow-engine` | 4 | Bidirectional flow tracking with bounded memory and idle expiry |
| `storage` | 5 | SQLx/PostgreSQL persistence with migrations and retention |
| `filter-language` | 6 | Display-filter lexer, parser, validator and parameterized SQL translation |
| `detection-engine` | 7 | Configurable, explainable heuristics over flows and metadata |
| `frontend/` | 8 | React + TypeScript dashboard |

Data will flow in one direction:

```
PCAP file / interface -> capture -> decoder -> flow-engine -> detection-engine
                                        \            \              \
                                         +------------+--------------+--> storage -> api-server -> dashboard
```

Lower crates never depend on higher ones. `api-server` and `cli` are thin shells over libraries.
