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

## Current components (Milestone 5)

```
  curl / client --HTTP--> +--------------------+  /health, /api/v1/... (JSON, OpenAPI)
                          | api-server (Axum)  |-- stream upload --> private temp file (.pcap)
                          +----+-----------+---+
                               |           |  SQL (parameterized, one transaction per import)
            spawn_blocking     |      +----v-----+
                               |      | storage  |--> PostgreSQL 16 (sessions, packets, flows,
                               |      +----^-----+     DNS/HTTP/TLS events, retention)
                          +----v-----+     |  PacketRow batches (bounded queue)
  shell --> cli --------> | analysis |-----+   pass 1: summaries + flows + fingerprint
            (inspect,     +----+-----+         pass 2: packets with flow IDs, in batches
             flows)            |
                +--------------v--------------------------------+
                | capture -> decoder -> flow-engine             |  PacketSink: borrowed bytes,
                | (limits)   (layers)    (FlowRecord)           |  one packet at a time
                +-----------------------------------------------+

  docker compose: PostgreSQL 16 (used by the API), Redis 7 (started; not yet used)
```

### `crates/api-server`

- `lib.rs` holds `Config` and two routers: `app()` (health only) and `app_with_state()` (health
  plus `/api/v1`). Keeping them in a library lets tests drive the real router in-process
  (`tower::ServiceExt::oneshot`) and over a real socket. See [docs/api.md](docs/api.md).
- `main.rs` initializes structured JSON logging (`tracing-subscriber`) and loads configuration
  from the environment. It connects to PostgreSQL, applies migrations, starts the hourly
  retention purge, binds the listener and serves with graceful shutdown on Ctrl+C or SIGTERM. It
  refuses to start without a valid `FLOWSENTINEL_DATABASE_URL`. The URL is never logged:
  `Config`'s `Debug` output redacts it.
- `routes.rs` holds the handlers, annotated for `utoipa`; `openapi.rs` assembles the OpenAPI
  document. `extract.rs` wraps axum's `Query`, `Path` and `Json` extractors so malformed requests
  get the same JSON error shape (`error.rs`) as everything else.
- `upload.rs` streams a request body to a private temporary file, enforcing the size limit, an
  idle timeout and a minimum average rate, and computing the SHA-256 on the way. The import handler then runs both analysis
  passes on blocking threads. Pass 2 hands packet batches to the async database writer through a
  bounded channel, so a large upload never sits in memory.
- `host.rs` refuses requests whose `Host` header is not a name of the server (DNS-rebinding
  protection). `state.rs` holds the import and read semaphores: reads get the database pool
  minus two connections per import slot, so heavy reading cannot starve imports.
- At startup the server deletes upload files left by a run that was killed; on shutdown it gives
  running requests 30 seconds.
- Configuration is read through an injectable lookup (`Config::from_lookup`), so tests never
  mutate process-global environment variables.
- The default bind address is `127.0.0.1:8080`. Binding elsewhere logs a warning until
  authentication exists.

### `crates/analysis`

The pipeline shared by front ends. `analyze_file` reads a capture once through
`capture → decoder → flow-engine`. It keeps the report without per-record data, the decode
summary, the finished flows, and a fingerprint of the packets that will be replayed.
`replay_packets` reads the first N packets again and replays the deterministic flow engine to
recover each packet's flow ID. It yields packets in batches and fingerprints what it read; the
caller compares the fingerprints and discards the result if the file changed.

### `crates/storage`

PostgreSQL persistence with SQLx. See [docs/data-retention.md](docs/data-retention.md).

- `migrations/` holds the schema, embedded in the binary (`sqlx::migrate!`) and checksum-verified
  at startup. No column can hold payload bytes.
- Every query is parameterized. Sort orders are enums that map to fixed SQL fragments. Extra
  `WHERE` conditions come through the `SqlCondition` trait, whose implementations push only fixed
  SQL text and bind every value.
- `ImportTransaction` writes a capture in one transaction: `begin_import` inserts the session and
  flows, `add_packets` inserts packet batches and their DNS/HTTP/TLS events, and `commit`
  publishes them. Dropping it rolls everything back.
- `PacketRow::from_analyzed` extracts indexed columns and serializes metadata to JSON text off the
  async runtime; `add_packets` moves the rows into the insert, so metadata is never copied.
- Feature `test-support` provides `testing::TestDatabase`, a migrated database created per test
  and dropped afterwards, even if the test panics.

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

### `crates/flow-engine`

Groups decoded packets into bidirectional flows. See [docs/flow-engine.md](docs/flow-engine.md).

- `FlowKey` holds the IP protocol and the two endpoints in canonical (sorted) order, so both
  directions match one flow. The initiator is decided separately: from the TCP handshake when one
  is seen (`tcp_syn`, `tcp_syn_ack`), otherwise from the first packet. Sort order never decides it.
- `FlowEngine::process` takes a `FlowPacket` (index, timestamp, wire length, borrowed
  `DecodedPacket`) and returns the flow ID it was assigned to. It reads only decoded metadata,
  never packet bytes.
- Each active flow keeps constant-size state: per-direction counters, Welford mean/variance for
  sizes and gaps, the first 256 sizes for the median, flag unions, an approximate TCP state and
  application lists capped at 4 entries each.
- Flows are timed by the engine's clock, which follows packet timestamps but accepts a jump of
  more than a day only when the next packet confirms it, so one corrupt timestamp cannot expire
  or freeze flows. Flows end on idle timeout (per protocol), shortly after TCP closes or when a
  new SYN reuses closed ports, by least-recently-seen eviction when `max_active_flows` is
  reached, when the clock is confirmed to have jumped back by more than a day, or at the end of
  the capture.
  Ordered indexes `(deadline, id)` and `(packet sequence, id)` make expiry and eviction
  logarithmic and deterministic.
- `finish` returns the `FlowRecord`s with the lowest IDs (at most `max_retained_flows`) in
  `flow_id` order (kept in a max-heap by ID while running), and a `FlowSummary` with totals,
  end-reason counts, ignored timestamp outliers and confirmed clock jumps.
- Depends on `capture` (timestamps) and `decoder` (layers) only.

### `crates/cli`

- A `clap` derive parser producing the `flowsentinel` binary. A bare invocation prints help.
- `inspect` renders a `CaptureReport` as tables or one JSON object. Exit codes: 0 success
  (including partial results), 2 usage, 3 rejected input, 4 malformed capture, 5 I/O.
- With `--decode`, the file is read twice so memory stays constant. Pass 1 passes
  `decode_view::SummaryCollector` to `capture` as a `PacketSink`; it decodes each packet and keeps
  only the running `DecodeSummary` and the widest endpoint text. Pass 2 decodes the same packets
  again and writes each row, tree or JSON element as soon as it is decoded, so the summaries can
  be printed first without keeping any packet.
- `flows` decodes each packet in one pass, feeds it to a `FlowEngine` and prints the finished
  flows as a table or one JSON object. `inspect` and `flows` share the capture flags through a
  flattened `CaptureArgs`.

### Infrastructure

- `docker-compose.yml` runs PostgreSQL and Redis bound to loopback, with health checks and
  passwords required from `.env`.
- CI (`.github/workflows/ci.yml`) runs format, clippy (`-D warnings`), tests and build on Linux
  and Windows. A second job boots the Compose services and waits for them to report healthy.

## Planned components

| Crate (planned) | Milestone | Responsibility |
| --- | --- | --- |
| `capture` | 10 | Live capture via libpcap (offline reading is done) |
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
