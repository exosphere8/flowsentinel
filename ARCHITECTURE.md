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

## Current components (Milestone 10)

```
  browser: dashboard (React, served at /)
  curl / client --HTTP--> +--------------------+  /health, /api/v1/... (JSON, OpenAPI)
                          | api-server (Axum)  |-- stream upload --> private temp file (.pcap)
                          +----+-----------+---+-- ?filter= --> filter-language --> SQL pieces + parameters
                               |           |  SQL (parameterized, one transaction per import)
            spawn_blocking     |      +----v-----+
                               |      | storage  |--> PostgreSQL 16 (sessions, packets, flows,
                               |      +----^-----+     alerts, DNS/HTTP/TLS events, retention)
                          +----v-----+     |  PacketRow batches (bounded queue)
  shell --> cli --------> | analysis |-----+   pass 1: summaries + flows + alerts + fingerprint
            (inspect,     +----+-----+         pass 2: packets with flow IDs, in batches
             flows,            |
             detect)           |
                +--------------v-----------------------------------------------------+
                | capture -> decoder -> flow-engine ---------> detection-engine       |
                | (limits)   (layers)    (FlowRecord)  finish   (rules -> Alert)       |
                |               \________ DNS/ARP layers ______^                     |
                +--------------------------------------------------------------------+

  docker compose: PostgreSQL 16
```

### `crates/api-server`

- `lib.rs` holds `Config` and two routers: `app()` (health only) and `app_with_state()` (health,
  `/api/v1` and, when `FLOWSENTINEL_DASHBOARD_DIR` is set, the built dashboard at `/`). Keeping them in a library lets tests drive the real router in-process
  (`tower::ServiceExt::oneshot`) and over a real socket. See [docs/api.md](docs/api.md).
- `main.rs` initializes structured JSON logging (`tracing-subscriber`) and loads configuration
  from the environment, including the detection thresholds (`FLOWSENTINEL_DETECTION_CONFIG`). It
  connects to PostgreSQL, applies migrations, starts the hourly retention purge, binds the
  listener and serves with graceful shutdown on Ctrl+C or SIGTERM. It refuses to start without a
  valid `FLOWSENTINEL_DATABASE_URL` or with an invalid detection configuration. The URL is never logged:
  `Config`'s `Debug` output redacts it.
- `routes.rs` holds the handlers, annotated for `utoipa`; `openapi.rs` assembles the OpenAPI
  document. `extract.rs` wraps axum's `Query`, `Path` and `Json` extractors so malformed requests
  get the same JSON error shape (`error.rs`) as everything else.
- `upload.rs` streams a request body to a private temporary file, enforcing the size limit, an
  idle timeout and a minimum average rate, and computing the SHA-256 on the way. The import handler then runs both analysis
  passes on blocking threads. Pass 2 hands packet batches to the async database writer through a
  bounded channel, so a large upload never sits in memory.
- `dashboard.rs` serves the dashboard's static files with an `index.html` fallback for its
  client-side routes, and adds the security headers (CSP, `nosniff`, `X-Frame-Options`,
  `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
  `Permissions-Policy`, and HSTS behind HTTPS) to every response. Unknown `/api/v1` paths
  keep their JSON `404`.
- `observability.rs` is the outermost layer. It gives each request an ID and a `request` span,
  writes one access-log line with the matched route template (`mark_route` records it), and
  counts requests, durations and audit events for the optional Prometheus listener.
  `telemetry.rs` sets up JSON logs and, with the `otel` feature, the OpenTelemetry exporter.
  `GET /ready` checks the database; `GET /health` does not.
- `healthcheck.rs` implements `flowsentinel-api healthcheck`, a minimal `GET /health` probe used
  by the container health check, so the image needs no `curl`.
- `host.rs` refuses requests whose `Host` header is not a name of the server (DNS-rebinding
  protection). `state.rs` holds the import and read semaphores: reads get the database pool
  minus two connections per import slot, so heavy reading cannot starve imports.
- At startup the server deletes upload files left by a run that was killed; on shutdown it gives
  running requests 30 seconds.
- Configuration is read through an injectable lookup (`Config::from_lookup`), so tests never
  mutate process-global environment variables.
- The default bind address is `127.0.0.1:8080`. Binding elsewhere without secure cookies logs a
  warning.
- `auth.rs` holds sessions and access control (see [docs/authentication.md](docs/authentication.md)):
  the `authenticate` middleware on every protected route (session cookie to account, CSRF check
  on state-changing methods), the `same_origin` middleware on all of `/api/v1`, the
  `Authorized<R>` extractor that handlers use to require a role (`Viewer`, `Analyst`, `Admin`)
  and that audits refusals, and Argon2id hashing on blocking threads behind a semaphore.
  `ratelimit.rs` counts failed password checks per username and client address. `accounts.rs`
  has the sign-in, session, password, account and audit-log handlers; `audit.rs` records events
  to the database and the log; `bootstrap.rs` creates the first admin from a password file and
  implements `flowsentinel-api create-user`.
- `main.rs` serves with `into_make_service_with_connect_info`, so handlers see the client address
  for limits and the audit log.

### `crates/analysis`

The pipeline shared by front ends. `analyze_file` reads a capture once through
`capture → decoder → flow-engine`. It keeps the report without per-record data, the decode
summary, the finished flows, and a fingerprint of the packets that will be replayed.
`analyze_file_with_detection` also feeds every decoded packet to a `Detector` and hands it the
finished flows, so the rules cost no extra pass.
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
- `ImportTransaction` writes a capture in one transaction: `begin_import` inserts the session,
  flows (with their alert count and highest severity) and alerts, `add_packets` inserts packet batches and their DNS/HTTP/TLS events, and `commit`
  publishes them. Dropping it rolls everything back.
- `PacketRow::from_analyzed` extracts indexed columns and serializes metadata to JSON text off the
  async runtime; `add_packets` moves the rows into the insert, so metadata is never copied.
- `accounts.rs` stores accounts, sign-in sessions (token digests only) and audit events. Changes
  that could remove the last enabled admin lock the admin rows first, so two concurrent changes
  cannot both succeed; role, state and password changes end the account's sessions in the same
  transaction.
- Feature `test-support` provides `testing::TestDatabase`, a migrated database created per test
  and dropped afterwards, even if the test panics.

### `crates/detection-engine`

Explainable heuristics (see [docs/detection-rules.md](docs/detection-rules.md)). Every alert is
a heuristic indicator, never a verdict, and carries its evidence, cited flows or packets,
uncertainty, likely false positives and ATT&CK context.

- `model.rs` defines `Alert`, `Severity`, `Confidence`, `AlertStatus`, `Evidence` and the fixed
  rule catalog `RULES`: twelve `Rule`s with stable IDs and their descriptions.
- `config.rs` holds `DetectionConfig` (TOML, unknown keys rejected, every value range-checked,
  files at most 64 KiB) with one section per rule.
- `packets.rs` evaluates DNS and ARP packets as they arrive (`Detector::observe_packet`).
  `window.rs` provides the sliding windows: per key at most 4,096 events, per rule at most
  16,384 keys and 131,072 events, with sweeps of expired keys driven by a clock that a lone
  outlier timestamp cannot move.
- `flows.rs` evaluates the finished flows (`Detector::finish`): windowed distinct counts for
  scans and failures, interval statistics for beaconing, and per-capture rarity, ratio and port
  checks.
- `finish` numbers alerts in catalog order and then by time, keeps at most 1,000 per rule, and
  records alert IDs on the cited flows. Results are deterministic.
- Depends on `capture`, `decoder` and `flow-engine` only; it reads metadata, never packet bytes.

### `crates/filter-language`

The display-filter language (see [docs/filter-language.md](docs/filter-language.md)). It has no
database dependency.

- `lexer.rs` turns text into tokens with byte spans (length and token limits). `parser.rs` builds
  an `Expr` tree by recursive descent (depth and clause limits). `fields.rs` is the fixed catalog
  of packet and flow fields (including the flow's alert facts): type, SQL column or predicate,
  and optional guard.
- `translate.rs` type-checks each comparison against the catalog and emits `Piece`s: `Sql` holds
  a `'static` fragment from the catalog or the translator, and `Param` holds a typed value. User
  text can only ever become a `Param`.
- The API's `Conditions` (`routes.rs`) implements `storage::SqlCondition` by pushing `Sql` pieces
  and binding `Param` pieces with SQLx, so filters reuse the storage layer's parameterized list
  queries.

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

### `crates/live-capture`

Authorized live capture (see [docs/live-capture.md](docs/live-capture.md)).

- `source.rs` defines `PacketSource` (one open interface or file) and `SourceFactory` (lists
  interfaces, compiles filters, opens sources), with stable error codes.
  - `libpcap.rs` (feature `libpcap`, the only module that touches libpcap) opens interfaces with
    promiscuous mode off unless asked, non-blocking reads (libpcap's read timeout does not start
    on an idle Linux interface) and the snapshot length. It
    compiles BPF filters on a "dead" handle before capturing.
  - `replay.rs` replays a capture file, so tests need neither network access nor privileges.
  - Builds without the feature use `Unavailable`.
- `session.rs` runs one capture on two threads. The capture thread hands packets to the writer
  through a `sync_channel` of 1,024 packets with `try_send`: when the writer is behind, packets
  are dropped and counted, never queued without bound. It stops at the first of the time,
  packet and byte limits, a stop request or the source's end. `writer.rs` writes classic pcap
  and hashes it on the way.
- `limits.rs` resolves requested limits against the server's maximums. `bpf.rs` checks filter
  text before libpcap sees it.
- In `api-server`, `live.rs` holds the single capture slot (`LiveManager`), the admin-only
  endpoints and the background task that, when a capture ends, imports its file through the
  same `store_file` path as uploads (source `live`) and deletes it.

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
  flows as a table or one JSON object. `detect` runs `analyze_file_with_detection` and prints the
  alerts with their explanations, or one JSON object. The commands share the capture flags
  through a flattened `CaptureArgs`.

### `frontend/`

The dashboard (see [docs/dashboard.md](docs/dashboard.md)): React 19, React Router and
TypeScript, built by Vite into static files that `api-server` serves. It talks only to the
metadata API, same-origin.

- `src/api/schema.ts` is generated from `docs/openapi.json` by `scripts/gen-api-types.mjs`;
  `src/api/client.ts` is the typed client with structured `ApiError`s and request cancellation.
- `src/pages/` has one component per route; `src/components/` holds tables, paging, the filter
  bar (validated by the server as it is typed), SVG bar charts with table equivalents, badges and
  the protocol tree, which never renders payload-like fields.
- List state (page, sort, filter) lives in the URL (`useSearchState`); data loading goes through
  `useResource`, which cancels requests on navigation and exposes loading, error and reload.
- Tests: Vitest and Testing Library in jsdom with axe-core; Playwright smoke tests in `e2e/`.

### Infrastructure

- `docker-compose.yml` runs PostgreSQL bound to loopback, with a health check and a password
  required from `.env`. The optional `app` profile builds the `Dockerfile` (dashboard,
  then a release `api-server`, on a slim Debian runtime) and runs it as UID 10001 with a
  read-only root file system, no capabilities and `no-new-privileges`, published on loopback.
- CI (`.github/workflows/ci.yml`) runs format, clippy (`-D warnings`), tests and build on Linux
  and Windows, the MSRV check, the database tests, and a fixture check. The `compose` job boots
  the Compose services, then builds and starts the `app` image and checks its health, dashboard,
  CSP and user. The `frontend` job lints, type-checks, tests and builds the dashboard on Linux
  and Windows, and the `e2e` job runs the Playwright smoke tests against a real server and
  database. CI runs on `main` and on `feature/**` branches before they are merged.

## Planned components

| Crate (planned) | Milestone | Responsibility |
| --- | --- | --- |
| (none) | 11 | Metrics, tracing and further hardening |

Data will flow in one direction:

```
PCAP file / interface -> capture -> decoder -> flow-engine -> detection-engine
                                        \            \              \
                                         +------------+--------------+--> storage -> api-server -> dashboard
```

Lower crates never depend on higher ones. `api-server` and `cli` are thin shells over libraries.
