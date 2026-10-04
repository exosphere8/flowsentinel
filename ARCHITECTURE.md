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

## Current components (Milestone 1)

```
                +--------------------+
  curl -------> | api-server (Axum)  |  GET /health -> {"status":"ok","service":"flowsentinel-api"}
                +--------------------+
  shell ------> | cli (flowsentinel) |  --version, --help, inspect --pcap
                +---------+----------+
                          |
                +---------v----------+
  .pcap file -> |      capture       |  global header + record headers -> CaptureReport
                +--------------------+

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

### `crates/cli`

- A `clap` derive parser producing the `flowsentinel` binary. A bare invocation prints help.
- `inspect` renders a `CaptureReport` as tables or one JSON object. Exit codes: 0 success
  (including partial results), 2 usage, 3 rejected input, 4 malformed capture, 5 I/O.

### Infrastructure

- `docker-compose.yml` runs PostgreSQL and Redis bound to loopback, with health checks and
  passwords required from `.env`.
- CI (`.github/workflows/ci.yml`) runs format, clippy (`-D warnings`), tests and build on Linux
  and Windows. A second job boots the Compose services and waits for them to report healthy.

## Planned components

| Crate (planned) | Milestone | Responsibility |
| --- | --- | --- |
| `capture` | 10 | Live capture via libpcap (offline reading is done) |
| `decoder` | 2, 3 | Bounds-checked protocol decoding into typed metadata |
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
