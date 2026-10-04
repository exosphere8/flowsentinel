# FlowSentinel

[![CI](https://github.com/exosphere8/flowsentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/exosphere8/flowsentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

FlowSentinel is a defensive network packet analyzer and flow-security monitor written in Rust.
It imports offline PCAP files (and, later, captures authorized live traffic). It decodes protocols
into privacy-conscious metadata, reconstructs bidirectional flows, and raises explainable,
heuristic alerts that a human can verify.

> **Authorized use only.** Analyze only networks and traffic that you own or are explicitly
> authorized to inspect. FlowSentinel is an observability tool, not an offensive one: it has no
> packet injection, scanning, decryption or credential-extraction features.

## Status

FlowSentinel is built in milestones (see [Roadmap](#roadmap)). Completed so far:

- **Milestone 0, foundation:** a Cargo workspace, an HTTP API with a health check, a CLI shell,
  Docker Compose services and CI.
- **Milestone 1, safe offline PCAP ingestion:** `flowsentinel inspect --pcap` reads classic
  libpcap files with strict resource limits and reports container metadata only.

## Quick start

Requirements: Rust 1.85+ (stable), Docker with Compose v2, and optionally `make`.

```bash
git clone https://github.com/exosphere8/flowsentinel.git
cd flowsentinel
cp .env.example .env            # then replace each "change-me" value

docker compose up -d --wait     # PostgreSQL + Redis, waits for health checks
cargo run -p api-server         # serves http://127.0.0.1:8080
```

In another terminal:

```bash
curl http://127.0.0.1:8080/health
# {"status":"ok","service":"flowsentinel-api"}

cargo run -p cli -- --version
# flowsentinel 0.1.0
```

Stop the services with `docker compose down`. Add `-v` to also delete their data volumes.

### Inspect a capture

```bash
cargo run -p cli -- inspect --pcap fixtures/pcap/le-usec.pcap
cargo run -p cli -- inspect --pcap fixtures/pcap/many-packets.pcap --max-packets 5 --json
```

`inspect` prints a capture summary and a per-packet metadata table (index, timestamp, captured
and original length), or one JSON object with `--json`. Packet contents are never shown. Limits
default to 512 MiB, 100,000 packets and 60 seconds. See
[docs/pcap-ingestion.md](docs/pcap-ingestion.md) for flags, output fields, warnings and exit codes.

### Windows note

When a checkout sits in a deeply nested folder, Cargo's build-script paths can exceed the classic
Windows path-length limit. The build then fails with `The system cannot find the path specified.
(os error 3)`. To fix it, point Cargo at a short target directory for the current shell only.
Nothing in the repository hardcodes this path.

```powershell
$env:CARGO_TARGET_DIR = "C:\t\flowsentinel-target"
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `FLOWSENTINEL_API_ADDR` | `127.0.0.1:8080` | API listen address (`IP:PORT`) |
| `RUST_LOG` | `info` | Log filter; logs are structured JSON on stdout |
| `POSTGRES_*`, `REDIS_*` | see `.env.example` | Docker Compose services |

The server logs a warning if it binds to a non-loopback address, because the API has no
authentication until Milestone 9.

## Development

| Command | Action |
| --- | --- |
| `make up` / `make down` | Start or stop PostgreSQL and Redis |
| `make dev` | Run the API server |
| `make fmt` | Format code |
| `make lint` | Clippy with `-D warnings` |
| `make test` | Run all tests |
| `make check` | Full CI gate: format check, lint, test, build |
| `make fixtures` | Regenerate the synthetic PCAP fixtures |

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Repository layout

```
crates/
  api-server/   Axum HTTP service (GET /health)
  capture/      Classic PCAP container reader with resource limits
  cli/          `flowsentinel` command-line tool
docs/           Design and user documentation
fixtures/       Synthetic test inputs only (fixtures/pcap/ is generated)
scripts/        Developer scripts, including the fixture generator
tests/          Cross-service end-to-end tests (from Milestone 5)
```

## Roadmap

| # | Milestone | State |
| --- | --- | --- |
| 0 | Foundation and developer environment | Done |
| 1 | Safe offline PCAP ingestion | Done |
| 2 | Core packet decoder (Ethernet, ARP, IPv4/6, ICMP, TCP, UDP) | Planned |
| 3 | Application metadata (DNS, DHCP, HTTP/1.1, TLS handshake) | Planned |
| 4 | Bidirectional flow reconstruction | Planned |
| 5 | PostgreSQL persistence and REST API | Planned |
| 6 | Display-filter language | Planned |
| 7 | Explainable rule-based detection | Planned |
| 8 | React dashboard | Planned |
| 9 | Authentication, RBAC and auditing | Planned |
| 10 | Authorized live capture | Planned |
| 11 | Observability, performance and hardening | Planned |
| 12 | Public release (v0.1.0) | Planned |

## License

[MIT](LICENSE) © exosphere8. Built by [exosphere8](https://github.com/exosphere8).
