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
- **Milestone 2, core packet decoding:** `inspect --decode` decodes Ethernet (with VLANs), ARP,
  IPv4, IPv6 (with extension headers), ICMP, ICMPv6, TCP and UDP headers into a protocol tree.
  Payloads are measured, never shown.
- **Milestone 3, application metadata:** `inspect --decode` also extracts bounded metadata from
  DNS, DHCP, HTTP/1.x and visible TLS handshakes (SNI, ALPN, versions, cipher-suite IDs).
  Credentials, cookies, query strings and bodies are redacted; TLS is never decrypted.

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

Add `--decode` to decode protocol headers, and `--verbose` for each packet's protocol tree:

```bash
cargo run -p cli -- inspect --pcap fixtures/pcap/decode-ipv4.pcap --decode
cargo run -p cli -- inspect --pcap fixtures/pcap/decode-ipv6.pcap --decode --verbose
cargo run -p cli -- inspect --pcap fixtures/pcap/decode-malformed.pcap --decode --json
```

```text
        #  Timestamp (UTC)                 Source             Destination        Protocol  Length  Info
        1  2026-01-01T00:00:00.000000Z     02:00:00:00:00:01  ff:ff:ff:ff:ff:ff  ARP           42  who-has 192.0.2.1 tell 192.0.2.10
        4  2026-01-01T00:00:00.030000Z     192.0.2.10         198.51.100.20      TCP           62  40001 -> 9 [SYN] seq=1000 win=64240 len=0
```

See [docs/protocol-decoding.md](docs/protocol-decoding.md) for supported protocols, statuses,
warnings and validation rules.

Application protocols are recognized by structure, never by port alone:

```bash
cargo run -p cli -- inspect --pcap fixtures/pcap/app-dns.pcap --decode
cargo run -p cli -- inspect --pcap fixtures/pcap/app-tls.pcap --decode --verbose
```

```text
        #  Timestamp (UTC)                 Source         Destination    Protocol  Length  Info
        1  2026-01-01T00:00:00.000000Z     192.0.2.10     198.51.100.80  TLS          268  TLS ClientHello SNI=www.example.com ALPN=h2,http/1.1 (handshake metadata only)
```

See [docs/application-metadata.md](docs/application-metadata.md) for fields, limits and redaction
rules.

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
  decoder/      Bounds-checked protocol and application-metadata decoder
docs/           Design and user documentation
fixtures/       Synthetic test inputs only (fixtures/pcap/ is generated)
fuzz/           cargo-fuzz targets (nightly; outside the main workspace)
scripts/        Developer scripts, including the fixture generator
tests/          Cross-service end-to-end tests (from Milestone 5)
```

## Roadmap

| # | Milestone | State |
| --- | --- | --- |
| 0 | Foundation and developer environment | Done |
| 1 | Safe offline PCAP ingestion | Done |
| 2 | Core packet decoder (Ethernet, ARP, IPv4/6, ICMP, TCP, UDP) | Done |
| 3 | Application metadata (DNS, DHCP, HTTP/1.1, TLS handshake) | Done |
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
