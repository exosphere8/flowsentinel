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
- **Milestone 4, flow reconstruction:** `flowsentinel flows --pcap` groups packets into
  bidirectional flows with per-direction counters, size and timing statistics, approximate TCP
  state and application metadata, within fixed memory limits.
- **Milestone 5, persistence and REST API:** the API server imports PCAP uploads into PostgreSQL
  as metadata only (captures, packets, flows, DNS/HTTP/TLS events) and serves them with
  pagination, validated sorting, structured errors, retention controls and an OpenAPI
  description.
- **Milestone 6, display filters:** packet and flow lists accept Wireshark-like filters such as
  `ip.addr == 192.0.2.0/24 and tls.sni contains "example"`. Filters are type-checked against a
  field catalog, report errors with positions, and are translated into parameterized SQL.
- **Milestone 7, explainable detections:** `flowsentinel detect --pcap` and every API import run
  twelve configurable rules (scans, failed connections, beaconing, rare ports, large outbound
  transfers, cleartext logins, DNS volume and tunneling, ARP conflicts and floods). Each alert is
  a heuristic indicator with its evidence, cited flows or packets, uncertainty and likely false
  positives, never a verdict. Analysts triage alerts through the API.
- **Milestone 8, dashboard:** a React and TypeScript web dashboard served by the API server shows
  an overview, captures, packets with their protocol trees, flows, alerts with their evidence
  and triage, and settings. Tables are paged, sorted and filtered on the server, display filters
  are validated as they are typed, and no packet payload is ever rendered.
- **Milestone 9, accounts and auditing:** every API call needs a signed-in session. Accounts have
  the role viewer, analyst or admin; passwords are hashed with Argon2id. Sessions expire after
  inactivity and after a fixed lifetime, state changes need a CSRF token, repeated failed
  sign-ins are locked out, and a security audit log records sign-ins, refusals and every change.

## Quick start

Requirements: Rust 1.85+ (stable), Docker with Compose v2, Node.js 22.22+ for the dashboard, and
optionally `make`.

```bash
git clone https://github.com/exosphere8/flowsentinel.git
cd flowsentinel
cp .env.example .env            # replace each "change-me", using the same password in
                                # POSTGRES_PASSWORD and FLOWSENTINEL_DATABASE_URL

docker compose up -d --wait     # PostgreSQL + Redis, waits for health checks
make admin                      # creates the first admin account (asks for a name and password)
make dev                        # loads .env, migrates the database, serves http://127.0.0.1:8080
```

Without `make`, export the variables from `.env` yourself and run `cargo run -p api-server`; create
the first admin with `cargo run -p api-server -- create-user --username NAME --role admin`, which
reads the password from standard input. Accounts, roles, sessions and the audit log are described
in [docs/authentication.md](docs/authentication.md).

### Dashboard

Build the dashboard and let the API server serve it on the same address:

```bash
make dashboard                                    # npm ci and npm run build in frontend/
FLOWSENTINEL_DASHBOARD_DIR=frontend/dist make dev  # http://127.0.0.1:8080
```

Or run everything in containers, with the server and dashboard built into one image that runs as
an unprivileged user:

```bash
docker compose --profile app up -d --build --wait   # http://127.0.0.1:8080
read -rs PW && printf '%s\n' "$PW" | docker compose --profile app exec -T app \
  flowsentinel-api create-user --username admin --role admin
```

Sign in, then import a capture on the **Captures** page, for example `fixtures/pcap/detect-mixed.pcap`. See
[docs/dashboard.md](docs/dashboard.md) for the pages, the development server, security headers
and tests.

In another terminal:

```bash
curl http://127.0.0.1:8080/health
# {"status":"ok","service":"flowsentinel-api"}

# Sign in (everything else answers 401 without a session); keep the cookie and the CSRF token.
read -rs PW && CSRF=$(curl -s -c cookies.txt -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$PW\"}" http://127.0.0.1:8080/api/v1/auth/login \
  | sed -n 's/.*"csrf_token":"\([0-9a-f]*\)".*/\1/p')

curl -b cookies.txt -H "X-CSRF-Token: $CSRF" -X POST -H 'Content-Type: application/vnd.tcpdump.pcap' \
  --data-binary @fixtures/pcap/flows-mixed.pcap \
  'http://127.0.0.1:8080/api/v1/captures?file_name=flows-mixed.pcap'
curl -b cookies.txt 'http://127.0.0.1:8080/api/v1/captures/1/flows?sort=-bytes'
curl -b cookies.txt -G 'http://127.0.0.1:8080/api/v1/captures/1/packets' --data-urlencode 'filter=tcp.port == 443'
curl -b cookies.txt 'http://127.0.0.1:8080/api/v1/captures/1/alerts'
rm cookies.txt

cargo run -p cli -- --version
# flowsentinel 0.1.0
```

The API, its errors and limits are described in [docs/api.md](docs/api.md); what is stored and
for how long in [docs/data-retention.md](docs/data-retention.md). The OpenAPI description is
served at `/api/v1/openapi.json`.

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

### Reconstruct flows

```bash
cargo run -p cli -- flows --pcap fixtures/pcap/flows-mixed.pcap
cargo run -p cli -- flows --pcap fixtures/pcap/flows-mixed.pcap --sort bytes --json
```

```text
      ID  Proto  Initiator              Responder              Packets       Bytes    Duration  State         Application
       1  UDP    192.0.2.10:53100       192.0.2.53:53                2         166      0.020s  -             DNS www.example.com
       2  TCP    192.0.2.10:40500       198.51.100.80:443            9        1017      0.211s  closed        TLS www.example.com
       3  TCP    192.0.2.10:40501       198.51.100.80:8080           2         108      0.001s  reset         (www.example.com)
```

Both directions of a conversation form one flow. The initiator comes from the TCP handshake when
one is seen, otherwise from the first packet, never from address order. See
[docs/flow-engine.md](docs/flow-engine.md) for statistics, timeouts, memory limits and JSON.

### Run the detection rules

```bash
cargo run -p cli -- detect --pcap fixtures/pcap/detect-mixed.pcap
cargo run -p cli -- detect --pcap fixtures/pcap/detect-mixed.pcap --config config/detection.example.toml --json
```

```text
Alerts are heuristic indicators: observed patterns to review, not proof of compromise.

[1] Possible SYN scan (FS-SCAN-SYN), medium severity, medium confidence
  When       2026-01-01T00:00:01.000000Z
  Endpoints  192.0.2.66 -> 198.51.100.20
  Evidence   distinct_ports_unanswered_or_refused=25, threshold=20, window=60 s
  ...
```

Every alert explains what was measured, why it may be wrong and which benign activity looks the
same. See [docs/detection-rules.md](docs/detection-rules.md) for the rules, thresholds and limits.

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
| `FLOWSENTINEL_DATABASE_URL` | (required by the API) | PostgreSQL URL; never logged |
| `FLOWSENTINEL_MAX_UPLOAD_MB` | 512 | Largest accepted upload |
| `FLOWSENTINEL_MAX_CONCURRENT_IMPORTS` | 2 | Imports processed at once |
| `FLOWSENTINEL_DB_MAX_CONNECTIONS` | 10 | Database connection pool size |
| `FLOWSENTINEL_UPLOAD_DIR` | system temp dir | Where uploads are kept while analyzed (one directory per server) |
| `FLOWSENTINEL_MAX_PACKETS` | 1000000 | Packets analyzed per import |
| `FLOWSENTINEL_MAX_ANALYSIS_SECONDS` | 600 | Processing time per import's first pass |
| `FLOWSENTINEL_ALLOWED_HOSTS` | loopback names | `Host` names the API answers (comma-separated, or `*`) |
| `FLOWSENTINEL_QUERY_TIMEOUT_SECONDS` | 10 | Time limit for one filtered list query |
| `FLOWSENTINEL_DETECTION_CONFIG` | built-in thresholds | Detection thresholds (TOML; see `config/detection.example.toml`) |
| `FLOWSENTINEL_DASHBOARD_DIR` | not set | Built dashboard to serve at `/` (`frontend/dist`) |
| `FLOWSENTINEL_PORT` | 8080 | Port the Compose `app` container is published on (127.0.0.1 only) |
| `FLOWSENTINEL_SESSION_IDLE_MINUTES` | 30 | A session ends after this long without a request |
| `FLOWSENTINEL_SESSION_MAX_HOURS` | 12 | A session ends this long after sign-in |
| `FLOWSENTINEL_SECURE_COOKIES` | `false` | `true` when served through HTTPS: `Secure`, `__Host-` session cookie |
| `FLOWSENTINEL_AUDIT_RETENTION_DAYS` | 365 | Days audit events are kept |
| `FLOWSENTINEL_ADMIN_USERNAME`, `FLOWSENTINEL_ADMIN_PASSWORD_FILE` | `admin`, not set | Creates the first admin from a password file while no account exists |
| `RUST_LOG` | `info` | Log filter; logs are structured JSON on stdout |
| `POSTGRES_*`, `REDIS_*` | see `.env.example` | Docker Compose services |

Keep the server on loopback, or put it behind an HTTPS reverse proxy and set
`FLOWSENTINEL_SECURE_COOKIES=true`; it logs a warning when it listens on a non-loopback address
without secure cookies. See [docs/authentication.md](docs/authentication.md).

## Development

| Command | Action |
| --- | --- |
| `make up` / `make down` | Start or stop PostgreSQL and Redis |
| `make dev` | Run the API server with the settings in `.env` |
| `make admin` | Create an admin account (asks for a name and a password) |
| `make fmt` | Format code |
| `make lint` | Clippy with `-D warnings` |
| `make test` | Run all tests (database tests skip without a server) |
| `make test-db` | Run the storage and API tests against the Compose PostgreSQL |
| `make check` | Full CI gate: format check, lint, test, build |
| `make fixtures` | Regenerate the synthetic PCAP fixtures |
| `make dashboard` | Install the dashboard's dependencies and build it into `frontend/dist` |
| `make frontend-check` | Dashboard API-type check, lint, type check and unit tests |
| `make e2e` | Dashboard end-to-end smoke tests (needs a running server; see docs/dashboard.md) |

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Repository layout

```
crates/
  analysis/     Two-pass analysis pipeline (capture, decode, flows) with bounded memory
  api-server/   Axum HTTP service: /health and the /api/v1 metadata API
  capture/      Classic PCAP container reader with resource limits
  cli/          `flowsentinel` command-line tool
  decoder/      Bounds-checked protocol and application-metadata decoder
  detection-engine/  Explainable heuristic rules over flows, DNS and ARP metadata
  filter-language/  Display-filter lexer, parser, type checker and SQL translation
  flow-engine/  Bidirectional flow reconstruction with bounded memory
  storage/      PostgreSQL persistence (SQLx, embedded migrations, retention)
config/         Example configuration (detection thresholds)
docs/           Design and user documentation
fixtures/       Synthetic test inputs only (fixtures/pcap/ is generated)
frontend/       React + TypeScript dashboard (Vite, Vitest, Playwright)
fuzz/           cargo-fuzz targets (nightly; outside the main workspace)
scripts/        Developer scripts, including the fixture generator
tests/          Notes on where the cross-crate and cross-service tests live
```

## Roadmap

| # | Milestone | State |
| --- | --- | --- |
| 0 | Foundation and developer environment | Done |
| 1 | Safe offline PCAP ingestion | Done |
| 2 | Core packet decoder (Ethernet, ARP, IPv4/6, ICMP, TCP, UDP) | Done |
| 3 | Application metadata (DNS, DHCP, HTTP/1.1, TLS handshake) | Done |
| 4 | Bidirectional flow reconstruction | Done |
| 5 | PostgreSQL persistence and REST API | Done |
| 6 | Display-filter language | Done |
| 7 | Explainable rule-based detection | Done |
| 8 | React dashboard | Done |
| 9 | Authentication, RBAC and auditing | Done |
| 10 | Authorized live capture | Planned |
| 11 | Observability, performance and hardening | Planned |
| 12 | Public release (v0.1.0) | Planned |

## License

[MIT](LICENSE) © exosphere8. Built by [exosphere8](https://github.com/exosphere8).
