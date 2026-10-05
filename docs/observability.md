# Observability

FlowSentinel's API server reports what it is doing through four channels:

- structured logs with request IDs;
- health and readiness probes;
- Prometheus metrics;
- optional OpenTelemetry traces.

None of them carries packet data, request bodies, query strings, passwords, session tokens or
cookies.

## Request IDs

Every response has an `X-Request-Id` header.

- If the request sent an `X-Request-Id` of 1 to 64 letters, digits, `.`, `_` or `-`, that value
  is kept, so a reverse proxy's ID follows the request through.
- Otherwise the server generates a random 32-character hexadecimal ID.

Quote the ID when reporting a problem.

- **Log lines.** Every log line written while the request is answered carries the ID. This holds
  whatever `RUST_LOG` filters out: the request span is created at `ERROR` level, so it stays
  whenever any log line is written.
- **Live captures.** A capture runs on after its start request has been answered. Its later lines
  carry the start request's ID in a `live_capture` span instead.

## Logs

Logs are JSON lines on stdout. `RUST_LOG` sets the level and filters (default `info`; for
example `RUST_LOG=info,sqlx=warn`).

Each request produces one access-log line with target `access`. A request the client abandons
before the answer is logged too, with status `499`. The line is written within the request's
`request` span, so it carries the request ID. This line was logged for
`GET /api/v1/captures/5/flows?filter=...` without a session:

```json
{"timestamp":"2026-10-05T05:18:18.757446Z","level":"INFO","fields":{"message":"request","route":"/api/v1/captures/{id}/flows","status":401,"duration_ms":0},"target":"access","span":{"method":"GET","request_id":"doc-example-1","name":"request"}}
```

- **`route`** is the matched route template, never the request path, so capture IDs and query
  strings (which may hold display filters) are not logged. This holds even when the request is
  refused, for example without a session or from another site. Responses without a route have
  fixed labels:

  | Label | Responses |
  | --- | --- |
  | `misdirected` | `421`, refused because of the `Host` header |
  | `method_not_allowed` | `405` for an API path |
  | `unmatched` | Other API paths that match no route |
  | `dashboard` | Dashboard files |
  | `/health`, `/ready` | The probes themselves |
- **`method`** is one of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, or
  `OTHER`.

To leave out access lines, set `RUST_LOG=info,access=warn`.

Other events (imports, sign-ins, live captures, errors) are logged with their own fields. The
audit log in PostgreSQL ([authentication.md](authentication.md#the-audit-log)) is the record of who
did what; logs are for operating the server.

## Health and readiness

Both probes are outside `/api/v1`, need no session, and are answered whatever the `Host`
header.

| Endpoint | Answers | Use |
| --- | --- | --- |
| `GET /health` | `200 {"status":"ok","service":"flowsentinel-api"}` whenever the process serves HTTP | Liveness: restart the process if it fails |
| `GET /ready` | `200 {"status":"ready","database":"ok"}` when PostgreSQL answers within 2 seconds; otherwise `503 {"status":"not_ready","database":"unavailable"}`. The database is checked at most once a second; concurrent probes share the check | Readiness: send traffic only when it passes |

Do not use `/ready` for liveness: a database outage should not restart every API process. The
container image's `HEALTHCHECK` (`flowsentinel-api healthcheck`) probes `/health`.

## Metrics

Metrics are off by default. Set `FLOWSENTINEL_METRICS_ADDR` (for example `127.0.0.1:9464`) to serve
`GET /metrics` in the Prometheus text format on that address. This is a separate listener from
the API.

> **The metrics listener has no authentication.** Keep it on loopback or a private network that
> only your metrics collector can reach. The server logs a warning when it listens on a
> non-loopback address. Metrics contain no capture data, but they reveal request rates, error
> rates and sign-in failures.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `flowsentinel_build_info` | gauge | `version` | Always 1; the running version |
| `flowsentinel_uptime_seconds` | gauge | | Seconds since the server started |
| `flowsentinel_http_requests_total` | counter | `method`, `route`, `status` | Requests answered |
| `flowsentinel_http_request_duration_seconds` | histogram | `method`, `route` | Time to answer, buckets from 1 ms to 10 s |
| `flowsentinel_audit_events_total` | counter | `action`, `outcome` | Audited events, such as `auth.login`/`failure` or `live.start`/`denied` |
| `flowsentinel_db_connections` | gauge | | Open database connections |
| `flowsentinel_db_idle_connections` | gauge | | Idle database connections |
| `flowsentinel_imports_in_progress` | gauge | | Imports and live captures holding an import slot |

Labels come only from fixed sets: route templates, the methods above, status codes, and audit
action names and outcomes. The number of series therefore stays bounded whatever clients send.
Counters live in memory and restart from zero when the server restarts.

A Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: flowsentinel
    static_configs:
      - targets: ["127.0.0.1:9464"]
```

Some useful queries and alerts:

- Server errors: `sum(rate(flowsentinel_http_requests_total{status=~"5.."}[5m]))`
- Overload: `sum(rate(flowsentinel_http_requests_total{status=~"429|503"}[5m]))`
- Possible password guessing: `rate(flowsentinel_audit_events_total{action="auth.login",outcome="failure"}[15m])`
- 95th-percentile latency per route: `histogram_quantile(0.95, sum by (le, route) (rate(flowsentinel_http_request_duration_seconds_bucket[5m])))`

## OpenTelemetry traces

Builds with the `otel` feature can export traces with OTLP over HTTP/protobuf, to `http://` or
`https://` endpoints:

```sh
cargo build --release -p api-server --features otel
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 ./target/release/api-server
```

- **When it exports.** Only when `OTEL_EXPORTER_OTLP_ENDPOINT` or
  `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set. The exporter also reads the other standard
  `OTEL_EXPORTER_OTLP_*` variables, such as headers and timeout.
- **HTTPS.** Endpoints are verified against the system's certificate store, or the bundle named
  by `SSL_CERT_FILE`.
- **What it exports.** Only the `request` spans (with request ID and method), the `live_capture`
  spans, and the access-log events (route template, status, duration). They are reported with
  the service name `flowsentinel-api`. Other log events, such as warnings or anything about
  accounts, stay in the logs.
- **On shutdown.** Spans still buffered are flushed.
- **Default builds.** Without the feature, the server ignores these variables.
