# REST API

`api-server` imports classic PCAP files and serves their **metadata** over HTTP: captures,
packets, flows, DNS, HTTP and TLS handshake events, and the alerts raised by the detection
rules. No endpoint returns packet payloads, and
TLS is never decrypted. The full OpenAPI 3.1 description is served at
`GET /api/v1/openapi.json`.

> Every endpoint except `POST /auth/login` and `GET /health` needs a signed-in session, and
> state-changing requests also need the session's CSRF token in `X-CSRF-Token`. Roles decide who
> may import, triage, delete and change settings. See [authentication.md](authentication.md).
> Import only captures you own or are authorized to analyze.

## Running

```bash
cp .env.example .env      # set POSTGRES_PASSWORD and the same password in FLOWSENTINEL_DATABASE_URL
make up                   # PostgreSQL via Docker Compose
make dev                  # loads .env and runs the server on 127.0.0.1:8080
```

At startup the server deletes upload files that an earlier run left behind (for example when it
was killed mid-import), connects to PostgreSQL and applies the embedded, checksummed migrations
(`crates/storage/migrations`). It then starts listening, and deletes expired captures in the
background right away and every hour after (see [data-retention.md](data-retention.md)). It
refuses to start if `FLOWSENTINEL_DATABASE_URL` is missing or invalid, if the database is
unreachable, if a setting is out of range, or if `FLOWSENTINEL_DETECTION_CONFIG` names a
file that cannot be read or is invalid. On Ctrl+C or SIGTERM it stops accepting
connections and gives running requests 30 seconds to finish; requests still running then are
cancelled and their upload files deleted.

| Variable | Default | Purpose |
| --- | --- | --- |
| `FLOWSENTINEL_API_ADDR` | `127.0.0.1:8080` | Listen address |
| `FLOWSENTINEL_DATABASE_URL` | (required) | `postgres://USER:PASSWORD@HOST:PORT/DATABASE`; never logged |
| `FLOWSENTINEL_MAX_UPLOAD_MB` | 512 | Largest accepted upload (1–65536) |
| `FLOWSENTINEL_MAX_CONCURRENT_IMPORTS` | 2 | Imports processed at once (1–16); more get `429` |
| `FLOWSENTINEL_DB_MAX_CONNECTIONS` | 10 | Connection pool size (1–100); see [Security notes](#security-notes) for how it is shared |
| `FLOWSENTINEL_QUERY_TIMEOUT_SECONDS` | 10 | Time limit for one filtered packet or flow list (1–300); slower queries get `503 query_timeout` |
| `FLOWSENTINEL_UPLOAD_DIR` | system temp dir | Where uploads are written while they are analyzed. Give each server its own directory: leftover `flowsentinel-upload-*.pcap` files in it are deleted at startup |
| `FLOWSENTINEL_MAX_PACKETS` | 1000000 | Packets analyzed per import (1–1000000); more are left out and the import is partial |
| `FLOWSENTINEL_MAX_ANALYSIS_SECONDS` | 600 | Processing time for an import's first pass (1–3600) |
| `FLOWSENTINEL_ALLOWED_HOSTS` | loopback names | Comma-separated `Host` names the server answers, or `*`; see [Host names](#host-names) |
| `FLOWSENTINEL_DETECTION_CONFIG` | built-in thresholds | TOML file of detection thresholds (see [detection-rules.md](detection-rules.md)) |
| `FLOWSENTINEL_DASHBOARD_DIR` | not set | Built dashboard to serve at `/` (see [dashboard.md](dashboard.md)); the server refuses to start if it has no `index.html` |
| `RUST_LOG` | `info` | Log filter; logs are JSON lines on stdout |

`flowsentinel-api healthcheck` (or `cargo run -p api-server -- healthcheck`) requests
`GET /health` from the server at `FLOWSENTINEL_API_ADDR` (through loopback when it listens on
`0.0.0.0` or `::`) and exits with status 0 if it answers `200` within 5 seconds, 1 otherwise. The
container image uses it as its health check.

## Importing a capture

Sign in first and keep the cookie and CSRF token (see
[authentication.md](authentication.md#csrf-protection)); importing needs the analyst or admin
role.

```bash
curl -b cookies.txt -H "X-CSRF-Token: $CSRF" -X POST \
  -H 'Content-Type: application/vnd.tcpdump.pcap' \
  --data-binary @fixtures/pcap/flows-mixed.pcap \
  'http://127.0.0.1:8080/api/v1/captures?file_name=flows-mixed.pcap'
```

The response is `201 Created` with a `Location: /api/v1/captures/{id}` header and the stored
capture (the same body as `GET /api/v1/captures/{id}`).

How an upload is handled:

1. **Request checks.** `file_name` must end in `.pcap` and is reduced to a sanitized final path
   component (`/` and `\` both separate components, on every platform). Names longer than 128
   characters are shortened and keep their `.pcap` ending, for example `aaaa...pcap`. The body must be the raw file with `Content-Type:
   application/vnd.tcpdump.pcap` or `application/octet-stream`. Multipart forms are rejected,
   and neither type can be sent cross-site without a CORS preflight, which the API does not
   allow. A `Content-Length` above the limit is rejected before anything is read.
2. **Streaming to disk.** The body is streamed to a new file with a random name in the upload
   directory, created with owner-only permissions on Unix. The size limit is enforced while
   streaming, and the SHA-256 is computed on the way. An upload that stalls for 30 seconds, or
   that averages less than 16 KiB/s after its first 30 seconds, is abandoned (`408`), so a slow
   client cannot hold an import slot indefinitely. The slot stays taken until the analysis
   threads finish, even if the client disconnects.
3. **Pass 1.** The file is read with the same limits and validation as `flowsentinel inspect`. It
   decodes every packet and reconstructs flows. Only summaries, flows and a fingerprint of the
   packets to be stored are kept.
4. **Pass 2.** The first `max_packets_stored` packets (a retention setting) are decoded again. The
   flow engine is replayed to recover each packet's flow ID, and the packets are written in
   batches of 1,000 through a bounded queue. Memory stays bounded however large the file is.
5. **One transaction.** The session, flows, packets and events are committed together. If
   anything fails, or the file's fingerprint differs between the passes, nothing is stored.
6. **Cleanup.** The temporary file is deleted in every case.

Measured with a release build against a local PostgreSQL 16 on the same machine as the tables in
[flow-engine.md](flow-engine.md), default settings. `same` and `distinct` are the synthetic UDP
captures described there; `tls` is a worst case for stored metadata, 100,000 TLS ClientHellos
each with a 255-character server name, 16 ALPN values, 64 groups and 64 more extensions (156 MB):

| Capture (100,000 packets each) | Import time | Server peak RSS | Stored |
| --- | --- | --- | --- |
| `same` (1 flow) | 3.4 s | 37 MB | 100,000 packets, 1 flow |
| `distinct` (100,000 flows) | 6.9 s | 194 MB | 100,000 packets, 100,000 flows |
| `tls` (60,000 flows) | 24.6 s | 262 MB | 100,000 packets with TLS events, 60,000 flows |
| `tls`, two imports at once | 25 s for both | 644 MB | 868 MB of database for the two |

Pass 1 keeps the flow records; pass 2 passes packets through in batches of 1,000, each packet's
metadata held as serialized JSON text until it is written. Peak memory therefore grows with the
number of flows and the number of concurrent imports (`FLOWSENTINEL_MAX_CONCURRENT_IMPORTS`),
not with the size of the file.

## Endpoints

All paths are under `/api/v1`. IDs are integers.

| Method and path | Returns |
| --- | --- |
| `POST /captures?file_name=NAME.pcap` | Import a capture (above) |
| `GET /captures` | Captures, newest first |
| `GET /captures/{id}` | One capture with its capture warnings, decode summary and flow summary |
| `DELETE /captures/{id}` | Deletes the capture and everything stored for it (`204`) |
| `GET /captures/{id}/packets` | Packet summaries: index, time, lengths, decode status, top protocol, endpoints, ports, flow ID, info line. Takes `filter` and `flow_id` |
| `GET /captures/{id}/packets/{index}` | One packet with its decoded protocol tree and decode warnings |
| `GET /captures/{id}/flows` | Flow summaries. Takes `filter` |
| `GET /captures/{id}/flows/{flow_id}` | One flow with its full record (statistics, TCP state, application metadata) |
| `GET /captures/{id}/dns` | DNS messages: transaction, query name and type, response code, answers |
| `GET /captures/{id}/http` | HTTP request and response metadata, already redacted by the decoder |
| `GET /captures/{id}/tls` | Visible TLS handshake metadata (SNI, ALPN, version, cipher-suite count) |
| `GET /captures/{id}/alerts` | Alerts raised for the capture. Takes `severity`, `status` and `rule` |
| `GET /captures/{id}/alerts/{alert_id}` | One alert with its evidence, explanation and cited flows and packets |
| `PATCH /captures/{id}/alerts/{alert_id}` | Changes an alert's triage status; body `{"status": "acknowledged"}` |
| `GET /overview` | Totals across all captures: captures, packets, flows, alerts by severity and status, open alerts by severity, and the five most recent imports |
| `GET /rules` | The detection rule catalog |
| `GET /filters/validate?target=packets\|flows&filter=...` | Checks a display filter; returns its normalized form |
| `GET /filters/fields?target=packets\|flows` | Filterable fields with types, operators and allowed values |
| `GET /settings/retention`, `PUT /settings/retention` | Retention settings (see [data-retention.md](data-retention.md)) |
| `GET /openapi.json` | OpenAPI description |
| `POST /auth/login`, `GET /auth/session`, `POST /auth/logout`, `PUT /auth/password` | Sessions and passwords (see [authentication.md](authentication.md#endpoints)) |
| `GET /users`, `POST /users`, `PATCH /users/{id}`, `DELETE /users/{id}` | Accounts (admin) |
| `GET /audit` | The audit log (admin) |
| `GET /live/interfaces`, `POST /live/captures`, `GET /live/captures/current`, `POST /live/captures/current/stop` | Authorized live capture (admin; see [live-capture.md](live-capture.md)) |
| `GET /health` (no prefix) | Liveness: `{"status":"ok","service":"flowsentinel-api"}` |
| `GET /ready` (no prefix) | Readiness: `200` when the database answers, otherwise `503` (see [observability.md](observability.md#health-and-readiness)) |
| `GET /` and other paths outside `/api/v1` (no prefix) | The dashboard, when `FLOWSENTINEL_DASHBOARD_DIR` is set; otherwise `404` |

Packets and events exist only for the stored packets of a capture. Flows and summaries always
cover the whole capture, up to the flow engine's retention limit (`flows_stored` against
`flows_total`).

### Pagination and sorting

List endpoints take `page` (1–1,000,000, default 1) and `per_page` (1–500, default 50). They
return:

```json
{ "items": [ ... ], "page": 1, "per_page": 50, "total": 19 }
```

`sort` accepts a fixed set of values; anything else is rejected with `invalid_sort`:

| Endpoint | `sort` values |
| --- | --- |
| `/captures` | `newest` (default), `oldest`, `packets`, `size` |
| `/captures/{id}/packets` | `index` (default), `-index`, `time`, `-length` |
| `/captures/{id}/flows` | `start` (default), `-bytes`, `-packets`, `-duration` |
| `/captures/{id}/alerts` | `severity` (default: most severe first), `time`, `id` |

`/captures/{id}/packets` also takes `flow_id` to list one flow's packets. Both packet and flow
lists take `filter`, a display filter such as `tcp.port == 443 and not ip.addr == 10.0.0.0/8`;
see [filter-language.md](filter-language.md). Unknown query parameters are rejected with
`invalid_query`.

### Alerts

Each import runs the detection rules described in [detection-rules.md](detection-rules.md) over
the whole capture, and stores the alerts with it. The capture reports `alerts_total` and a
`detection_summary`; each stored flow reports `alert_count` and `max_alert_severity`.

**Every alert is a heuristic indicator that deserves review, not proof of compromise**, and each
response says so in its `nature` field, next to the rule's uncertainty and likely false
positives.

```bash
curl -b cookies.txt 'http://127.0.0.1:8080/api/v1/captures/1/alerts?severity=high'
curl -b cookies.txt -H "X-CSRF-Token: $CSRF" -X PATCH -H 'Content-Type: application/json' \
  -d '{"status":"false_positive"}' \
  'http://127.0.0.1:8080/api/v1/captures/1/alerts/4'
```

`severity` takes `low`, `medium` or `high`; `status` takes `open`, `acknowledged`, `resolved` or
`false_positive`; `rule` takes a rule ID from `GET /rules`. Other values are rejected
(`invalid_severity`, `invalid_status`, `invalid_rule`). Only the status of an alert can change;
the change is logged with the capture and alert IDs and recorded in `status_changed_at`. Flows can
be filtered by their alerts, for example `filter=alert.severity == high`.

### Times

Packet times are reported both as Unix nanoseconds (`ts_ns`, `first_seen_ns`, ...) and as RFC 3339
UTC strings with nanosecond precision (`time`, `first_seen`, ...). Capture times
(`created_at`, `expires_at`) are RFC 3339 UTC.

## Errors

Every error is JSON with a stable `code`:

```json
{ "error": { "code": "invalid_per_page", "message": "per_page must be between 1 and 500" } }
```

| Status | Codes |
| --- | --- |
| 400 | `invalid_query`, `invalid_path`, `invalid_page`, `invalid_per_page`, `invalid_sort`, `invalid_target`, `unsupported_extension`, `empty_upload`, `upload_interrupted`, `invalid_ttl`, `invalid_max_packets`, `invalid_body` (malformed JSON); accounts: `invalid_username`, `weak_password`, `wrong_password`, `nothing_to_change`, `cannot_delete_self`; audit filters: `invalid_action`, `invalid_outcome`, `invalid_actor`; filter errors (`unknown_field`, `syntax_error`, `invalid_value`, ... with a `position`; see [filter-language.md](filter-language.md#limits-and-errors)) |
| 401 | `unauthenticated` (no session, or it ended); `invalid_credentials` (sign-in) |
| 403 | `forbidden` (the role does not allow it); `csrf_token_invalid`; `cross_site_request` |
| 404 | `not_found` (unknown capture, packet, flow, account or endpoint) |
| 405 | `method_not_allowed` |
| 409 | `username_taken`; `last_admin` (it would leave no enabled admin) |
| 408 | `upload_timeout` |
| 413 | `upload_too_large`; `invalid_body` for a JSON body over 16 KiB |
| 415 | `unsupported_media_type`; `invalid_body` for a JSON body without `Content-Type: application/json` |
| 422 | Capture errors with the same codes as the CLI (`invalid_magic`, `unsupported_format`, `truncated_record_data`, ...); `invalid_body` for well-formed JSON with missing or unknown fields |
| 429 | `import_busy`; `filter_busy` (too many filtered lists running); `too_many_attempts` (sign-in lockout, with `Retry-After`) |
| 500 | `internal_error`; the cause is logged, never returned |
| 421 | `invalid_host`: the `Host` header is not one the server answers |
| 503 | `database_unavailable`; `server_busy` (no database slot within 10 seconds); `query_timeout` (a filtered list took longer than its limit) |

Messages never contain SQL, file paths, stack traces or packet data. Client-supplied text echoed
in a message is cut at 200 characters.

## Security notes

- Every query is parameterized. Sort orders map to fixed SQL fragments. Display filters are
  translated into fixed SQL fragments plus bound parameters; filter text never becomes SQL.
- No table has a column for payload bytes; see [data-retention.md](data-retention.md) for what is
  stored.
- JSON request bodies are limited to 16 KiB; uploads to `FLOWSENTINEL_MAX_UPLOAD_MB`.
- Every response, including errors and dashboard files, carries a Content Security Policy,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, a
  `Permissions-Policy` that turns off device APIs, and an `X-Request-Id`. With
  `FLOWSENTINEL_SECURE_COOKIES=true` it also carries `Strict-Transport-Security`. API responses
  are sent with `Cache-Control: no-store`. See [dashboard.md](dashboard.md#security) and
  [observability.md](observability.md#request-ids).
- The server sends no CORS headers, so browsers do not let other sites read API responses.
- Concurrent imports are limited, and each import's work is bounded by the capture limits and
  the flow engine's limits: `FLOWSENTINEL_MAX_UPLOAD_MB`, `FLOWSENTINEL_MAX_PACKETS` (1,000,000)
  and `FLOWSENTINEL_MAX_ANALYSIS_SECONDS` (600) for the first pass. A larger capture is imported
  partially, and its `completion_state` says which limit stopped it: `complete`,
  `packet_limit_reached` or `time_limit_reached`.
- Reads and settings changes share the database pool minus two connections per import slot
  (at least one), so heavy reading cannot starve imports. A request that waits more than 10
  seconds for a slot gets `503 server_busy`. Filtered packet and flow lists may use at most half
  of these slots at once; more wait up to 5 seconds for a turn, without holding a slot, and then
  get `429 filter_busy`. They run under `FLOWSENTINEL_QUERY_TIMEOUT_SECONDS`.
- PostgreSQL ends any statement running longer than five minutes and any transaction left idle
  for five minutes, so a stuck request cannot hold locks. Connections are named
  `flowsentinel-api` in `pg_stat_activity`. TLS to the database follows the URL's `sslmode`; see
  [hardening.md](hardening.md#database).

### Host names

A web page on another site can make its own DNS name resolve to 127.0.0.1 and then send requests
that the browser treats as same-origin ("DNS rebinding"). To prevent this, the API answers only
requests whose `Host` header names the server: by default `localhost`, `127.0.0.1`, `::1` and the
listen address when it is a specific one. Other names get `421 invalid_host`. When clients reach
the server by another name or address (for example in a container, or on a lab network), list
them in `FLOWSENTINEL_ALLOWED_HOSTS`, for example `analyzer.lab.example,192.0.2.5`. `*` disables
the check. `GET /health` is answered for any host.

## Tests

`crates/api-server/tests/api.rs` drives every endpoint in-process against a real, disposable
PostgreSQL database: imports, pagination, sorting, structured errors, upload validation,
retention, `Host` checks, long and Windows-style file names, uploads far larger than the JSON
body limit, partial imports, display filters, alerts and their triage, the OpenAPI document, and
privacy. The privacy test fetches every list and detail endpoint, alerts included, for every
application fixture and the detection fixture, and checks that no secret or payload marker
appears.
See [CONTRIBUTING.md](../CONTRIBUTING.md#database-tests) for running them.
