# Data retention

FlowSentinel stores **metadata only**. This page lists what an import writes to PostgreSQL, what
is never stored, and how long stored data is kept.

## What is stored

| Table | One row per | Contents |
| --- | --- | --- |
| `capture_sessions` | Imported file | Sanitized file name, size, SHA-256, PCAP header facts, counts, time range, completion state, capture warnings, decode summary, flow summary, `created_at`, `expires_at` |
| `packets` | Stored packet | Index, time, lengths, decode status, endpoints, ports, flow ID, decoded layers (JSON), decode warnings, info line |
| `flows` | Retained flow | Endpoints, counters, statistics, TCP state, end reason, the full flow record (JSON) |
| `dns_events` | DNS packet | Transaction ID, query name and type, response code, answer summaries (addresses and names; other record data is never decoded) |
| `http_events` | HTTP packet | Method, host, path (query string removed, tokens masked), status, content type, whether anything was redacted |
| `tls_events` | TLS handshake packet | Handshake type, server name, ALPN, negotiated version, cipher-suite count |
| `retention_settings` | (one row) | The settings below |

Every value comes from the decoder and flow engine described in
[protocol-decoding.md](protocol-decoding.md), [application-metadata.md](application-metadata.md)
and [flow-engine.md](flow-engine.md). The same redaction rules apply.

## What is never stored

- Packet payloads or raw packet bytes: no column can hold them. The uploaded file, which does
  contain them, is deleted as soon as the import ends, whether it succeeds or fails. If the
  server is killed mid-import (for example out of memory or `kill -9`), the file stays in the
  upload directory until the server next starts, which deletes it before accepting requests.
  Keep the upload directory on storage only the server can read (the files are created with
  owner-only permissions on Unix).
- HTTP bodies, query strings, cookies, authorization headers and URL credentials.
- TLS random values, session IDs, key shares, tickets and certificates. TLS is never decrypted.
- DNS record data other than addresses and names, and DHCP options other than the five documented
  ones.
- The database URL or password, which never reach logs or error messages.

## Settings

```bash
curl http://127.0.0.1:8080/api/v1/settings/retention
# {"session_ttl_days":30,"max_packets_stored":100000}

curl -X PUT -H 'Content-Type: application/json' \
  -d '{"session_ttl_days":7,"max_packets_stored":10000}' \
  http://127.0.0.1:8080/api/v1/settings/retention
```

| Setting | Default | Range | Effect |
| --- | --- | --- | --- |
| `session_ttl_days` | 30 | 1–3650 | An import's `expires_at` is its import time plus this many days |
| `max_packets_stored` | 100,000 | 0–1,000,000 | Packets (with their DNS/HTTP/TLS events) stored per import, out of those analyzed. Flows and summaries cover every analyzed packet. `0` stores flows and summaries only |

The database enforces the same ranges. A change applies to **new imports only**: existing
captures keep their `expires_at` and stored packets.

An import analyzes at most `FLOWSENTINEL_MAX_PACKETS` packets (1,000,000 by default) within
`FLOWSENTINEL_MAX_ANALYSIS_SECONDS` (600 by default); a larger capture is stored partially and its
`completion_state` is `packet_limit_reached` or `time_limit_reached`. See [api.md](api.md).

## Expiry and deletion

- The server deletes every capture whose `expires_at` has passed, in the background right after
  it starts and then every hour.
  Each run is logged with the number of captures deleted.
- `DELETE /api/v1/captures/{id}` deletes a capture at once.
- Deleting a capture removes all its packets, flows and events in the same statement (foreign keys
  with `ON DELETE CASCADE`).

PostgreSQL reclaims the space of deleted rows through autovacuum. Deleted data can remain in the
database's files, write-ahead log and backups until those are rotated. Treat database storage
and backups with the same care as the captures themselves.

## Sizing

Stored packets dominate. Each packet row holds its decoded layers as JSON. Measured with
`pg_column_size` over the 70 packets of seven synthetic fixtures, rows took 745 bytes (ARP) to
1,999 bytes, 1,345 on average. DNS, HTTP and TLS packets averaged about 1.7–1.9 KB and plain
TCP or UDP packets about 1.0–1.3 KB, before indexes and table overhead. Lower
`max_packets_stored` to keep the database small; the flow table and summaries remain
complete.
