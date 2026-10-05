# Performance

This document covers how to measure FlowSentinel's speed and what we measured. All numbers
depend on the machine, the PostgreSQL setup and the captures. Treat them as orders of magnitude
and re-measure on your own hardware before sizing a deployment.

The measurements below were taken on 2026-10-05:

- **Machine:** a 4-vCPU cloud VM (Intel Xeon @ 2.10 GHz).
- **Server:** a release build of `api-server` with default settings.
- **Database:** PostgreSQL 16 on the same VM.

## Analysis pipeline benchmark

```sh
cargo bench -p analysis
```

The benchmark generates synthetic captures at run time, so no files are needed. Each capture
holds 200,000 Ethernet/IPv4/UDP packets with 32-byte payloads (18 MB). The benchmark runs the
same code `inspect`, `flows`, `detect` and API imports use (decoding, flow reconstruction and
optionally every detection rule) and reports the median of five runs. It uses only the standard
library: `criterion` needs a newer Rust than the project's minimum (1.85).

| Case | Time | Packets/s | Throughput |
| --- | --- | --- | --- |
| Decode + flows, one flow | 0.077 s | 2.6 million | 233 MB/s |
| Decode + flows + detection, one flow | 0.079 s | 2.5 million | 228 MB/s |
| Decode + flows, 60,000 flows | 0.290 s | 690,000 | 62 MB/s |
| Decode + flows + detection, 60,000 flows | 0.300 s | 670,000 | 60 MB/s |

Many flows cost more than many packets: each new flow is a hash-table insertion and a record kept
until the capture ends. Detection adds little because its state is bounded per rule (see
[detection-rules.md](detection-rules.md)).

## Imports through the API

An import also writes flows, packets and events to PostgreSQL in one transaction, which takes
most of the time. Import times for 100,000-packet captures, including a worst case for stored
TLS metadata, are in [api.md](api.md#importing-a-capture).

We also imported the benchmark's 60,000-flow capture: 200,000 packets, 18 MB.

- **Time:** 10.1 s.
- **Stored:** 60,000 flows and the default 100,000 packets.

## Reading through the API

The script `scripts/load_test.py` drives a running server, using only the Python standard
library:

```sh
FLOWSENTINEL_LOAD_PASSWORD=... python3 scripts/load_test.py \
    --url http://127.0.0.1:8080 --username admin --concurrency 16 --duration 30
```

It signs in once, then repeatedly reads six endpoints: a capture, a page of packets, flows sorted
by bytes, a filtered flow list, alerts and the overview. The account must exist, and if no capture
exists the script imports `fixtures/pcap/detect-mixed.pcap` first.

The script reports requests per second, the status codes seen, and the 50th, 95th and 99th
percentile latency per endpoint. It exits non-zero if any request failed. Point it only at a
server you run for testing: it creates load and, if needed, a capture.

On the small fixture, which measures the server's per-request cost rather than query size:

| Clients | Requests/s | p50 | p95 | p99 | Errors |
| --- | --- | --- | --- | --- | --- |
| 4 | 1,430 | 2–3 ms | 3–5 ms | 4–6 ms | 0 |
| 16 | 1,540 | 8–12 ms | 16–21 ms | 20–25 ms | 0 |
| 32 | 1,650 | 16–22 ms | 33–40 ms | 42–51 ms | 0 |

Throughput levels off because reads share a bounded set of database connections
(`FLOWSENTINEL_DB_MAX_CONNECTIONS`, default 10, minus two per import slot; see
[api.md](api.md#security-notes)). Beyond that point, more clients add waiting time instead of
throughput.

On the 60,000-flow capture above, single requests (median of five):

| Request | Time |
| --- | --- |
| Flows sorted by bytes, first page | 38 ms |
| Flows sorted by bytes, page 500 of 100 | 70 ms |
| Flows filtered by `flow.initiator_port > 50000 and flow.bytes > 100` (11,023 matches) | 46 ms |
| Flows filtered by `udp.port == 4242` (1 match) | 38 ms |
| Packets filtered by `udp.srcport == 4242` (2 matches of 100,000 stored) | 90 ms |
| Packets, page 1,000 of 100 | 111 ms |

Filtered lists scan the capture's rows. Each runs under `FLOWSENTINEL_QUERY_TIMEOUT_SECONDS`
(default 10), and at most half of the read slots may run filters at once. Further filtered
requests wait up to 5 seconds for a turn without holding a database connection, then get
`429 filter_busy`. An expensive filter therefore slows other filters, not the rest of the
dashboard.

## Fuzzing

The parsers and request-input checks have coverage-guided fuzz targets; see
[../fuzz/README.md](../fuzz/README.md). A run of `request_inputs` covered 5.7 million inputs in
120 seconds without a failure.
