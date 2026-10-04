# Authorized live capture

Admins can record traffic from one of the server's network interfaces for a limited time and
analyze it like an imported capture. This document covers how it works, how to turn it on, its
limits and the API. [permissions.md](permissions.md) explains how to give the server the capture
permission it needs without running it as root.

> **Capture only traffic you are authorized to inspect.** Every start requires an explicit
> confirmation (`"authorized": true`). Every start, stop and result is recorded in the audit log
> with the admin's account and address. Live capture is passive: it never sends packets, never
> decrypts anything, and changes nothing on the interface except promiscuous mode, which is off
> unless requested.

## How it works

1. An admin picks an interface and, optionally, a capture filter (BPF) and limits.
2. The server checks the request. Then:
   - libpcap compiles the filter without opening an interface, so a bad filter is refused
     before capturing starts;
   - the interface is opened with:
     - promiscuous mode off unless requested;
     - non-blocking reads, so a capture notices stop requests and its time limit within a fraction
       of a second even when no traffic arrives (on Linux, libpcap's own read timeout does not
       start until a packet arrives);
     - the snapshot length (bytes kept per packet).
3. A capture thread reads packets and passes them through a bounded channel of 1,024 packets to
   a writer thread.
   - The writer appends them to a private temporary file in the upload directory (owner-only
     permissions on Unix), as a classic pcap file.
   - If the writer falls behind, for example on a slow disk, the capture thread does not wait or
     queue more. It drops the packet and counts it in `dropped_backpressure`.
   - Memory therefore stays bounded by 1,024 packets of at most the snapshot length.
   - Packets the kernel or the interface dropped are reported in `dropped_by_system`.
4. The capture stops at the first of:
   - its time limit;
   - its packet limit;
   - its file-size limit;
   - an admin's stop request.
5. The file is then imported exactly like an upload, and stored as metadata only with source
   `live`. The temporary file is deleted, whether the import succeeds or fails. If the server is
   killed mid-capture, the file is deleted at the next startup with other leftover uploads.

At most one live capture runs at a time. It holds one import slot from start to finish, so it can
always be stored when it ends.

## Turning it on

Live capture needs two things.

**1. A build with libpcap.**

- Build with the `live-capture` feature:
  `cargo build --release -p api-server --features live-capture`.
- On Debian or Ubuntu this needs `libpcap-dev`. On Windows it needs the Npcap SDK, plus Npcap
  installed to run; see [permissions.md](permissions.md).
- The container image (`Dockerfile`) is built this way.
- Without the feature, the live endpoints answer `501 live_capture_unavailable`, and everything
  else works as before.

**2. An operator's decision at runtime.**

- Set `FLOWSENTINEL_LIVE_CAPTURE=true`. It is off by default, and the endpoints then answer
  `503 live_capture_disabled`.
- Optionally restrict it to some interfaces with `FLOWSENTINEL_LIVE_INTERFACES=eth1,lo`.

Then grant the capture permission as described in [permissions.md](permissions.md). Without it,
starting a capture answers `503 capture_permission_denied` with a pointer to that document.

| Variable | Default | Purpose |
| --- | --- | --- |
| `FLOWSENTINEL_LIVE_CAPTURE` | `false` | Allow live capture |
| `FLOWSENTINEL_LIVE_INTERFACES` | any | Comma-separated interfaces that may be captured on |
| `FLOWSENTINEL_LIVE_MAX_SECONDS` | 600 | Longest capture a request may ask for (1–3600) |

## Limits

| Limit | Default | Largest allowed |
| --- | --- | --- |
| `max_seconds` | 60 | `FLOWSENTINEL_LIVE_MAX_SECONDS` (default 600) |
| `max_packets` | 100,000 | `FLOWSENTINEL_MAX_PACKETS` (default 1,000,000) |
| `max_bytes` (file size, headers included) | 100 MiB | `FLOWSENTINEL_MAX_UPLOAD_MB` (default 512 MiB) |
| `snaplen` (bytes kept per packet) | 65,535 | 262,144 (smallest: 64) |

- A request can lower the limits but never raise them. Values out of range get
  `400 invalid_limit`.
- The capture's time limit is checked between reads, at least every 100 milliseconds or so, so a
  capture can run slightly longer than its limit (2.3 s for a 2 s limit in our test).
- The import then applies the usual limits and retention settings. For example, only the first
  `max_packets_stored` packets are stored as packet rows, while flows and alerts cover the whole
  capture.

### Capture filters

The filter is standard libpcap (BPF) syntax, for example `tcp port 443` or
`udp and not port 53`.

- It may have at most 1,024 bytes of printable ASCII. Control characters are refused before
  libpcap sees the text.
- A filter only selects which packets are kept. It cannot change anything on the network.
- Invalid filters get `400 invalid_capture_filter` with libpcap's message.

## API

All live endpoints need the admin role. State changes need the CSRF token (see
[authentication.md](authentication.md)).

| Method and path | Purpose |
| --- | --- |
| `GET /api/v1/live/interfaces` | Interfaces that may be captured on: name, description, addresses, loopback, up |
| `POST /api/v1/live/captures` | Start: `{"interface", "filter"?, "promiscuous"?, "max_seconds"?, "max_packets"?, "max_bytes"?, "snaplen"?, "authorized": true}`; `202` with the status |
| `GET /api/v1/live/captures/current` | The current or most recent capture: state, counters, stop reason, the stored capture's ID, or the error |
| `POST /api/v1/live/captures/current/stop` | Stop the running capture; it is then imported |

The `state` field moves through these values:

1. `idle` (no capture since the server started);
2. `capturing`;
3. `importing`;
4. `finished` (with `capture_id`) or `failed` (with `error`).

| Status | Codes |
| --- | --- |
| 400 | `authorization_required`, `unknown_interface`, `invalid_capture_filter`, `invalid_limit` |
| 403 | `forbidden` (not an admin), `interface_not_allowed`, `csrf_token_invalid` |
| 409 | `live_capture_running`, `no_live_capture` (stop with nothing running) |
| 429 | `import_busy` |
| 501 | `live_capture_unavailable` |
| 503 | `live_capture_disabled`, `capture_permission_denied` |

The dashboard's **Live capture** page (admins only) shows the interfaces and a start form with the
authorization confirmation. While a capture runs, it shows the live counters and a stop button,
and afterwards a link to the stored capture.

## Audit

| Action | Details |
| --- | --- |
| `live.start` | Interface, filter, promiscuous mode and the applied limits |
| `live.stop` | Who asked |
| `live.finish` | Success: stop reason, packets, dropped counts, the stored capture's ID. Failure: the error code |

## Tests

`crates/live-capture/tests/session.rs` drives capture sessions with replay sources, which read a
synthetic fixture instead of an interface. It checks:

- that a replayed capture is written byte for byte;
- each limit;
- stop requests;
- that a writer slower than the source drops packets and counts them instead of queueing them;
- that writer and source failures end the capture with their error;
- that the snapshot length cuts packets but keeps their wire length.

Unit tests cover:

- limits;
- filter text;
- the pcap writer;
- libpcap filter compilation and the recognition of permission errors.

`crates/api-server/tests/live.rs` checks the API with a replay source against PostgreSQL:

- a capture is imported as metadata with source `live`;
- the temporary file is deleted;
- one capture at a time;
- stopping;
- every request check;
- admin-only access;
- the disabled and unavailable answers;
- the interface allowlist;
- the audit events.

One test captures real loopback traffic through libpcap. It sends ordinary UDP datagrams from the
test to its own socket on `127.0.0.1`. It runs when `FLOWSENTINEL_LIVE_TEST_INTERFACE=lo` is set:

```bash
FLOWSENTINEL_LIVE_TEST_INTERFACE=lo cargo test -p live-capture --features libpcap --test session
```

CI builds and tests everything with libpcap. It then gives the test binary `CAP_NET_RAW` only
(`setcap`) and runs the loopback test as the unprivileged runner user.

## Limits of this design

- The captured packets exist on disk in the temporary file until the capture is imported, just
  like an uploaded file. Keep the upload directory on storage only the server can read.
- One capture at a time; there is no continuous or scheduled capture.
- Only Ethernet captures (link type 1) are decoded (see
  [protocol-decoding.md](protocol-decoding.md)). Ethernet interfaces and Linux's `lo` qualify.
  Linux's pseudo-interface `any` (Linux cooked capture), macOS loopback, and Wi-Fi in monitor
  mode do not: their packets are counted and stored with the status `unsupported`.
- The counts of packets dropped by the system come from libpcap's statistics. Their meaning
  varies by platform.
