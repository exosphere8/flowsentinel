# Flow reconstruction

`flowsentinel flows` groups the packets of a capture into **bidirectional flows**, one per
conversation, and reports traffic statistics, TCP state, application metadata and warnings for
each. It uses the same capture reader and decoder as `inspect --decode`, and keeps metadata only.

> Analyze only captures you own or are explicitly authorized to inspect.

## Usage

```bash
flowsentinel flows --pcap <PATH> [--json] [--sort start|bytes|packets|duration]
                   [--max-active-flows N] [--max-flows N]
                   [--idle-timeout-seconds S] [--tcp-idle-timeout-seconds S]
                   [--max-file-size-mb MB] [--max-packets N] [--max-duration-seconds S]
```

| Flag | Default | Allowed | Effect |
| --- | --- | --- | --- |
| `--max-active-flows` | 65536 | 1–1000000 | Flows tracked at once; when full, the least recently seen flow is evicted |
| `--max-flows` | 100000 | 1–1000000 | Finished flows kept for output; further flows are counted but not listed |
| `--idle-timeout-seconds` | 60 | 1–86400 | Idle timeout for UDP, ICMP and other flows |
| `--tcp-idle-timeout-seconds` | 300 | 1–86400 | Idle timeout for open TCP flows |
| `--sort` | `start` | | `start` (flow ID), `bytes`, `packets` or `duration` (largest first) |
| `--json` | off | | One JSON object on stdout |

The capture limits (`--max-file-size-mb`, `--max-packets`, `--max-duration-seconds`) and exit
codes are the same as for `inspect`; see [pcap-ingestion.md](pcap-ingestion.md).

### Example

```text
$ flowsentinel flows --pcap fixtures/pcap/flows-mixed.pcap
Capture
  File               flows-mixed.pcap (2045 bytes)
  Packets processed  19
  Completion         complete

Flow summary
  Packets            18 in flows, 1 without an IP layer
  Flows              6 total, 6 listed, 0 not retained, peak 5 active
  Ended by           idle_timeout 3, tcp_finished 2, capture_end 1
  Limits             65536 active, 100000 retained

Flows
      ID  Proto  Initiator              Responder              Packets       Bytes    Duration  State         Application
       1  UDP    192.0.2.10:53100       192.0.2.53:53                2         166      0.020s  -             DNS www.example.com
       2  TCP    192.0.2.10:40500       198.51.100.80:443            9        1017      0.211s  closed        TLS www.example.com
       3  TCP    192.0.2.10:40501       198.51.100.80:8080           2         108      0.001s  reset         (www.example.com)
       4  UDP    [2001:db8::a00]:40600  [2001:db8::1400]:9           2         198      0.001s  -             -
       5  UDP    192.0.2.10:40700       198.51.100.80:9              2         114      1.000s  -             (www.example.com)
       6  UDP    192.0.2.10:40700       198.51.100.80:9              1          72      0.000s  -             (www.example.com)
```

## Flow keys and direction

A flow is identified by the IP protocol number and the two endpoints (address and port). The two
endpoints are stored in a fixed sorted order, so packets in both directions match the same flow.
**The sort order is only used for matching.** Which side started the flow is decided separately:

| `initiator_basis` | Rule |
| --- | --- |
| `tcp_syn` | The first packet was a SYN without ACK: its sender is the initiator |
| `tcp_syn_ack` | The first packet was a SYN-ACK: its *receiver* is the initiator (the capture started mid-handshake) |
| `first_packet` | Otherwise the sender of the first packet is assumed to be the initiator |

Packets without an IP layer (ARP, unsupported link types, frames too malformed to reach IP) are
counted in `packets_without_ip` and belong to no flow. ICMP and other port-less protocols use
port 0. Non-initial IP fragments carry no ports, so they are counted in a port-less flow for the
same addresses and protocol, and that flow gets a `portless_fragments` warning. Fragments are not
reassembled.

## What each flow records

| Field | Notes |
| --- | --- |
| `flow_id` | Sequential from 1, in order of each flow's first packet |
| `initiator`, `responder` | `{ip, port}` |
| `first_seen`, `last_seen`, `duration_seconds` | Earliest and latest valid packet timestamps |
| `first_packet_index`, `last_packet_index` | Capture positions of the first and last packet |
| `initiator_to_responder`, `responder_to_initiator` | `packets`, `bytes` (on-the-wire frame bytes) and `payload_bytes` (transport payload) |
| `packets_total`, `bytes_total` | Both directions |
| `packet_size` | Frame sizes: `min`, `max`, `mean`, `stddev` (population), `median`; `median_exact` is false when the median comes from the first 256 packets only |
| `inter_arrival` | Gaps between consecutive packets in seconds (`min`, `max`, `mean`, `stddev`); absent for single-packet flows |
| `tcp` | `state`, flags seen from each side, SYN/FIN/RST counts, `duplicate_segments` (data, SYN or FIN segments identical to the previous one from the same side; pure ACKs never count) |
| `application` | Recognized protocols; DNS names queried in the flow; names that earlier DNS answers mapped to the responder's address; HTTP hosts and paths; TLS server names and ALPN |
| `dominant_endpoint` | `initiator` or `responder` if that side sent more than 55% of the bytes, else `balanced` |
| `end_reason` | `idle_timeout`, `tcp_finished`, `evicted`, `capture_end` or `clock_reset` |
| `warnings` | `out_of_order_timestamp`, `missing_timestamp`, `portless_fragments`, `missing_transport_header` and `timestamp_outlier`, each with a count |
| `alert_ids` | IDs of the alerts that cite this flow, filled in when detection runs (`flowsentinel detect` and API imports); empty in `flowsentinel flows` output |

Statistics use constant memory per flow: Welford's algorithm for mean and standard deviation, and
the first 256 sizes for the median. Application lists are capped: 4 DNS queries, 4 names per
responder, 4 HTTP hosts, 4 HTTP paths, 4 TLS server names and 4 ALPN values.

### TCP state approximation

The state is inferred from flags only. There is no sequence-number tracking or reassembly.

| State | When |
| --- | --- |
| `syn_sent` | SYN seen, no SYN-ACK yet |
| `syn_received` | SYN-ACK seen, handshake not yet acknowledged |
| `established` | ACK after the SYN-ACK |
| `midstream` | The first packet was not a SYN or SYN-ACK (the connection predates the capture) |
| `closing` | One side sent FIN |
| `closed` | Both sides sent FIN |
| `reset` | Any RST |

A segment is a **duplicate** when it carries data, SYN or FIN and its sequence number, payload
length and flags equal those of the previous such segment from the same side. That usually means a
retransmission or a duplicated capture. Pure ACKs repeat sequence numbers legitimately and are
never counted.

## Ending flows and bounded memory

### The engine's clock

Flows are timed by the engine's own clock, which is driven by packet timestamps:

- The clock follows the latest timestamp. It never moves backwards by less than a day, so
  reordered packets and merged captures with some clock skew are harmless: a packet that is late
  by a few minutes still counts as activity "now".
- A timestamp more than a day away from the clock (`MAX_UNCONFIRMED_JUMP`), in either direction,
  is **held**. Until it is confirmed, it counts neither for the clock nor in its flow's
  `first_seen`, `last_seen` or timing statistics.
- If the next timestamped packet lies within a day of the held one, the jump is **confirmed** and
  counted in `clock_jumps`:
  - **Forward** (a quiet period of more than a day): the clock moves on. The flow that received
    the held packet is timed from it, so the conversation after the gap stays whole.
  - **Backward**: times before and after the jump cannot be compared, so every active flow ends
    with end reason `clock_reset`. Each flow can be ended this way only once, so the cost stays
    linear however often the time jumps.
- Otherwise the held timestamp was a lone outlier. It is counted in `timestamp_outliers`, and the
  packet's flow gets a `timestamp_outlier` warning.
- So one corrupt record (in 2106, say) can neither expire every active flow at once, nor freeze
  expiry, nor distort its flow's duration. If the very first timestamp is the corrupt one, the
  next two packets confirm the jump back and the clock is corrected.
- Packets without a valid timestamp use the clock's time. Flows seen before the first valid
  timestamp take that timestamp when it arrives.
- Known ambiguities:
  - A packet held after a long gap is timed as if no time had passed. If it shares a 5-tuple with
    a flow that is still active by the clock, it joins that flow.
  - Timestamps that go back and forth by less than a day are treated as reordering, so packets
    far apart in time on the same 5-tuple can share a flow.

### When a flow ends

Before each packet, every flow whose deadline has passed ends:

| Flow | Deadline |
| --- | --- |
| Open TCP | Last packet + `--tcp-idle-timeout-seconds` (300 s) |
| TCP after FIN both ways or RST | Last packet + 10 s, to absorb trailing ACKs (`tcp_finished`) |
| UDP, ICMP, other | Last packet + `--idle-timeout-seconds` (60 s) |

"Last packet" is the clock's time at the flow's latest packet. A packet that arrives after its
flow ended starts a new flow with a new ID. So does a SYN without ACK on a connection that already
closed (FIN both ways, or RST): it is a new connection on the same ports.

At most `--max-active-flows` flows are tracked. When the table is full, the least recently seen
flow, by packet order rather than by timestamp, is ended as `evicted` before the new one is
created.

At most `--max-flows` finished records are kept. They are the flows with the **lowest IDs**,
that is the earliest to start. Records beyond the limit are counted in `flows_not_retained`.

Expiry and eviction use ordered indexes keyed by `(deadline, flow ID)` and
`(packet sequence number, flow ID)`. The engine is **deterministic**: the same packets in the
same order always produce the same flows, IDs and statistics. Tests check this.

Out-of-order timestamps are tolerated. `first_seen` and `last_seen` are the true minimum and
maximum, the gap for an out-of-order packet counts as zero, and the flow gets an
`out_of_order_timestamp` warning. Packets without a valid timestamp are counted in a
`missing_timestamp` warning.

### Memory

Memory is bounded by the two limits whatever the capture contains. Each flow's state has a
constant size, and its application lists hold at most 4 entries each, of at most about 260
characters. DNS names learned from answers are shared between flows rather than copied.

Measured peak resident memory (release build, Linux x86-64). The UDP captures are synthetic, with
100,000 packets over 100 seconds; `distinct` has a new flow per packet and `same` has one flow.
`loaded` has 20,001 flows of 9 TCP packets each, whose HTTP path, TLS server-name and ALPN lists
are all full:

| Capture and options | Peak active | Listed | Peak RSS | Time |
| --- | --- | --- | --- | --- |
| `same`, defaults | 1 | 1 | 9.8 MB | 0.04 s |
| `distinct`, `--max-flows 1 --max-active-flows 1000` | 1,000 | 1 | 9.8 MB | 0.07 s |
| `distinct`, `--max-flows 1` | 60,001 | 1 | 68.8 MB | 0.14 s |
| `distinct`, `--max-flows 1 --max-active-flows 1000000 --idle-timeout-seconds 86400` | 100,000 | 1 | 105.5 MB | 0.17 s |
| `distinct`, defaults | 60,001 | 100,000 | 125.9 MB | 0.34 s |
| `distinct`, 1,000,000 packets, `--max-packets 1000000` | 65,536 | 100,000 | 172.4 MB | 1.33 s |
| `loaded`, `--max-flows 1 --max-packets 1000000` | 20,001 | 1 | 101.5 MB | 0.83 s |

These figures work out to:

- about 1 KB per active flow without application metadata;
- about 0.6 KB per retained record without application metadata;
- about 4.5 KB per active flow when three application lists are full.

With every list full, a flow's text alone is bounded at about 6 KB. At the default limits
(65,536 active and 100,000 retained) a hostile capture could therefore need more than 1 GB; this
is an estimate from the limits, not a measurement. Lower `--max-active-flows` and `--max-flows`
on small machines.

### Limitations

- The flow key is the IP protocol plus both addresses and ports. VLAN tags are not part of it, so
  identical conversations on different VLANs (overlapping address spaces) share one flow.
- ICMP, ICMPv6 and other port-less protocols form one flow per address pair and protocol, whatever
  their identifiers.
- Without a handshake, the first packet's sender is taken as the initiator. For a flow first
  seen through a RST or an ICMP echo reply, that is the responding side.
- `responder_dns_names` come from any DNS answer earlier in the capture. They are hints, not
  verified facts.
- TCP and UDP packets whose transport header is missing (cut by the snapshot length, or
  malformed) are counted in a port-less flow with a `missing_transport_header` warning.

## JSON

```json
{
  "capture": { "...": "capture summary, as in pcap-ingestion.md" },
  "completion_state": "complete",
  "capture_warnings": [],
  "flow_summary": {
    "packets_seen": 19, "packets_in_flows": 18, "packets_without_ip": 1,
    "flows_total": 6, "flows_retained": 6, "flows_not_retained": 0, "peak_active_flows": 5,
    "end_reasons": { "idle_timeout": 3, "tcp_finished": 2, "capture_end": 1 },
    "timestamp_outliers": 0, "clock_jumps": 0,
    "max_active_flows": 65536, "max_retained_flows": 100000
  },
  "flows": [ { "flow_id": 1, "...": "fields listed above" } ]
}
```

## Library use

```rust
use flow_engine::{FlowConfig, FlowEngine, FlowPacket};

let mut engine = FlowEngine::new(FlowConfig::default());
// For each decoded packet, in capture order:
// let flow_id = engine.process(&FlowPacket { index, timestamp, wire_length, decoded: &decoded });
let report = engine.finish(); // finished flows in flow_id order, plus totals
```

`process` returns the ID of the flow the packet was assigned to (`None` for non-IP packets), so
callers can link packets to flows.

## Fixture

`fixtures/pcap/flows-mixed.pcap` (generated by `scripts/generate_pcap_fixtures.py`) contains a DNS
lookup, a TLS connection to the resolved address with a full handshake, a duplicate segment and
FIN exchange, a refused connection (SYN then RST), an IPv6 UDP exchange with an out-of-order
timestamp, an ARP packet, and a UDP conversation that idles out and restarts 90 seconds later.
