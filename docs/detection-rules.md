# Detection rules

FlowSentinel runs a small set of explainable rules over the metadata of a capture: the
reconstructed flows and the DNS and ARP messages. Each rule looks for one well-known traffic
pattern and raises an **alert** that names the pattern, cites the flows or packets it was built
from, shows the measured evidence and explains, in plain language, why it may be wrong.

> **Every alert is a heuristic indicator: an observed pattern that deserves review, not proof of
> compromise.** No rule decides that a host is infected, compromised or malicious. Each alert
> lists the benign causes that most often produce the same pattern.

Rules read metadata only. They never see payload bytes, never decrypt anything and never contact
another system: no threat-intelligence lookups, no blocking and no active probing.

## Running the rules

From the command line:

```bash
flowsentinel detect --pcap <PATH> [--config detection.toml] [--json]
                    [--max-file-size-mb MB] [--max-packets N] [--max-duration-seconds S]
```

The capture limits and exit codes are those of `inspect` (see
[pcap-ingestion.md](pcap-ingestion.md)). An unreadable or invalid `--config` file is a usage
error (exit code 2), and the message names only the file's name and the offending setting.

The API server runs the same rules on every import and stores the alerts with the capture (see
[api.md](api.md#alerts)). It reads thresholds from the file named by
`FLOWSENTINEL_DETECTION_CONFIG` and refuses to start if that file is invalid.

### Example

```text
$ flowsentinel detect --pcap fixtures/pcap/detect-mixed.pcap
Capture
  File               detect-mixed.pcap (11416 bytes)
  Packets processed  138
  Completion         complete

Detection summary
  Alerts             5
  By severity        high 2, medium 2, low 1
  Flows evaluated    47

Alerts are heuristic indicators: observed patterns to review, not proof of compromise.

[1] Possible SYN scan (FS-SCAN-SYN), medium severity, medium confidence
  When       2026-01-01T00:00:01.000000Z
  Endpoints  192.0.2.66 -> 198.51.100.20
  Evidence   distinct_ports_unanswered_or_refused=25, threshold=20, window=60 s
  Why        192.0.2.66 sent TCP connection attempts to 25 distinct ports on 198.51.100.20 within 60 s, and they were refused or never answered. This is consistent with a SYN port scan, but it is a heuristic indicator that needs review.
  Caveats    Port counts come from reconstructed flows; a capture that misses the replies makes successful connections look unanswered.
  Benign causes  authorized vulnerability or inventory scanners; monitoring that probes many service ports; a client retrying through a list of fallback ports
  Flows      3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27
  ATT&CK context  T1046 Network Service Discovery
...
```

## What an alert contains

| Field | Meaning |
| --- | --- |
| `alert_id` | Numbered from 1 within a capture, in rule order (the table below) and then by time |
| `rule_id`, `rule_name` | The stable rule identifier and its name |
| `severity` | `low`, `medium` or `high`: how much attention the pattern deserves **if** it is a true positive. Fixed per rule |
| `confidence` | `low`, `medium` or `high`: how strongly the measurements support the pattern, for example how far a threshold was exceeded |
| `status` | `open` when raised; analysts change it to `acknowledged`, `resolved` or `false_positive` |
| `nature` | Always the statement that the alert is a heuristic indicator, not proof of compromise |
| `first_seen`, `last_seen` | Time range of the matching traffic, including traffic after the first 50 cited flows or packets |
| `source`, `destination`, `destination_port` | The endpoint whose behavior matched, and the endpoint it was directed at when there is one |
| `related_flow_ids`, `related_packet_indexes` | The flows or packets the alert was built from, at most 50 each, starting with the first ones that matched. DNS alerts cite both the query packets and their flows; ARP alerts cite packets only (ARP has no flow) |
| `evidence` | The measured values and thresholds, as name/value pairs |
| `explanation` | The evidence in a sentence, including what else it could mean |
| `uncertainty` | Why the rule can be wrong |
| `likely_false_positives` | Benign activity that produces the same pattern |
| `mitre_attack` | MITRE ATT&CK techniques the pattern can relate to. These are context for the analyst, never a claim that a technique was used |

Flows cited by an alert record the alert's ID in `alert_ids` (at most 16 per flow). In the API,
flows also carry `alert_count` and `max_alert_severity`, which the display filter can use
(`alert`, `alert.count`, `alert.severity`; see [filter-language.md](filter-language.md)). ARP
alerts cannot be found this way, because ARP packets belong to no flow.

A JSON alert (`flowsentinel detect --json`, abridged):

```json
{
  "alert_id": 2,
  "rule_id": "FS-BEACON",
  "rule_name": "Regular repeated connections",
  "severity": "medium",
  "confidence": "medium",
  "status": "open",
  "nature": "heuristic indicator: an observed pattern that deserves review, not proof of compromise",
  "first_seen": { "unix_seconds": 1767225620, "nanos": 0, "rfc3339": "2026-01-01T00:00:20.000000Z" },
  "source": "192.0.2.10",
  "destination": "203.0.113.80",
  "destination_port": 8443,
  "related_flow_ids": [41, 42, 43, 44, 45, 46, 47],
  "related_packet_indexes": [],
  "evidence": [
    { "name": "connections", "value": "7" },
    { "name": "mean_interval_seconds", "value": "60.000" },
    { "name": "interval_stddev_seconds", "value": "0.000" },
    { "name": "jitter_ratio", "value": "0.000" },
    { "name": "max_jitter_ratio", "value": "0.1" }
  ],
  "explanation": "192.0.2.10 connected to 203.0.113.80 port 8443 7 times at intervals of 60.0 s with little variation (jitter 0.000). Regular check-ins are typical of update and monitoring software and can also be command-and-control beaconing; review what the destination is.",
  "uncertainty": "Regularity alone is common: update checks, health checks and telemetry all beacon. Few connections give an unreliable estimate.",
  "likely_false_positives": ["software update and licence checks", "monitoring agents and health checks", "NTP, telemetry and keep-alive traffic"],
  "mitre_attack": ["T1071 Application Layer Protocol"]
}
```

The JSON output also has a `detection_summary` with totals per rule and severity, the number of
flows evaluated, flows and DNS/ARP packets skipped for lack of a valid timestamp, events not
evaluated because of the limits below, and the rules that reached the alert limit.

## The rules

| ID | Name | Severity | Input | Raised when (defaults) |
| --- | --- | --- | --- | --- |
| `FS-SCAN-SYN` | Possible SYN scan | medium | flows | One host's TCP handshakes to **20** distinct ports of another host are refused or unanswered within **60 s** |
| `FS-SCAN-PORTS` | Many ports contacted on one host | medium | flows | One host contacts **50** distinct TCP/UDP ports of another host within **60 s**, any outcome |
| `FS-SCAN-HOSTS` | Same port tried on many hosts | medium | flows | One host's attempts to the same TCP/UDP port on **20** distinct hosts are refused or unanswered within **60 s** |
| `FS-TCP-FAIL` | Many failed TCP connections | low | flows | One host's TCP connection attempts are refused or unanswered **30** times within **60 s**, across any destinations |
| `FS-BEACON` | Regular repeated connections | medium | flows | One host connects to the same destination and port at least **6** times, with a mean interval of at least **10 s** and a jitter (standard deviation ÷ mean) of at most **0.1** |
| `FS-RARE-PORT` | Rarely used destination port | low | flows | In a capture of at least **50** flows, a port that is not a common service port or in the dynamic range (49152–65535) is used by at most **1** flow and answered |
| `FS-OUTBOUND-RATIO` | Large outbound transfer | medium | flows | A flow from an internal host to an external one carries at least **1,000,000** bytes out and at least **10** times more out than in |
| `FS-CLEARTEXT` | Cleartext login protocol in use | low | flows | A TCP connection to port **21, 23, 110, 143, 513 or 514** (FTP, Telnet, POP3, IMAP, rlogin, rsh) is answered |
| `FS-DNS-VOLUME` | High DNS query volume | low | DNS | One client sends **200** DNS queries within **60 s** |
| `FS-DNS-TUNNEL` | Possible DNS tunneling | high | DNS | Under one parent domain, one client sends **10** suspicious queries, or a suspicious query arrives when it has queried **30** distinct subdomains, within **300 s** |
| `FS-ARP-CONFLICT` | IP address claimed by several MAC addresses | high | ARP | ARP messages map one IPv4 address to **2** or more MAC addresses within **60 s** |
| `FS-ARP-GRATUITOUS` | Many gratuitous ARP replies | low | ARP | One MAC address sends **20** gratuitous ARP announcements within **60 s** |

`GET /api/v1/rules` returns this catalog with each rule's description, uncertainty, likely false
positives and ATT&CK context.

### Details

**Scans and failures** (`FS-SCAN-SYN`, `FS-SCAN-PORTS`, `FS-SCAN-HOSTS`, `FS-TCP-FAIL`) count
distinct values in a sliding window over flow start times. A *failed attempt* is a TCP flow that
began with a SYN and either was never answered (`syn_sent`) or was reset before any payload moved.
`FS-SCAN-HOSTS` counts only flows that were not answered (failed TCP attempts, UDP without a
reply), because answered connections to one port on many hosts are ordinary browsing.
The alert cites the flows in the window when the threshold was reached and every later flow of
the same pattern. Confidence is high when the peak count is at least twice the threshold.

**Beaconing** groups flows by initiator, responder, protocol and responder port, and measures the
intervals between their start times. Very short mean intervals are ignored (normal polling or bulk
traffic). Confidence is high with at least twice the minimum connections and half the allowed
jitter.

**Rare destination port** is judged within the capture only. The direction of the flow must be
known: from the TCP handshake, or for UDP, an initiator port that looks like a client's (1024 or
above and not a common service port), so a server reply seen before its request does not make
the client's port look like a service. One of the flows must have been answered. Common service
ports (for example 22, 53, 80, 123, 443, 3389) never count as rare.

**Outbound ratio** needs the configured `internal_networks`: the initiator must be inside and the
responder outside. Bytes are totaled per pair of hosts over the qualifying flows.

**Cleartext** is decided by port only. The service might use STARTTLS, or something else might
listen on that port.

**DNS volume and tunneling** look at queries (not responses) and the client that sent them. The
parent domain is the last two labels of the name; the rest is the subdomain. A query is
*suspicious* when a subdomain label has at least 40 characters, the whole name at least 100, a
label of 16 or more characters has a Shannon entropy of at least 3.8 bits per character, or the
query type is TXT or NULL. The evidence item `threshold_reached` says whether the query count,
the subdomain count or both were reached; both together give high confidence. Distinct
subdomains are counted by a 64-bit digest, so the names themselves are not kept in memory. Names
too long to show in full (for example labels of 8-bit bytes, shown escaped) keep their last two
labels when shortened, so their parent domain is still found (see
[application-metadata.md](application-metadata.md)).

**ARP conflict** cites the claims in the window and lists up to 8 of the MAC addresses involved.
At most 50 are tracked; beyond that the list ends "and at least N more". ARP probes from `0.0.0.0` claim no address and are ignored.
**Gratuitous ARP** counts announcements in which the sender and target IP address are the same.

## Configuration

Thresholds come from a TOML file. [config/detection.example.toml](../config/detection.example.toml)
lists every setting with its default; a file needs only the settings it changes:

```toml
internal_networks = ["10.0.0.0/8", "192.168.0.0/16"]

[beaconing]
enabled = false

[syn_scan]
min_ports = 30
```

The file must be at most 64 KiB. Unknown keys are rejected, and every value is range-checked:
windows 1–86,400 s; windowed counts 1–4,096 (a window holds at most 4,096 events, so a larger
threshold could never be reached); other counts 1–1,000,000; `beaconing.min_connections` 3–1,000,000;
ratios, intervals and entropy must be positive numbers; at most 256 internal networks and 64 cleartext ports.

## Bounded resources

The rules run in the same pass as flow reconstruction, so they see each packet once.

- Flow rules see the finished flows that are retained (at most `max_retained_flows`, 100,000 by
  default). Their memory is proportional to that number.
- Each DNS/ARP rule keeps sliding windows by key (client, parent domain, address or MAC address):
  at most 16,384 keys, 4,096 events per key and 131,072 events across all keys. Keys whose events
  have expired are swept out as the capture's time advances, and a window gives memory back when
  it holds far fewer events than it has room for. When the key table is full, the half of the
  keys seen least recently is evicted (counted in `keys_evicted`), so new hosts and domains are
  always evaluated; a flood of noise can therefore push out an older pattern. Events over the
  event budget are not evaluated and are counted in `events_not_evaluated`.
- The time used to expire windows moves only when two consecutive DNS/ARP packets agree, so a
  lone corrupt timestamp cannot expire every window. A packet stamped more than a window ahead of
  that time is not evaluated (and is counted), so it cannot hide the packets after it. When the
  time is confirmed to have jumped back by more than a window width (for example, two captures
  concatenated), the windows start afresh, including the packet that announced the jump.
- Flow rules group the flows first and build alerts only for the 1,000 groups that start
  earliest, so a capture of many one-flow patterns does not build alerts it cannot report.
- Each rule raises at most 1,000 alerts per capture (the earliest are kept) and lists such rules
  in `rules_at_alert_limit`. Each alert cites at most 50 flows and 50 packets.

Measured on Linux with a release build of `flowsentinel detect`, 400,000-packet synthetic
captures built to stress the limits (generated locally, not committed):

| Capture | Peak RSS, `flows` | Peak RSS, `detect` | Time, `detect` |
| --- | --- | --- | --- |
| Every DNS query to a new parent domain, from 60,000 clients | 146.4 MB | 234.7 MB | 3.23 s |
| Long, distinct DNS names from 64 clients within one window | 201.3 MB | 217.5 MB | 2.08 s |
| One IPv4 address claimed by 400,000 MAC addresses | 18.7 MB | 19.7 MB | 0.17 s |
| 990,736 packets: 960 (client, domain) keys each filled to 4,096 events over 2.7 hours, kept alive by later queries | 41.3 MB | 108.6 MB | 4.02 s |

Most of the memory is the flow table (the `flows` column runs the same pass without the rules).
In the first row every key is new, so the key tables keep evicting (1,155,072 keys evicted);
nothing is left unevaluated. The last row is the worst case for window memory: before windows
returned memory as their events expired, it peaked at 422 MB. A 60,000-packet capture spanning
17 hours, in which every DNS query used a new parent domain, is evaluated completely, because
expired keys are swept out.

## Limitations

- Rules see only what the capture contains. Asymmetric routing, sampling or a capture that
  starts mid-conversation changes what looks unanswered, regular or rare.
- Thresholds are generic defaults. Tune them for your network, and expect both missed patterns
  and false positives.
- Timing rules use packet timestamps as recorded; flows or DNS/ARP packets without a valid
  timestamp are skipped by windowed rules and counted.
- Rules do not correlate across captures and do not track hosts over time.
- Parent domains are the last two labels, so multi-label public suffixes (for example `co.uk`)
  group unrelated domains.

## Fixture

`fixtures/pcap/detect-mixed.pcap` (11,416 bytes, 138 packets, 47 flows) is generated by
`scripts/generate_pcap_fixtures.py` from synthetic data. It contains ordinary DNS and HTTPS
traffic and one instance of each of these patterns: a SYN scan of 25 ports, a Telnet session, 12
long TXT queries under `tunnel.example`, two MAC addresses claiming 192.0.2.1, and seven
connections to 203.0.113.80:8443 at 60-second intervals. Tests expect exactly five alerts:
`FS-SCAN-SYN`, `FS-BEACON`, `FS-CLEARTEXT`, `FS-DNS-TUNNEL` and `FS-ARP-CONFLICT`.

## Library use

```rust
use analysis::{AnalysisConfig, analyze_file_with_detection};
use capture::MonotonicClock;
use detection_engine::{DetectionConfig, Detector};

let detector = Detector::new(DetectionConfig::load(path_to_toml)?)?;
let analysis = analyze_file_with_detection(pcap, &AnalysisConfig::default(), detector,
                                           &MonotonicClock::start())?;
for alert in &analysis.detection.unwrap().alerts {
    println!("{} {} {}", alert.alert_id, alert.rule_id, alert.explanation);
}
```

`Detector::observe_packet` takes each decoded packet in capture order and `Detector::finish`
takes the finished flows. Live captures are imported like uploads, so the same rules run on them.
