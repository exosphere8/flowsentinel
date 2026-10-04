# Protocol decoding

`flowsentinel inspect --decode` decodes each packet's protocol headers into typed metadata: a
protocol tree per packet, a status, and warnings. Packet bytes are examined transiently while the
capture is read and are never stored or printed. Payloads are reported by **length only**.

> Decode only captures you own or are explicitly authorized to analyze.

## Usage

```bash
flowsentinel inspect --pcap <PATH> --decode            # summary + one row per packet
flowsentinel inspect --pcap <PATH> --decode --verbose  # adds each packet's protocol tree
flowsentinel inspect --pcap <PATH> --decode --json     # one JSON object
```

All `inspect` limits (`--max-file-size-mb`, `--max-packets`, `--max-duration-seconds`) apply
unchanged. `--verbose` requires `--decode`, and has no effect with `--json`, which always includes
the full protocol tree. Without `--decode`, output is exactly as described in
[pcap-ingestion.md](pcap-ingestion.md).

### Example

```text
$ flowsentinel inspect --pcap fixtures/pcap/decode-ipv4.pcap --decode --max-packets 5
...
Decode summary
  Packets decoded    5
  Status             complete 5
  Protocols          Ethernet 5, ARP 2, IPv4 3, TCP 2, UDP 1

Decode warnings
  none

Packets
        #  Timestamp (UTC)                 Source             Destination        Protocol  Length  Info
        1  2026-01-01T00:00:00.000000Z     02:00:00:00:00:01  ff:ff:ff:ff:ff:ff  ARP           42  who-has 192.0.2.1 tell 192.0.2.10
        2  2026-01-01T00:00:00.010000Z     02:00:00:00:00:02  02:00:00:00:00:01  ARP           42  192.0.2.1 is-at 02:00:00:00:00:01
        3  2026-01-01T00:00:00.020000Z     192.0.2.10         198.51.100.20      UDP           79  40000 -> 9 len=37
        4  2026-01-01T00:00:00.030000Z     192.0.2.10         198.51.100.20      TCP           62  40001 -> 9 [SYN] seq=1000 win=64240 len=0
        5  2026-01-01T00:00:00.040000Z     198.51.100.20      192.0.2.10         TCP           62  9 -> 40001 [SYN,ACK] seq=5000 ack=1001 win=64240 len=0
```

`Length` is the on-the-wire length. Source and destination are the innermost IP addresses, or
MAC addresses for frames without an IP layer (such as ARP). With `--verbose`, each row is followed
by its tree:

```text
           Frame: 62 bytes captured, 62 on the wire, decode complete
           Ethernet II: 02:00:00:00:00:01 -> 02:00:00:00:00:02, type 0x0800 (IPv4), header 14 bytes
           IPv4: 192.0.2.10 -> 198.51.100.20, ttl 64, id 0x0001, DF, dscp 0, ecn 0, header 20 bytes (options 0), total 48, payload 28, protocol TCP (6), checksum ok
           TCP: 40001 -> 9, flags SYN, seq 1000, ack 0, window 64240, urgent 0, header 28 bytes (options 8), payload 0 bytes
```

## Supported protocols

| Layer | Protocol | Decoded metadata |
| --- | --- | --- |
| Link | Ethernet II (`LINKTYPE_ETHERNET` only) | Source/destination MAC, EtherType and name, up to two VLAN tags (802.1Q `0x8100`, 802.1ad `0x88A8`, legacy `0x9100`: priority, drop-eligible, VLAN ID), header length |
| Link | ARP (Ethernet/IPv4) | Hardware/protocol type and address lengths, operation and name, sender/target MAC and IPv4 |
| Network | IPv4 | Header length, DSCP, ECN, total length, identification, DF/MF flags, fragment offset (bytes), TTL, protocol and name, header-checksum validity, addresses, options length, declared payload length |
| Network | IPv6 | Traffic class, flow label, payload length, next header, hop limit, addresses, extension-header chain (type, name, length), fragment header (offset, M flag, identification), upper-layer protocol |
| Transport | ICMP (in IPv4), ICMPv6 (in IPv6) | Type, code, type name; identifier and sequence for echo request/reply only; payload length |
| Transport | TCP | Ports, sequence and acknowledgment numbers, header length, flags (`FIN` … `CWR`, `AE`), window, urgent pointer, options length, payload length |
| Transport | UDP | Ports, length field, payload length |

Not decoded: other link types (Linux cooked, raw IP, 802.11, …), 802.3/LLC frames, other
EtherTypes (LLDP, MPLS, PPPoE, …), other IP protocols (GRE, ESP, SCTP, …) and TCP/IP option
contents. Payloads are never shown. DNS, DHCP, HTTP/1.x and TLS handshakes add an application
layer with bounded metadata; see [application-metadata.md](application-metadata.md).

## Status and warnings

Every packet gets one status, describing where decoding stopped:

| Status | Meaning |
| --- | --- |
| `complete` | Every header present was decoded: down to TCP/UDP/ICMP/ARP, or to an IP layer whose transport header is legitimately absent (a non-initial fragment, IPv6 "no next header") |
| `unsupported` | Decoding reached a link type, EtherType or IP protocol that is not decoded. Outer layers are kept. |
| `truncated` | The captured bytes end inside a header, usually because of a short snapshot length |
| `malformed` | A header field is invalid. Outer layers are kept. |

Warnings carry a code, the layer they apply to, and a fixed explanation. They never contain
packet bytes. The decoded table appends the reason to the Info column, for example
`[malformed: TCP data offset is below 5]`.

| Code | Meaning |
| --- | --- |
| `unsupported_link_type` | The capture's link type is not Ethernet |
| `unsupported_ethertype` | EtherType (or an 802.3 length field) not decoded |
| `unsupported_ip_protocol` | IP protocol / next header not decoded |
| `unsupported_arp_format` | ARP that is not Ethernet/IPv4 |
| `truncated_header` | Captured bytes end inside this layer's header |
| `invalid_header_field` | A field has an impossible value (wrong IP version, IHL < 5, TCP data offset < 5, UDP length < 8, IPv4 reserved flag, Hop-by-Hop not first, …) |
| `length_mismatch` | Declared lengths disagree with each other or with a fully captured frame: an IPv4 total length or IPv6 payload length beyond the frame, an IP payload too short for the TCP/UDP/ICMP header, a UDP length beyond (malformed) or short of (warning) the IP payload, IPv6 extension headers beyond the payload length, an IPv6 payload length of 0, an 802.3 length beyond the frame |
| `too_many_vlan_tags` | More than two stacked VLAN tags |
| `fragment` | The packet is an IPv4 or IPv6 fragment (informational) |
| `extension_header_limit` | More than 8 IPv6 extension headers |
| `encrypted_payload` | IPv6 ESP: the upper layer is not visible |
| `bad_ipv4_checksum` | IPv4 header checksum mismatch. Often caused by checksum offload on the capturing host, so this is informational. |

The JSON `decode_summary` and the human "Decode warnings" block aggregate warnings per code and
layer, with a count and the first packet affected.

## Validation rules

Every field is read through bounds-checked accessors that return "missing" instead of panicking.

The decoder is given each packet's on-the-wire length, so it can tell two cases apart. If the
capture's snapshot length cut the packet short, running out of bytes is `truncated`. If the frame
was captured in full, a header that declares more bytes than exist is lying, and is reported as
`malformed` with `length_mismatch`. Decoding stops at that layer, so inflated lengths never reach
later layers.

- **Ethernet:** at least 14 bytes; up to two VLAN tags; type/length values ≤ 1500 are 802.3
  lengths (not decoded); 1501–1535 is invalid.
- **ARP:** the 8-byte fixed header must be present; Ethernet ARP must use 6-byte hardware and
  4-byte protocol addresses; the address block (`2 × (hlen + plen)`, at most 1020 bytes) must be
  fully captured.
- **IPv4:** version 4; IHL ≥ 5 and the full header (with options) captured; total length ≥ header
  length (a total length of 0, typical of captures taken before segmentation offload, is
  therefore `malformed`); total length within a fully captured frame. Bytes beyond the total
  length (Ethernet padding) are ignored. The transport layer sees at most
  `total length − header length` bytes.
- **IPv4 fragments:** for a non-initial fragment (offset ≠ 0), the transport layer is **not**
  decoded, because its bytes are continuation data. For the first fragment (MF set, offset 0),
  the transport header is decoded but length cross-checks are skipped. In a first fragment, a TCP
  `payload_length` (derived from the IP lengths) covers only this fragment, while a UDP
  `payload_length` (from the UDP length field) covers the whole datagram.
- **IPv6:** version 6; 40-byte header captured; payload length within a fully captured frame.
  A payload length of 0 is `unsupported` when a Hop-by-Hop header follows (a possible jumbogram),
  fine with "no next header", and `malformed` otherwise.
  The extension-header chain is followed only for headers with a known length format:
  Hop-by-Hop, Routing, Destination Options, Mobility, HIP and Shim6 (`(len + 1) × 8`), AH
  (`(len + 2) × 4`) and Fragment (8). Each header must be fully captured, Hop-by-Hop must come
  first, and at most 8 headers are traversed. ESP stops the walk; "no next header" (59) ends it.
  Any other value is treated as the upper-layer protocol. Extension bytes are never misread as
  transport headers. A Fragment header with a non-zero offset ends the walk: the bytes after it
  are continuation data and are not parsed (the fragment header's own next-header value is
  reported as the upper layer). An extension header that runs past the declared payload length
  is a `length_mismatch`; one cut by the snapshot length is `truncated`.
- **TCP:** data offset ≥ 5 and the full header with options within the IP payload. Payload length
  is derived from the IP lengths.
- **UDP:** 8-byte header within the IP payload; length ≥ 8; length > IP payload is malformed,
  length < IP payload is a warning.
- **ICMP/ICMPv6:** 8-byte header within the IP payload. ICMP is decoded only inside IPv4 and
  ICMPv6 only inside IPv6.

One packet's result never depends on another's, so a malformed packet cannot stop or corrupt
the decoding of later packets.

## JSON

With `--decode --json`, each entry of `packets` gains a `decoded` object, and the report gains a
top-level `decode_summary`:

```json
{
  "summary": { "...": "as in pcap-ingestion.md" },
  "decode_summary": {
    "packets_decoded": 14,
    "status_counts": { "complete": 14 },
    "protocol_counts": { "ethernet": 14, "arp": 2, "ipv4": 12, "icmp": 2, "tcp": 5, "udp": 4 },
    "warnings": [ { "code": "fragment", "protocol": "ipv4", "count": 2, "first_packet_index": 13 } ]
  },
  "packets": [
    {
      "index": 3,
      "file_offset": 140,
      "timestamp": { "unix_seconds": 1767225600, "nanos": 20000000, "rfc3339": "2026-01-01T00:00:00.020000Z" },
      "captured_length": 79,
      "original_length": 79,
      "decoded": {
        "status": "complete",
        "layers": [
          { "layer": "ethernet", "destination": "02:00:00:00:00:02", "source": "02:00:00:00:00:01", "vlan_tags": [], "ethertype": 2048, "ethertype_name": "IPv4", "header_length": 14 },
          { "layer": "ipv4", "header_length": 20, "dscp": 0, "ecn": 0, "total_length": 65, "identification": 1, "dont_fragment": true, "more_fragments": false, "fragment_offset": 0, "ttl": 64, "protocol": 17, "protocol_name": "UDP", "checksum_valid": true, "source": "192.0.2.10", "destination": "198.51.100.20", "options_length": 0, "payload_length": 45 },
          { "layer": "udp", "source_port": 40000, "destination_port": 9, "length": 45, "payload_length": 37 }
        ],
        "warnings": []
      }
    }
  ],
  "completion_state": "complete",
  "warnings": []
}
```

Layers are tagged by `"layer"`. TCP flags serialize as `{"bits": 18, "names": ["SYN", "ACK"]}`.

## Safety properties

- **Transient bytes.** The `capture` crate lends each record's bytes (at most 262,144) to the
  decoder for one call through a reusable buffer. No public type in `decoder` can hold payload
  bytes.
- **No panics.** Property tests decode random bytes under random link types, random transport
  bytes behind valid IPv4 headers, and random IPv6 extension-header chains (thousands of cases per
  run). Every prefix of a valid frame is checked to report `truncated`, never panic.
- **Bounded work.** VLAN tags (2) and IPv6 extension headers (8) have fixed traversal limits, each
  step must advance by a validated length, and warnings are capped at 8 per packet. No allocation
  is sized from a packet field.
- **Fuzzing.** `fuzz/` holds cargo-fuzz targets for the decoder and for whole captures; see
  [fuzz/README.md](../fuzz/README.md).
- **Independent cross-check.** During development, every decoded field of the decode fixtures
  was compared against Scapy (454 field comparisons, 0 mismatches).

## Memory

With `--decode`, the capture is read **twice**. The first pass computes the capture and decode
summaries, which are printed first. The second pass decodes the same packets again and writes each
one immediately. No decoded packet is kept, so memory does not grow with the number of packets.
The second pass reads exactly as many packets as the first. Each pass also fingerprints what it
read (the global header and every record's metadata and bytes). If the file changes between the
passes, the command reports `the capture changed while it was being read` and exits with code 5.
With `--json`, the object stays valid and gains an `error` member with code `capture_changed`.

`--max-duration-seconds` limits the first pass, which decides which packets are reported. The
second pass is bounded by that packet count and a one-hour cap instead, because its speed also
depends on how fast the output is consumed (for example by a pager). The total running time can
therefore exceed the limit, by roughly the time the first pass took plus the output time.

Measured peak resident memory and wall time for a synthetic capture of 100,000 Ethernet/IPv4/TCP
packets (release build, Linux):

| Command | Peak RSS | Time |
| --- | --- | --- |
| `inspect` | 9.9 MB | 0.05 s |
| `inspect --decode` | 10.2 MB | 0.15 s |
| `inspect --decode --json` | 10.4 MB | 0.26 s |
| `inspect --decode --verbose` | 10.3 MB | 0.31 s |

The remaining growth is the 40-byte-per-record packet table from
[pcap-ingestion.md](pcap-ingestion.md).

## Fixtures

| File | Contents |
| --- | --- |
| `decode-ipv4.pcap` | ARP request/reply, UDP, TCP handshake/data/FIN with options, ICMP echo, 802.1Q and QinQ VLANs, a two-fragment UDP datagram |
| `decode-ipv6.pcap` | UDP, TCP, ICMPv6 echo and neighbor solicitation, Hop-by-Hop + Destination Options chain, fragments, ESP, no-next-header |
| `decode-unsupported.pcap` | LLDP, 802.3/LLC, GRE, three VLAN tags, then a valid packet |
| `decode-malformed.pcap` | Short Ethernet frame, bad IPv4 version/IHL/total length, bad TCP data offset, bad UDP lengths, snaplen-cut TCP, bad IPv6 version, extension header longer than the payload length, snaplen-cut extension header, IPv4 total length beyond the frame, then a valid packet |
| `decode-raw-linktype.pcap` | `LINKTYPE_RAW` (101) packets, reported as unsupported |

Generated by `scripts/generate_pcap_fixtures.py`; see [fixtures/README.md](../fixtures/README.md).
