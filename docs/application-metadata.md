# Application metadata

With `--decode`, FlowSentinel also recognizes four application protocols and extracts a fixed,
bounded set of metadata fields from each: **DNS**, **DHCP**, **HTTP/1.x** and **visible TLS
handshake metadata**. Bodies, credentials, cookies, tokens, query strings, TLS random values, key
material and certificates are never exposed.

> Decode only captures you own or are explicitly authorized to analyze.

```bash
flowsentinel inspect --pcap fixtures/pcap/app-dns.pcap --decode
flowsentinel inspect --pcap fixtures/pcap/app-tls.pcap --decode --verbose
flowsentinel inspect --pcap fixtures/pcap/app-http.pcap --decode --json
```

```text
        #  Timestamp (UTC)                 Source         Destination    Protocol  Length  Info
        1  2026-01-01T00:00:00.000000Z     192.0.2.10     198.51.100.80  TLS          268  TLS ClientHello SNI=www.example.com ALPN=h2,http/1.1 (handshake metadata only)
        2  2026-01-01T00:00:00.010000Z     198.51.100.80  192.0.2.10     TLS          149  TLS ServerHello TLS 1.3 cipher=0x1301 (handshake metadata only)
```

Application layers appear as the last entry of a packet's protocol tree (`"layer": "dns"`,
`"dhcp"`, `"http"` or `"tls"`), after the Ethernet, IP and transport layers described in
[protocol-decoding.md](protocol-decoding.md).

## Recognition rules

Recognition is conservative: **ports are hints, never proof**. A parser accepts a payload only if
its structure is valid. Anything else stays unknown and gets no application layer.

| Transport | Parser tried | When |
| --- | --- | --- |
| UDP | DNS | Either port is 53, 5353 (mDNS) or 5355 (LLMNR) |
| UDP | DHCP | Either port is 67 or 68 (tried after DNS if both apply) |
| TCP | DNS (2-byte length prefix) | Either port is 53 |
| TCP | TLS, then HTTP | Any port, by structure; also tried on port 53 when the payload is not DNS |

- A UDP payload on a DNS or DHCP port that is not a valid message gets an
  `unrecognized_application_data` warning and no application layer. UDP datagrams are
  self-contained, so the mismatch is worth noting. If the snapshot length cut the datagram before
  the protocol's header could even be checked, the packet is `truncated` instead.
- TCP payloads that match nothing are left silently unknown. They may be continuation segments.
- There is **no TCP stream reassembly**. A message is recognized only when it starts at the
  beginning of a segment. Messages split across segments are decoded as far as the first segment
  goes and flagged `incomplete_application_data`. One consequence: a segment from the middle of an
  HTTP body that happens to begin with a request line is decoded as a request.
- Fragmented IP packets are not examined.
- Parsers see at most the first **8,192 bytes** of a payload.

Structural checks used for recognition:

- **DNS:** 12-byte header; opcode QUERY, IQUERY, STATUS, NOTIFY or UPDATE; Z bit clear; at most
  16 questions, at least one in a query; every question must parse.
- **DHCP:** 236-byte BOOTP header; `op` 1 or 2; hardware address length ≤ 16; magic cookie
  `0x63825363`.
- **HTTP:** a request line with a known method (`GET HEAD POST PUT DELETE CONNECT OPTIONS TRACE
  PATCH`), a printable target and `HTTP/1.0` or `HTTP/1.1`, terminated by a line ending; or a
  status line `HTTP/1.x NNN reason` with a code from 100 to 599. HTTP/2 and later are not decoded.
- **TLS:** a handshake record (content type 22, version 0x0300–0x0304, length ≤ 18,432)
  starting a ClientHello or ServerHello with a sane version and session-ID length; for a
  ClientHello, an even, non-empty cipher-suite list. Only the first record is read. A hello longer
  than its record continues in the next record. It is reported as incomplete, and the next
  record's header is never read as hello data.

## Fields

### DNS

| Field | Notes |
| --- | --- |
| `transport` | `udp` or `tcp` |
| `transaction_id`, `is_response`, `opcode`, `opcode_name` | |
| `authoritative`, `truncated`, `recursion_desired`, `recursion_available` | Header flags |
| `response_code`, `response_code_name` | `NOERROR`, `NXDOMAIN`, … |
| `question_count`, `answer_count`, `authority_count`, `additional_count` | From the header |
| `questions[]` | `name`, `record_type`, `type_name`, `class` (the first 4 are kept) |
| `answers[]` | `name`, `record_type`, `type_name`, `class`, `ttl`, `data_length`, `data` (at most 32, within the text budget below) |

`data` is a safe summary: the address for A/AAAA, the target name for CNAME/NS/PTR,
`preference exchange` for MX, `priority weight port target` for SRV. For every other type,
including TXT, `data` is `null` and only `data_length` is shown. The mDNS cache-flush bit is
masked out of `class`. Authority and additional records are counted but not listed.

Names are shown in presentation format: `.` and `\` inside a label are escaped, and non-printable
bytes are shown as `\DDD`. A name may be at most 255 wire octets. Escaping can make a name up to
four times longer, so a shown name is cut at 255 characters (ending in `...`). All names and answer
data of one message share a budget of 2,048 characters. When it runs out, no further answers are
listed and `application_limit_reached` is added.

**Compression-loop protection.** Each pointer must target an offset strictly lower than every
offset already visited for that name, and at most 16 pointers are followed per name. Self
pointers, forward pointers, cycles and long chains are rejected. A rejected question name means
the payload is not DNS. An invalid answer marks the packet `malformed`. An answer section that
runs past the available bytes is classified by why the bytes ended: `truncated` when the snapshot
length cut the message, `incomplete_application_data` when a DNS-over-TCP message continues in a
later segment, `application_limit_reached` at the 8 KiB limit, and `malformed` when a complete
message declares more answers than it holds.

**Bounded work.** Name text is built only up to the 255-character limit while the rest of the
encoding is still validated, and questions beyond the 4 kept are walked without being decoded.
The cost of a message therefore does not grow with how its names are encoded.

### DHCP

| Field | Notes |
| --- | --- |
| `op` | `request` or `reply` |
| `message_type`, `message_type_name` | Option 53: `DHCPDISCOVER` … `DHCPINFORM` |
| `transaction_id`, `hardware_type`, `hardware_address_length`, `broadcast` | |
| `client_ip`, `your_ip`, `server_ip`, `relay_ip` | `ciaddr`, `yiaddr`, `siaddr`, `giaddr` |
| `client_mac` | Only for Ethernet (type 1, length 6) |
| `requested_ip`, `server_identifier`, `lease_time_seconds` | Options 50, 54, 51 |
| `hostname` | Option 12: printable ASCII, other bytes replaced with `?`, at most 64 characters |
| `option_codes` | Codes of every option present, in order (at most 64) |

Option values other than these five are **never exposed**: not client identifiers, not vendor
data, not parameter lists. The BOOTP `sname` and `file` fields are never read.

### HTTP

| Field | Notes |
| --- | --- |
| `kind` | `request` or `response` |
| `version` | `HTTP/1.0` or `HTTP/1.1` |
| `method`, `path` | Request only; see "Request targets" below. `path` is printable ASCII, at most 256 characters (`path_truncated` says if it was cut). |
| `host` | `Host` header, or the authority of an absolute URL or a CONNECT target. Accepted only as `host[:port]` or `[ipv6][:port]`, where host is letters, digits, `-`, `_` and `.` and the port is 1–5 digits. Lowercased. |
| `status_code`, `reason` | Response only; reason at most 64 printable characters |
| `content_length`, `content_type`, `connection`, `chunked` | `content_type` is the media type only (parameters dropped); `connection` keeps only `keep-alive`, `close` and `upgrade` |
| `query_redacted` | A query string or `;` path parameters (such as `;jsessionid=`) were present and removed |
| `userinfo_redacted` | `user:password@` was present in an absolute URL and removed |
| `path_segments_redacted` | Number of path segments replaced with `{redacted}` (token-like, containing an address, or an embedded URL) |
| `target_withheld` | The request target was not shown (see below) |
| `redacted_headers` | Names of credential-bearing headers present: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `api-key`, `x-auth-token`, `x-access-token`, `x-csrf-token`, `x-xsrf-token`. Their values are never read. |
| `header_count`, `header_block` | Header lines examined; `complete` (blank line seen), `incomplete` (continues beyond this packet) or `stopped` (limit or malformed line) |

No other header is exposed (not `User-Agent`, `Referer`, `Location`, …), and bodies are never
read. Any redaction adds a `sensitive_data_redacted` warning.

#### Request targets

Only two target forms are shown:

- **Origin form** (`/path`, but not `//…`), and `*`.
- **Absolute `http://` or `https://` URLs** whose authority (everything up to the first `/`) is a
  clean `host[:port]`, optionally after `user:password@`, which is removed.

Every other form is withheld entirely and flagged `target_withheld`: other schemes (`ftp:`,
`ws:`, …), scheme-relative `//…` targets, and authorities containing `?` or `#`. These are
ambiguous and can carry credentials. For CONNECT, only a valid `host:port` is shown.

From a shown path, the query string, fragment and `;` parameters are removed. Then:

- any segment of 32 or more characters, or of 16 or more that mixes letters and digits, is
  replaced with `{redacted}`, which catches typical reset tokens, session IDs and API keys;
- any segment containing `@` or `%40` (credentials or e-mail addresses) is replaced with
  `{redacted}`;
- an embedded URL such as `/fetch/http://user:pw@host/` is cut at its scheme and replaced with a
  single `{redacted}`, because its authority may hold credentials.

Masking happens before the path is shortened to 256 characters, so a token that straddles the cut
is never partly shown. This is a heuristic: short or purely alphabetic secrets in a path are not
detected, so treat paths as potentially sensitive.

### TLS

Every TLS layer carries `"visibility": "visible handshake metadata only; nothing is decrypted"`,
and the table's Info column ends with `(handshake metadata only)`.

| Field | Notes |
| --- | --- |
| `record_version`, `record_version_name` | Record-layer version |
| `handshake_type`, `handshake_type_name` | `client_hello` or `server_hello` |
| `hello_version`, `hello_version_name` | The hello's legacy version field |
| `server_name` | SNI host name (ClientHello); validated hostname, lowercased |
| `alpn` | ALPN protocol names (at most 16, each at most 32 printable characters) |
| `cipher_suites`, `cipher_suite_count` | Offered IDs (ClientHello, at most 128) or the selected one (ServerHello) |
| `supported_versions`, `supported_groups` | From those extensions (at most 64 each) |
| `extensions[]` | `extension_type` and `name` of every extension (at most 64); GREASE values are named `GREASE` |
| `negotiated_version`, `negotiated_version_name` | ServerHello: the supported_versions selection, else the legacy version |
| `complete` | The whole hello was visible in this packet |

FlowSentinel **never decrypts TLS** and never shows the client/server random, session IDs, key
shares, pre-shared-key identities or binders, session tickets, certificates or any encrypted
record. Only ClientHello and ServerHello are parsed. Certificate, alert and application-data
records are left unknown. ALPN names that are not printable, such as GREASE values, are skipped.

## Limits

| Limit | Value |
| --- | --- |
| Payload bytes examined per packet | 8,192 |
| DNS questions (recognition / kept) / summarized answers | 16 / 4 / 32 |
| DNS compression pointers per name | 16 |
| DNS name length | 255 wire octets; 255 shown characters |
| DNS text per message (names and answer data) | 2,048 characters |
| DHCP options walked | 64 |
| DHCP host name | 64 characters |
| HTTP lines | 2,048 bytes each, 64 header lines |
| HTTP path / reason / content type | 256 / 64 / 100 characters |
| TLS cipher suites / extensions / ALPN names / versions and groups | 128 / 64 / 16 / 64 |

Reaching any of these limits adds an `application_limit_reached` warning and decoding continues.
That includes extra cipher suites, extensions, ALPN names, versions or groups beyond the
recorded counts, a shortened DHCP host name, and extra DNS questions or answers. The DNS question
limit for recognition is the exception: a message declaring more than 16 questions is not
treated as DNS at all.

## Warnings and status

| Code | Meaning | Status |
| --- | --- | --- |
| `unrecognized_application_data` | Payload on a DNS/DHCP UDP port is not a valid message | unchanged |
| `malformed_application_data` | A recognized message is invalid: DNS compression loop, a bad DHCP option length, conflicting `Content-Length`, TLS lengths that disagree inside a fully visible hello, or a UDP message whose declared contents run past the datagram | `malformed` |
| `incomplete_application_data` | A TCP message continues beyond this packet (segmentation). Never used for UDP, whose datagrams are whole messages. | unchanged |
| `truncated_header` | The snapshot length cut a recognized message, or a hinted UDP message's header, short | `truncated` |
| `application_limit_reached` | A limit in the table above was reached | unchanged |
| `sensitive_data_redacted` | Credentials, cookies, tokens, a query string or URL credentials were removed | unchanged |

Per packet, each warning code is listed once per layer. The JSON fields (`query_redacted`,
`userinfo_redacted`, `redacted_headers`) show every redaction that applied.

## Privacy verification

The fixtures embed `FLOWSENTINEL-SECRET` in every credential-like position:

- an `Authorization` bearer token, a cookie, a `Set-Cookie` value and a query string;
- URL credentials (also inside a request path) and a form-posted password;
- a TXT record;
- the TLS random, session ID and key share.

Integration tests run every output mode (`--decode`, `--verbose`, `--json`) on every fixture and
assert that the marker never appears. The payload marker string is checked the same way. During
development, the DNS, DHCP, HTTP and TLS fields extracted from the fixtures were compared against
Scapy: 137 comparisons, 0 mismatches (for redacted paths, only the part before `{redacted}`).

## Fixtures

| File | Contents |
| --- | --- |
| `app-dns.pcap` | A/AAAA queries and responses with name compression, NXDOMAIN, MX, TXT, mDNS, a compression loop, DNS over TCP, non-DNS bytes on port 53, a response cut by the snapshot length |
| `app-dhcp.pcap` | DISCOVER, OFFER, REQUEST, ACK, then non-DHCP bytes on port 68→67 |
| `app-http.pcap` | GET with query string, `Authorization` and `Cookie`; 200 response with `Set-Cookie` and a body; POST with URL credentials and a password body; HEAD on port 8080; non-HTTP bytes on port 80; a GET whose path embeds a URL with credentials |
| `app-tls.pcap` | ClientHello (SNI, ALPN, GREASE, key share), ServerHello (TLS 1.3), Certificate and application-data records, ClientHello on port 8443 |
