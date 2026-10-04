# Display-filter language

Packet and flow lists in the API accept a **display filter**: a small, Wireshark-like language
for selecting rows by their metadata. Filters are parsed, type-checked against a fixed list of
fields, and translated into SQL in which every value you write is a bound query parameter.
Filter text never becomes SQL text.

```text
ip.addr == 192.0.2.0/24 and tcp.port == 443
dns.qry.name contains "example" or tls.sni == "www.example.com"
not arp and frame.len > 1000
tcp.flags.syn and not tcp.flags.ack
flow.bytes >= 1000000 && flow.duration > 60
```

## Using filters

| Request | Effect |
| --- | --- |
| `GET /api/v1/captures/{id}/packets?filter=...` | Lists matching packets (paginated and sorted as usual) |
| `GET /api/v1/captures/{id}/flows?filter=...` | Lists matching flows |
| `GET /api/v1/filters/validate?target=packets&filter=...` | Checks a filter without running it; returns the normalized form |
| `GET /api/v1/filters/fields?target=flows` | Lists the fields, their types, operators and allowed values |

URL-encode the filter in the query string (for example `%3D%3D` for `==` and `%22` for `"`). A
blank filter means no filter. Packet and flow filters use different fields: `frame.len` exists
only for packets, and `flow.bytes` only for flows.

```bash
curl -G http://127.0.0.1:8080/api/v1/captures/1/packets \
  --data-urlencode 'filter=tls.sni contains "example" and not ip.dst == 10.0.0.0/8'
```

## Syntax

```text
filter     = or
or         = and { ("or" | "||") and }
and        = unary { ("and" | "&&") unary }
unary      = ("not" | "!") unary | "(" filter ")" | comparison | field
comparison = field operator value
operator   = "==" | "!=" | "<" | "<=" | ">" | ">=" | "contains"
             (or the words eq, ne, lt, le, gt, ge)
value      = number | address | address/prefix | word | "quoted string"
```

- `not` binds tighter than `and`, which binds tighter than `or`; use parentheses to group.
- Keywords and field names are case-insensitive.
- Strings are double-quoted. Inside them only `\"` and `\\` are escapes; control characters are
  rejected. Unquoted words also work as values where they are unambiguous (`decode.status ==
  malformed`, `http.host == www.example.com`).
- A **boolean field** alone tests it: `tcp`, `dns`, `tcp.flags.syn`. `== true` and `== false`
  also work.

## Meaning

| Field type | Operators | Notes |
| --- | --- | --- |
| IP address or CIDR | `==`, `!=` | `==` means "within": `ip.src == 192.0.2.0/24`. A bare address is a /32 or /128. IPv4 and IPv6 both work |
| Integer, number | `==`, `!=`, `<`, `<=`, `>`, `>=` | Integers must be whole and within the field's range; `flow.duration` accepts decimals |
| Text | `==`, `!=`, `contains` | Case-insensitive. `contains` is a plain substring test, with no wildcards |
| Keyword | `==`, `!=` | One of the field's listed values, case-insensitive |
| Boolean | `==`, `!=`, or bare | |

- A field that has no value for a row never matches, whatever the operator. `ip.addr != 192.0.2.1`
  does not match ARP packets, which have no IP address, while `not ip.addr == 192.0.2.1` does.
  This follows Wireshark.
- Fields with two sides (`ip.addr`, `port`, `tcp.port`) match if either side matches. With `!=`,
  neither side may match.
- `tcp.port` and `udp.port` also require the packet or flow to be TCP or UDP. `port` accepts
  either. A flow without ports (ICMP, ESP, or TCP/UDP seen only as fragments without the
  transport header) has no port value, so no port field matches it, just as for such packets.
- The DNS, HTTP and TLS text fields hold the values the decoder extracted, already redacted (see
  [application-metadata.md](application-metadata.md)). For flows they hold the first such value
  in the flow.

## Fields

### Packet fields

| Field | Type | Meaning |
| --- | --- | --- |
| `frame.number` | unsigned integer | 1-based packet index |
| `frame.len` | unsigned integer | On-the-wire length in bytes |
| `frame.cap_len` | unsigned integer | Captured length in bytes |
| `ip.src` | IP address or CIDR | Source IP address |
| `ip.dst` | IP address or CIDR | Destination IP address |
| `ip.addr` | IP address or CIDR | Source or destination IP address |
| `ip.proto` | integer 0–255 | IP protocol number |
| `port` | integer 0–65535 | TCP or UDP source or destination port |
| `tcp.port` | integer 0–65535 | TCP source or destination port |
| `tcp.srcport` | integer 0–65535 | TCP source port |
| `tcp.dstport` | integer 0–65535 | TCP destination port |
| `udp.port` | integer 0–65535 | UDP source or destination port |
| `udp.srcport` | integer 0–65535 | UDP source port |
| `udp.dstport` | integer 0–65535 | UDP destination port |
| `tcp.flags.fin` | boolean | TCP FIN flag |
| `tcp.flags.syn` | boolean | TCP SYN flag |
| `tcp.flags.rst` | boolean | TCP RST flag |
| `tcp.flags.psh` | boolean | TCP PSH flag |
| `tcp.flags.ack` | boolean | TCP ACK flag |
| `tcp.flags.urg` | boolean | TCP URG flag |
| `dns.qry.name` | text | First DNS question name |
| `http.host` | text | HTTP host |
| `tls.sni` | text | TLS server name (SNI) |
| `decode.status` | keyword: `complete`, `unsupported`, `truncated`, `malformed` | Decode status |
| `ethernet` | boolean | Has an Ethernet layer |
| `arp` | boolean | Is ARP |
| `ip` | boolean | Has an IPv4 or IPv6 layer |
| `ipv4` | boolean | Has an IPv4 layer |
| `ipv6` | boolean | Has an IPv6 layer |
| `icmp` | boolean | Is ICMP |
| `icmpv6` | boolean | Is ICMPv6 |
| `tcp` | boolean | Is TCP |
| `udp` | boolean | Is UDP |
| `dns` | boolean | Carries DNS |
| `dhcp` | boolean | Carries DHCP |
| `http` | boolean | Carries HTTP |
| `tls` | boolean | Carries a TLS handshake |

### Flow fields

| Field | Type | Meaning |
| --- | --- | --- |
| `flow.id` | unsigned integer | Flow ID |
| `flow.initiator` | IP address or CIDR | Initiator IP address |
| `flow.responder` | IP address or CIDR | Responder IP address |
| `ip.addr` | IP address or CIDR | Either endpoint's IP address |
| `ip.version` | integer 0–6 | IP version (4 or 6) |
| `ip.proto` | integer 0–255 | IP protocol number |
| `flow.initiator_port` | integer 0–65535 | Initiator port |
| `flow.responder_port` | integer 0–65535 | Responder port |
| `port` | integer 0–65535 | Either endpoint's port |
| `tcp.port` | integer 0–65535 | Either TCP port |
| `udp.port` | integer 0–65535 | Either UDP port |
| `flow.bytes` | unsigned integer | Bytes in both directions |
| `flow.packets` | unsigned integer | Packets in both directions |
| `flow.duration` | number | Duration in seconds |
| `flow.state` | keyword: `syn_sent`, `syn_received`, `established`, `midstream`, `closing`, `closed`, `reset` | Approximate TCP state |
| `flow.end_reason` | keyword: `idle_timeout`, `tcp_finished`, `evicted`, `capture_end`, `clock_reset` | Why the flow ended |
| `dns.qry.name` | text | First DNS name queried in the flow |
| `http.host` | text | First HTTP host in the flow |
| `tls.sni` | text | First TLS server name in the flow |
| `ipv4` | boolean | Is IPv4 |
| `ipv6` | boolean | Is IPv6 |
| `tcp` | boolean | Is TCP |
| `udp` | boolean | Is UDP |
| `icmp` | boolean | Is ICMP |
| `icmpv6` | boolean | Is ICMPv6 |
| `dns` | boolean | Carried DNS |
| `dhcp` | boolean | Carried DHCP |
| `http` | boolean | Carried HTTP |
| `tls` | boolean | Carried a TLS handshake |

## Limits and errors

| Limit | Value |
| --- | --- |
| Filter length | 1,024 bytes |
| Tokens | 256 |
| Value (quoted or not) | 255 characters |
| Nesting (parentheses and `not`) | 16 levels |
| Comparisons and field tests | 64 |

An invalid filter is rejected with HTTP 400 and a structured error that gives the byte range of
the problem:

```json
{ "error": { "code": "unknown_field", "message": "invalid filter: unknown field `nosuch` at position 20",
             "position": { "start": 20, "end": 26 } } }
```

| Code | Cause |
| --- | --- |
| `empty_filter` | Only whitespace (from `/filters/validate`; list endpoints treat it as no filter) |
| `filter_too_long`, `filter_too_complex` | A limit above was exceeded |
| `unexpected_character`, `unterminated_string`, `invalid_escape` | The text could not be tokenized |
| `syntax_error` | The tokens do not form a filter; the message says what was expected |
| `unknown_field` | Not a field of this target |
| `invalid_operator` | The operator does not apply to the field's type |
| `invalid_value` | The value does not fit the field, for example a port above 65535 or a malformed address |

Error messages quote at most a field name (shortened to 64 characters) or one unexpected
printable character, never the rest of the filter. Positions are byte offsets into the filter as
sent (it is not trimmed) and always cover whole characters; an error at the end of the filter has
an empty range at its length.

### Query time limits

A valid filter can still be expensive: `contains` and case-insensitive comparisons on text fields
scan every row of a capture. Two limits keep one client from tying up the database:

- Each filtered packet or flow list runs with a statement timeout (10 seconds by default,
  `FLOWSENTINEL_QUERY_TIMEOUT_SECONDS`). A query that exceeds it is cancelled in the database and
  the request gets `503 query_timeout`; narrow the filter (for example add `ip.addr == ...` or
  `tcp.port == ...`) and try again.
- At most half of the API's read slots (the database pool minus connections reserved for
  imports) serve filtered lists at once; further filtered requests get `429 filter_busy`
  immediately.

### Normalized form

`/filters/validate` returns the filter in a canonical form: keywords lowercased, operators
spelled out (`and`, `or`, `not`, `==`), values quoted and parentheses kept only where the
structure needs them. The normalized form compiles to exactly the same SQL. It can be longer
than what was typed, because of the added spaces and quotes; if it exceeds the 1,024-byte limit,
it is rejected as too long when sent back.

## How filters run

1. The **lexer** splits the text into tokens with byte positions and enforces the length and token
   limits.
2. The **parser** builds a syntax tree by recursive descent with depth and clause limits.
3. The **checker** looks every field up in the catalog for the target, checks the operator against
   the field's type and converts each value: IP and CIDR, integer within range, finite number,
   keyword from the allowed list, or text.
4. The **translator** emits SQL as a list of pieces. Each piece is either a fixed SQL fragment
   compiled into the program or a typed parameter (`text`, `bigint` or `double precision`). The
   API binds the parameters with SQLx. Each comparison is wrapped in `COALESCE(..., false)`, so a
   missing value cannot make `not` match by accident.

Because only fixed fragments become SQL, a filter cannot change the query's structure, whatever it
contains. Tests and a fuzz target check this: quoted text always becomes exactly one parameter,
injection attempts match nothing and leave the data intact, arbitrary input never panics, error
positions are whole characters within the input, and normalized filters (nested, negated, with
long numbers and values) reparse to the same SQL whenever they fit the length limit.
