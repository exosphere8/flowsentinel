# Security Policy

FlowSentinel processes network traffic, which is sensitive by nature. This document covers
acceptable use, how to report vulnerabilities, and the project's current security posture.

## Authorized use

Use FlowSentinel only on networks and traffic that you own or are explicitly authorized to inspect.
Capturing or analyzing other people's traffic without permission may be illegal where you live.
Before you capture or import traffic, make sure you have consent and that you comply with
applicable law and policy.

FlowSentinel is a defensive tool. These features are explicit non-goals and will not be accepted:
packet injection, active scanning, traffic manipulation or evasion, decryption without authorized
keys, credential or secret extraction, exploitation, persistence, and stealth features.

## Reporting a vulnerability

Do **not** open a public issue for security problems.

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/exosphere8/flowsentinel/security/advisories/new).
Include the affected version or commit, reproduction steps, and the impact you observed. Use
synthetic inputs only; never attach real captures.

You can expect an acknowledgement within 7 days. Once a fix is available, there will be a
coordinated disclosure that credits you unless you prefer otherwise.

## Supported versions

FlowSentinel is pre-1.0. Only the latest commit on `main` receives security fixes.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Older commits | No |

## Current security posture (Milestone 3)

- The API binds to `127.0.0.1` by default and has **no authentication yet**. Do not expose it to
  a network. The server logs a warning if configured to listen on a non-loopback address.
- The API serves only `GET /health`, which touches no data.
- PostgreSQL and Redis bind to loopback, and Compose refuses to start them without passwords
  from `.env`. `.env` is git-ignored; only `.env.example` with placeholder values is committed.
- `.gitignore` blocks `*.pcap`/`*.pcapng` outside `fixtures/` so real captures aren't committed by
  accident. Fixtures must be synthetic.
- All crates set `unsafe_code = "forbid"`.
- Logs are structured JSON and never contain packet data.
- `flowsentinel inspect` treats capture files as hostile input. It validates the path, type,
  extension and size before reading. It streams the file through a fixed buffer, never sizes an
  allocation from a value in the file, and rejects records that declare more than libpcap's
  maximum for the link type (262,144 bytes for most types).
  Packet-count and time limits bound the work. It outputs container metadata only: packet bytes
  are skipped, never stored, and never appear in output or error messages. File names are reduced
  to a sanitized final component. Details: [docs/pcap-ingestion.md](docs/pcap-ingestion.md).
- `inspect --decode` examines each packet's bytes only during one function call and keeps typed
  header metadata. Payloads are reported by length only; no decoder type can hold payload bytes.
  All field access is bounds-checked, traversal loops (VLAN tags, IPv6 extension headers) have
  fixed limits, and a malformed packet yields a status and warning instead of an error. Property
  tests and cargo-fuzz targets (`fuzz/`) exercise the parsers with arbitrary input. Details:
  [docs/protocol-decoding.md](docs/protocol-decoding.md).
- Application metadata (DNS, DHCP, HTTP/1.x, TLS handshakes) is extracted field by field with
  fixed size limits; nothing is copied wholesale. HTTP bodies, query strings, URL credentials,
  cookies and authorization/token headers are never read into output; their presence is reported
  as a redaction. DHCP option values other than five documented ones are never exposed. TLS is
  never decrypted, and randoms, session IDs, key shares, PSK identities, tickets and certificates
  are skipped. DNS compression pointers are loop-protected and decoded text is budgeted per
  message. HTTP request targets other than plain paths or `http(s)://host` URLs are withheld, and
  token-like path segments are masked (a heuristic). Fixtures embed secret marker strings, and
  tests assert they never appear in any output, in any letter case. Details:
  [docs/application-metadata.md](docs/application-metadata.md).

Later milestones add authentication and RBAC (9), audit logging (9), upload hardening (5, 11),
and dependency auditing, secret scanning and static analysis in CI (11).
