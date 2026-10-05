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

FlowSentinel is pre-1.0. Security fixes go to `main` and are released as a patch of the latest
minor version (see [docs/releasing.md](docs/releasing.md)).

| Version | Supported |
| --- | --- |
| Latest release (0.1.x) | Yes |
| `main` | Yes |
| Older releases | No; upgrade to the latest release |

## Current security posture

- Every API call except sign-in and `/health` needs a signed-in session, and each account has a
  role: viewers read, analysts also import and triage, admins also delete captures, change
  settings, manage accounts and read the audit log. The server checks the role on every request;
  the dashboard only hides what a role cannot use.
- Passwords are hashed with Argon2id (19 MiB, 2 passes), at most four at a time. Session tokens
  are 256-bit random values in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` and
  `__Host-`-prefixed with `FLOWSENTINEL_SECURE_COOKIES=true`), stored only as SHA-256 digests,
  issued fresh at each sign-in, and ended by inactivity (30 minutes), age (12 hours), sign-out,
  or any change to the account's role, state or password.
- State-changing requests need the session's CSRF token in `X-CSRF-Token`, and requests that a
  browser marks as cross-site, or whose `Origin` differs from their `Host`, are refused.
- Failed sign-ins are limited per username (5 in 15 minutes) and per client address (20); wrong,
  unknown and disabled accounts get the same answer after the same amount of hashing work.
- A security audit log records sign-ins, refused requests and every change with account, client
  address and outcome, without passwords or tokens, and is kept for a configurable period.
  Details: [docs/authentication.md](docs/authentication.md).
- The server listens on `127.0.0.1` by default. To reach it from a network, put it behind an
  HTTPS reverse proxy and set `FLOWSENTINEL_SECURE_COOKIES=true`; it logs a warning when it
  listens elsewhere without secure cookies. It never needs root privileges.
- The API sends no CORS headers, and every state-changing request needs a non-simple content
  type (uploads require `application/vnd.tcpdump.pcap` or `application/octet-stream`) or method
  (`PUT`, `PATCH`, `DELETE`). Browsers therefore block cross-site requests to it from other origins.
  Requests whose `Host` header is not a name of the server (by default only loopback names) are
  refused with `421`, which stops DNS-rebinding pages from reaching a loopback API; set
  `FLOWSENTINEL_ALLOWED_HOSTS` when clients use another name.
- Uploads are streamed to a randomly named file in the upload directory (owner-only permissions
  on Unix), limited in size (`FLOWSENTINEL_MAX_UPLOAD_MB`, checked against `Content-Length` and
  while streaming), in idle time (30 s) and in rate (at least 16 KiB/s on average after 30 s),
  and deleted when the import ends, successfully or not. Files left by a server that was killed
  mid-import are deleted at the next startup. Only the sanitized final component of the
  client's file name is stored. Imports run at most `FLOWSENTINEL_MAX_CONCURRENT_IMPORTS` at a
  time, each holding its slot until its analysis threads finish, and each is analyzed under
  packet, time and flow limits. Reads use the database pool minus connections reserved for
  imports, and shutdown waits at most 30 seconds for running requests.
- Every response carries a strict Content Security Policy (same-origin scripts, styles and
  connections only; no inline scripts, plugins or framing), `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` and
  `Cross-Origin-Resource-Policy: same-origin`, and a `Permissions-Policy` denying device APIs;
  HSTS when served through HTTPS (`FLOWSENTINEL_SECURE_COOKIES=true`). API responses are never
  cached (`Cache-Control: no-store`). The dashboard renders all capture-derived text
  (file names, DNS names, HTTP paths, TLS server names) as text, never as HTML; ESLint rejects
  `dangerouslySetInnerHTML`, `innerHTML` and `outerHTML`. It refuses to render payload-like
  fields even if the API were to send them. It loads nothing from third-party origins. Details:
  [docs/dashboard.md](docs/dashboard.md).
- The container image (`Dockerfile`, Compose `app` profile) runs the server as an unprivileged
  user (UID 10001), with a read-only root file system, all Linux capabilities dropped and
  `no-new-privileges`; only the upload volume is writable, and the port is published on
  `127.0.0.1`. Its health check uses the server binary itself, so the image contains no shell
  tools for it. The `app` container is limited to 256 processes, and the database containers
  also run with `no-new-privileges`.
- The server refuses to start with an upload directory that other users can write to (unless it
  has the sticky bit, like `/tmp`). PostgreSQL ends statements and idle transactions after five
  minutes, and database connections can use TLS with certificate verification
  (`sslmode=verify-full`).
- Logs, metrics and traces never contain request bodies, query strings (which can hold display
  filters), credentials or packet data. Access logs, metrics and traces name requests by route
  template, never by path. Traces carry only request spans and access events. The optional metrics
  listener has no authentication and is off by default. Details:
  [docs/observability.md](docs/observability.md).
- Supply chain: CI checks Rust dependencies against the RustSec advisory database, licenses and
  sources (`cargo-deny`, `deny.toml`), and runs `npm audit` for the dashboard. It scans new
  commits, and weekly the whole Git history, for secrets (gitleaks), and runs CodeQL on the
  dashboard and the workflows. Fuzz targets cover the packet parsers, the filter language and the
  API's request-input checks. Deployment checklist: [docs/hardening.md](docs/hardening.md).
- Live capture is passive and opt-in. It is compiled in only with the `live-capture` feature, off
  unless `FLOWSENTINEL_LIVE_CAPTURE=true`, admin-only, and needs an explicit authorization
  confirmation for each capture. Interfaces can be restricted with `FLOWSENTINEL_LIVE_INTERFACES`.
  Promiscuous mode is off unless requested; filters are length- and character-checked and
  compiled by libpcap before capturing. Every capture is bounded in time, packets, bytes and
  snapshot length; a slow writer causes counted drops, not unbounded memory. Packets go to a
  private temporary file that is imported as metadata and deleted. The server needs only
  `CAP_NET_RAW` for it (tested as an unprivileged user in CI), never root. Starts, stops and
  results are audited. Details: [docs/live-capture.md](docs/live-capture.md) and
  [docs/permissions.md](docs/permissions.md).
- Storage is metadata only: no table has a column that can hold payload bytes, and the redaction
  rules of the decoder apply to everything stored. Integration tests import every application
  fixture and check that no secret or payload marker reaches the database or any API response.
- Every SQL statement is parameterized. Sort orders are fixed fragments chosen by enums, and
  query parameters are validated (unknown parameters are rejected). Errors are structured JSON
  without SQL, file paths or stack traces. JSON request bodies are limited to 16 KiB.
- Display filters are tokenized, parsed and type-checked against a fixed field catalog with
  length, token, nesting and clause limits. They are translated into fixed SQL fragments and
  bound parameters only, so filter text cannot change a query's structure. Property tests and a
  fuzz target check this. Filtered lists run under a statement timeout (default 10 s) and at most
  half of the read slots serve them at once, so an expensive filter cannot take the
  database away from other requests or imports. See [docs/filter-language.md](docs/filter-language.md).
- The database URL, which contains a password, is never logged or returned. `Config`'s `Debug`
  output redacts it. Retention (default 30 days, hourly purge) bounds how long imported metadata
  is kept; see [docs/data-retention.md](docs/data-retention.md).
- PostgreSQL binds to loopback, and Compose refuses to start it without a password from
  `.env`. `.env` is git-ignored; only `.env.example` with placeholder values is committed.
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
- `flowsentinel flows` builds flows from decoded metadata only; it never sees packet bytes. The
  active-flow table and the list of finished flows have fixed maximums (`--max-active-flows`,
  `--max-flows`), per-flow state is constant-size, and application lists are capped. A capture
  crafted to create millions of flows therefore causes evictions and uncounted records, not
  unbounded memory. Flows are timed by an internal clock that ignores a lone timestamp more than
  a day off, so a corrupt record cannot end, freeze or immortalize flows. Details: [docs/flow-engine.md](docs/flow-engine.md).
- Detection rules (`flowsentinel detect` and API imports) read decoded metadata and flow records
  only. Alerts are described everywhere as **heuristic indicators, not proof of compromise**;
  each carries its evidence, uncertainty and likely false positives, and ATT&CK techniques are
  context tags, never claims. Rules are passive: no lookups, probing or blocking. Their state is
  bounded against crafted captures (per-key, per-rule and per-alert limits, windows that give
  memory back as events expire, least-recent keys evicted when a table is full, alerts per rule
  capped at 1,000 before they are built, subdomains held as digests, a time base that a lone
  corrupt timestamp cannot move), and events or keys over a limit are counted, not silently lost. The detection configuration is
  size-limited, rejects unknown keys and is range-checked; the API refuses to start with an
  invalid one. Only an alert's status can be changed through the API. Details:
  [docs/detection-rules.md](docs/detection-rules.md).

Planned improvements are tracked as GitHub issues; reports and suggestions are welcome.
