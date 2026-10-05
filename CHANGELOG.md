# Changelog

All notable changes to FlowSentinel are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Until 1.0.0, minor versions may change the API,
the database schema (migrations run automatically) and configuration; each such change is listed
under **Changed** with what to do.

## [Unreleased]

## [0.1.0] - 2026-10-05

The first public release. FlowSentinel is a defensive, metadata-first packet analyzer: it reads
captures you are authorized to inspect, reconstructs flows, explains suspicious patterns, and
stores and shows metadata only, never payloads.

### Added

- **Offline capture analysis** (`flowsentinel` CLI):
  - `inspect` reads classic libpcap files under strict size, packet and time limits.
  - `inspect --decode` decodes Ethernet (with VLANs), ARP, IPv4, IPv6 (with extension headers),
    ICMP, ICMPv6, TCP and UDP into a protocol tree.
  - Bounded metadata from DNS, DHCP, HTTP/1.x and visible TLS handshakes: SNI, ALPN, versions
    and cipher-suite IDs. Credentials, cookies, query strings and bodies are redacted; TLS is
    never decrypted.
  - `flows` reconstructs bidirectional flows with per-direction statistics and approximate TCP
    state, within fixed memory limits.
  - `detect` runs twelve explainable heuristic rules: scans, failed connections, beaconing,
    rare ports, large outbound transfers, cleartext logins, DNS volume and tunneling, and ARP
    conflicts and floods. Each alert carries its evidence, cited flows or packets, uncertainty
    and likely false positives.
- **API server**:
  - Imports captures into PostgreSQL as metadata only.
  - Serves captures, packets, flows, DNS/HTTP/TLS events and alerts, with pagination,
    validated sorting, structured errors and an OpenAPI description.
  - Wireshark-like display filters, type-checked and translated into parameterized SQL.
  - Alert triage.
  - Retention settings and automatic purging.
- **Web dashboard** served by the API server: overview, captures, packets with their protocol
  trees, flows, alerts with evidence and triage, settings, accounts, the audit log and live
  capture. Strict Content Security Policy; no payload is ever rendered.
- **Accounts**:
  - Viewer, analyst and admin roles; Argon2id password hashing.
  - Sessions with idle and absolute timeouts, CSRF protection, and sign-in rate limits.
  - A security audit log.
- **Authorized live capture** (`live-capture` feature, off unless enabled):
  - Admin-only, with an explicit authorization confirmation per capture.
  - Bounded in time, packets and bytes.
  - BPF filters checked before use; promiscuous mode off by default.
  - Needs only `CAP_NET_RAW`.
- **Observability**:
  - A request ID in every response and log line.
  - JSON access logs with route templates.
  - A readiness probe.
  - Optional Prometheus metrics and OpenTelemetry traces, none of which carry capture data.
- **Hardening**:
  - Security headers, including HSTS behind HTTPS.
  - Database TLS with certificate verification, and server-side statement timeouts.
  - Upload-directory permission checks.
  - Lints that deny panicking shortcuts outside tests.
  - A container that runs as an unprivileged user with a read-only file system and no
    capabilities.
- **Supply chain**:
  - `cargo-deny`, `npm audit`, gitleaks and CodeQL in CI.
  - Fuzz targets for every parser of untrusted input.
  - Property tests, end-to-end browser tests, benchmarks and a load-test script.
- **Releases**:
  - Prebuilt binaries for Linux (x86-64, ARM64), macOS (Apple silicon, Intel) and Windows
    (x86-64), with SHA-256 checksums and build provenance attestations.
  - A container image for linux/amd64 and linux/arm64 on GitHub Container Registry, with an SBOM
    and provenance.
  - License notices for all bundled third-party code (`THIRD_PARTY_LICENSES.md`).

### Known limitations

- Only classic pcap files are read; pcapng must be converted first (`editcap -F pcap`).
- Only Ethernet link types are decoded. Linux cooked captures (`any`), raw IP, macOS loopback
  and 802.11 are counted as unsupported.
- No TCP stream reassembly: application messages are recognized only when they start at the
  beginning of a segment. HTTP/2, HTTP/3 and QUIC are not decoded.
- Detections are heuristics over one capture at a time, with generic default thresholds. Tune
  them for your network and expect both missed patterns and false positives.
- One live capture at a time; no continuous or scheduled capture.
- One server process per database: the sign-in rate limits and live-capture slot are held in
  memory.

[Unreleased]: https://github.com/exosphere8/flowsentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/exosphere8/flowsentinel/releases/tag/v0.1.0
