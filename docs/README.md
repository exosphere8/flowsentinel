# Documentation

| Document | Contents |
| --- | --- |
| [../README.md](../README.md) | Overview, quick start, roadmap |
| [../ARCHITECTURE.md](../ARCHITECTURE.md) | Components, boundaries, design principles |
| [../SECURITY.md](../SECURITY.md) | Authorized use, vulnerability reporting, security posture |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Local setup, workflow, quality gates |
| [pcap-ingestion.md](pcap-ingestion.md) | `flowsentinel inspect`: supported input, limits, output, errors |
| [protocol-decoding.md](protocol-decoding.md) | `inspect --decode`: protocols, statuses, warnings, validation rules |
| [application-metadata.md](application-metadata.md) | DNS, DHCP, HTTP and TLS handshake metadata: recognition, fields, limits, redaction |
| [flow-engine.md](flow-engine.md) | `flowsentinel flows`: flow keys, direction, statistics, TCP state, expiry, memory limits |
| [api.md](api.md) | REST API: running, importing, endpoints, pagination, sorting, errors |
| [filter-language.md](filter-language.md) | Display filters: syntax, fields, semantics, limits, errors, how they become SQL |
| [detection-rules.md](detection-rules.md) | `flowsentinel detect` and API alerts: the rules, alert fields, thresholds, limits, measurements |
| [authentication.md](authentication.md) | Accounts, roles, sessions, CSRF, sign-in limits and the audit log |
| [live-capture.md](live-capture.md) | Authorized live capture: turning it on, limits, filters, backpressure, API |
| [permissions.md](permissions.md) | Least-privilege capture permissions on Linux, Docker, macOS and Windows |
| [dashboard.md](dashboard.md) | The web dashboard: pages, running it, security headers, privacy, accessibility, tests |
| [data-retention.md](data-retention.md) | What is stored, what never is, retention settings and deletion |
| [observability.md](observability.md) | Request IDs, logs, health and readiness, Prometheus metrics, OpenTelemetry |
| [hardening.md](hardening.md) | Deployment checklist, response headers, database TLS, containers, supply-chain checks |
| [performance.md](performance.md) | Benchmarks, load testing, measured throughput and latency |
| [../fuzz/README.md](../fuzz/README.md) | Running the cargo-fuzz targets |

Each later milestone adds its own document here.
