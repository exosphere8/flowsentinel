# Hardening

This document lists FlowSentinel's defences and the checklist for deploying it. The threat model
and vulnerability reporting are in [../SECURITY.md](../SECURITY.md).

## Deployment checklist

- [ ] **Authorized use only.** Import only captures, and capture only on networks, that you own or
      are authorized to inspect.
- [ ] **Keep the server off the open network.** By default it listens on `127.0.0.1:8080`. To
      reach it from elsewhere, put it behind an HTTPS reverse proxy and set
      `FLOWSENTINEL_SECURE_COOKIES=true`. This gives a `Secure`, `__Host-` session cookie and
      HSTS.
- [ ] **Set `FLOWSENTINEL_ALLOWED_HOSTS`** to the names clients use, and nothing broader. Other
      `Host` headers get `421`, which stops DNS-rebinding pages.
- [ ] **Create the first admin from a password file** (`FLOWSENTINEL_ADMIN_PASSWORD_FILE`) or with
      `make admin`, then remove the file. Give every person their own account with the least role
      they need ([authentication.md](authentication.md)).
- [ ] **Use a strong, unique `POSTGRES_PASSWORD`** and keep `.env` out of version control (it is
      git-ignored).
- [ ] **Encrypt the database connection** when PostgreSQL is on another host: see
      [Database](#database).
- [ ] **Give the upload directory to the server alone** (`chmod 700`). The server refuses to start
      if other users can write to it, unless it has the sticky bit like `/tmp`. In Kubernetes,
      `emptyDir` volumes are writable by everyone, so point `FLOWSENTINEL_UPLOAD_DIR` at a
      subdirectory owned by the server's user with mode 700. For example, create it with
      `mkdir -m 700 /uploads/private` in an init container running as the same user (UID 10001
      for the image).
- [ ] **Keep metrics private.** If you set `FLOWSENTINEL_METRICS_ADDR`, bind it to loopback or a
      network only your collector reaches; it has no authentication
      ([observability.md](observability.md#metrics)).
- [ ] **Leave live capture off** unless you need it. If you turn it on:
  - Set `FLOWSENTINEL_LIVE_INTERFACES`.
  - Grant only `CAP_NET_RAW`, never root ([permissions.md](permissions.md)).
- [ ] **Review retention**: how long captures (default 30 days) and audit events (default 365
      days) are kept ([data-retention.md](data-retention.md)).
- [ ] **Watch the audit log** and the `flowsentinel_audit_events_total` metric for failed sign-ins
      and refused actions.
- [ ] **Keep up to date**, and rebuild the image to pick up base-image security fixes.

## HTTP

Every response carries these headers:

- **Content Security Policy:** `default-src 'self'`. It allows no inline scripts or styles, no
  plugins and no framing.
- **Basic hardening headers:**
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
- **Cross-origin isolation:** `Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Resource-Policy: same-origin`.
- **Device APIs:** `Permissions-Policy` turns off camera, microphone, geolocation, payment and
  USB.
- **`X-Request-Id`.**
- **HSTS** (`max-age=31536000`), with `FLOWSENTINEL_SECURE_COOKIES=true` only.

Exact values are in [dashboard.md](dashboard.md#security).

API responses also carry `Cache-Control: no-store`, so capture metadata is not kept by browsers
or proxies.

The server sends no CORS headers. Every state-changing request needs a session cookie
(`SameSite=Strict`), a CSRF token header and a same-origin `Origin`.

Request bodies and work are bounded:

- JSON bodies are limited to 16 KiB.
- Uploads are limited in size, idle time and rate.
- Imports, reads, filtered queries and password hashing each have their own concurrency limits.
- Filtered queries run under a statement timeout.
- Sign-ins are rate-limited per account and per address.

Details are in [api.md](api.md#security-notes) and [authentication.md](authentication.md).

## Database

The server connects with a bounded pool. Each connection:

- is named `flowsentinel-api` in `pg_stat_activity`;
- has `statement_timeout` and `idle_in_transaction_session_timeout` set to five minutes, so a
  stuck statement or client cannot hold locks indefinitely;
- uses only parameterized SQL (see [api.md](api.md#security-notes)).

TLS is chosen by `sslmode` in `FLOWSENTINEL_DATABASE_URL`:

| `sslmode` | Effect |
| --- | --- |
| `disable` | No TLS |
| `prefer` (default) | TLS when the server offers it, without verification; fine on loopback or a private Docker network, not across untrusted networks |
| `require` | TLS always, without verifying the server |
| `verify-full` | TLS, with the certificate checked against trusted CAs and the host name. **Use this across any network you do not control.** |

Trusted CAs are the system's certificate store, or the file named by `sslrootcert`:

```sh
FLOWSENTINEL_DATABASE_URL='postgres://flowsentinel:...@db.example.internal:5432/flowsentinel?sslmode=verify-full&sslrootcert=/etc/flowsentinel/db-ca.crt'
```

We tested against PostgreSQL 16 with a test CA:

- `verify-full` connected over TLS with the right CA.
- `verify-full` refused a certificate from another CA, a certificate for another host name, and a
  server whose CA was not given.
- `require` connected over TLS.

With this client, `verify-ca` also checks the host name. Use `verify-full` to make that explicit.

Give the database account only the rights it needs. It owns FlowSentinel's tables and runs the
migrations at startup; it needs no superuser or `CREATEDB` rights. Migrations and the hourly
retention purge lift the five-minute statement limit for themselves, because they can
legitimately run longer.

Behind a connection pooler such as PgBouncer, the per-connection settings may be refused or
ignored: PgBouncer rejects the `options` startup parameter unless it is listed in
`ignore_startup_parameters`, and then does not apply it. In that case, set the limits on the
database role instead:

```sql
ALTER ROLE flowsentinel SET statement_timeout = '300s';
ALTER ROLE flowsentinel SET idle_in_transaction_session_timeout = '300s';
```

## Containers

The `Dockerfile` and the Compose `app` profile run the server:

- as UID 10001, never root;
- with a read-only root file system, the upload volume being the only writable path;
- with all Linux capabilities dropped and `no-new-privileges`;
- with a limit of 256 processes and threads (`pids_limit`; see the comment in
  `docker-compose.yml`);
- published on `127.0.0.1` only;
- with a health check built into the server binary, so the image contains no shell tools for it.

The PostgreSQL container also runs with `no-new-privileges`; its port is published
on `127.0.0.1` only.

Live capture in a container needs `NET_RAW` added back; see [permissions.md](permissions.md).

## Supply chain and code checks

CI runs on every push and pull request:

| Check | What it catches |
| --- | --- |
| `cargo-deny` (`deny.toml`) | Rust dependencies with RustSec advisories (vulnerable, unmaintained, unsound or yanked), licenses outside the allow-list, crates from unknown registries or Git, wildcard versions |
| `npm audit --audit-level=high` | Dashboard dependencies with high or critical advisories |
| gitleaks (`.gitleaks.toml`, `.github/workflows/secrets.yml`) | Credentials or keys in new commits on every push and pull request, and in the whole Git history weekly. Synthetic fixtures and tests are allow-listed because they plant fake secrets on purpose |
| CodeQL (`.github/workflows/codeql.yml`) | Security issues in the dashboard's TypeScript and in the workflows; also weekly |
| `clippy -D warnings`, workspace lints | Rust mistakes. `unsafe` code is forbidden. `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!` and unchecked indexing are denied outside tests, so hostile input cannot crash the server through a forgotten shortcut |
| ESLint | Dashboard code, including a ban on `innerHTML`, `outerHTML` and `dangerouslySetInnerHTML` |
| Tests, property tests, end-to-end tests | Behaviour, including that no payload or secret marker reaches the database, logs or API responses |

`Cargo.lock` and `package-lock.json` are committed, and CI builds with `--locked` and `npm ci`.

Fuzz targets ([../fuzz/README.md](../fuzz/README.md)) cover:

- the pcap reader, packet decoder and application parsers;
- the flow and detection engines;
- the filter language;
- the API's checks of untrusted request input.

Run them before releases and after parser changes.

To run the supply-chain checks locally:

```sh
cargo install cargo-deny --locked
cargo deny check
(cd frontend && npm audit --audit-level=high)
```
