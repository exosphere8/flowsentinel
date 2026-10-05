# Installation

FlowSentinel needs PostgreSQL 16 or later. You can run a release in two ways:

- **The container image** (Docker Compose), the simplest way;
- **prebuilt binaries** for Linux, macOS and Windows.

To build from source instead, see the [README](../README.md#quick-start).

> Use FlowSentinel only on captures and networks you own or are authorized to inspect. Before
> exposing it beyond your own machine, go through the [deployment checklist](hardening.md).

## Container image (Docker Compose)

Images are published to `ghcr.io/exosphere8/flowsentinel`, tagged with the version (`0.1.0`)
and the minor series (`0.1`). The image includes the dashboard, live-capture support (off unless
enabled) and OpenTelemetry export (off unless configured).

```sh
git clone --branch v0.1.0 https://github.com/exosphere8/flowsentinel.git
cd flowsentinel
cp .env.example .env    # then set POSTGRES_PASSWORD to a strong, unique value
echo 'FLOWSENTINEL_IMAGE=ghcr.io/exosphere8/flowsentinel:0.1.0' >> .env
docker compose --profile app pull app
docker compose --profile app up -d --no-build --wait
```

Then create the first admin; the command reads the password from standard input:

```sh
read -rs PW && printf '%s\n' "$PW" | docker compose --profile app exec -T app \
  flowsentinel-api create-user --username admin --role admin
```

Open <http://127.0.0.1:8080> and sign in. The server is published on `127.0.0.1` only. To reach
it from other machines, put an HTTPS reverse proxy in front and set `FLOWSENTINEL_SECURE_COOKIES`
and `FLOWSENTINEL_ALLOWED_HOSTS` in `.env` ([hardening.md](hardening.md)).

To verify the image's provenance before running it, use the GitHub CLI:

```sh
gh attestation verify oci://ghcr.io/exosphere8/flowsentinel:0.1.0 --repo exosphere8/flowsentinel
```

## Prebuilt binaries

Each [release](https://github.com/exosphere8/flowsentinel/releases) has an archive per platform:

| Platform | Archive |
| --- | --- |
| Linux x86-64 (glibc 2.35 or later) | `flowsentinel-0.1.0-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 (glibc 2.35 or later) | `flowsentinel-0.1.0-aarch64-unknown-linux-gnu.tar.gz` |
| macOS, Apple silicon | `flowsentinel-0.1.0-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `flowsentinel-0.1.0-x86_64-apple-darwin.tar.gz` |
| Windows x86-64 | `flowsentinel-0.1.0-x86_64-pc-windows-msvc.zip` |

Each archive contains:

- `flowsentinel`, the command-line analyzer;
- `flowsentinel-api`, the API server;
- `dashboard/`, the built web dashboard;
- `docs/`;
- `config/detection.example.toml`;
- `.env.example`;
- the license, README, changelog and security policy.

The binaries do not include live capture, which needs libpcap at run time. Use the container
image, or build with `--features live-capture` ([live-capture.md](live-capture.md)).

Verify the download:

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify flowsentinel-0.1.0-x86_64-unknown-linux-gnu.tar.gz --repo exosphere8/flowsentinel
```

### Command-line analyzer

The CLI needs no database:

```sh
tar -xzf flowsentinel-0.1.0-x86_64-unknown-linux-gnu.tar.gz
cd flowsentinel-0.1.0-x86_64-unknown-linux-gnu
./flowsentinel inspect --pcap capture.pcap --decode
./flowsentinel flows --pcap capture.pcap
./flowsentinel detect --pcap capture.pcap
```

### API server and dashboard

1. **Have a PostgreSQL database and account ready.** The account needs no superuser rights; the
   server creates its tables on start. Any PostgreSQL 16 or later works, including the one in
   this repository's Compose file (`docker compose up -d --wait`).
2. **Configure and start the server** from the extracted directory:

   ```sh
   export FLOWSENTINEL_DATABASE_URL='postgres://flowsentinel:PASSWORD@127.0.0.1:5432/flowsentinel'
   export FLOWSENTINEL_DASHBOARD_DIR=./dashboard
   export FLOWSENTINEL_UPLOAD_DIR=/var/lib/flowsentinel/uploads   # owned by this user, mode 700
   ./flowsentinel-api
   ```

   For a database on another host, add `?sslmode=verify-full`
   ([hardening.md](hardening.md#database)).
3. **Create the first admin.** In another terminal, with the same `FLOWSENTINEL_DATABASE_URL`,
   pipe the password in. Typed input would be visible on screen.

   ```sh
   read -rs PW && printf '%s\n' "$PW" | ./flowsentinel-api create-user --username admin --role admin
   ```

   Alternatively, point `FLOWSENTINEL_ADMIN_PASSWORD_FILE` at a file holding the password before
   the first start, then delete the file ([authentication.md](authentication.md)).
4. **Sign in** at <http://127.0.0.1:8080>.

All settings are environment variables, listed in the [README](../README.md#configuration) and
`.env.example`. `./flowsentinel-api --help` lists the commands.

On Windows, use `flowsentinel-api.exe`, and set variables with `$env:NAME = "value"` in
PowerShell.

To run the server as a service, use your platform's service manager (systemd, launchd or a
Windows service wrapper). Run it as a dedicated, unprivileged user, and keep its environment in
a file only that user can read.

## Upgrading

1. Read the [changelog](../CHANGELOG.md) for the new version. Before 1.0.0, minor versions may
   change the API or configuration.
2. Back up the database (`pg_dump`).
3. Replace the binaries or image, and start the server. It applies database migrations on start.

You cannot roll back past a migration without restoring the backup.

## Uninstalling

- **Compose:** `docker compose --profile app down -v` stops the services and deletes their
  volumes, including the database.
- **Binaries:** delete the extracted directory, the upload directory and the database.
