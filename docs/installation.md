# Installation

FlowSentinel needs PostgreSQL 16 or later. You can run a release in two ways:

- **The container image** (Docker Compose), the simplest way;
- **prebuilt binaries** for Linux, macOS and Windows.

To build from source instead, see the [README](../README.md#quick-start).

> Use FlowSentinel only on captures and networks you own or are authorized to inspect. Before
> exposing it beyond your own machine, go through the [deployment checklist](hardening.md).

## Container image (Docker Compose)

Images are published to `ghcr.io/exosphere8/flowsentinel` for `linux/amd64` and `linux/arm64`,
so they run on Intel and ARM machines, including Docker Desktop on Apple silicon. Each image is
tagged with its version (`0.1.0`) and minor series (`0.1`); there is no `latest` tag. The image
includes:

- the dashboard;
- live-capture support, off unless enabled;
- OpenTelemetry export, off unless configured.

The license notices of the third-party code it contains are at
`/usr/share/doc/flowsentinel/THIRD_PARTY_LICENSES.md`.

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

The `app` service passes only the settings listed in `docker-compose.yml` to the server. To set
others, add them in a `docker-compose.override.yml` next to it, which Compose reads
automatically. Examples are OpenTelemetry (`OTEL_EXPORTER_OTLP_ENDPOINT`) and Prometheus metrics
(`FLOWSENTINEL_METRICS_ADDR`):

```yaml
services:
  app:
    environment:
      OTEL_EXPORTER_OTLP_ENDPOINT: https://otel-collector.example.internal:4318
```

Live capture also needs a capability for the container; see [permissions.md](permissions.md).

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
- the license, the third-party license notices (`THIRD_PARTY_LICENSES.md`), the README, the
  changelog and the security policy.

The binaries do not include live capture, which needs libpcap at run time. Use the container
image, or build with `--features live-capture` ([live-capture.md](live-capture.md)).

### Verifying a download

Check the archive against `SHA256SUMS` from the same release:

| System | Command |
| --- | --- |
| Linux | `sha256sum -c SHA256SUMS --ignore-missing` |
| macOS | `grep aarch64-apple-darwin SHA256SUMS \| shasum -a 256 -c` (or `x86_64-apple-darwin`) |
| Windows (PowerShell) | `Get-FileHash flowsentinel-0.1.0-x86_64-pc-windows-msvc.zip`, then compare the hash with its line in `SHA256SUMS` |

To check its build provenance, use the GitHub CLI:

```sh
gh attestation verify flowsentinel-0.1.0-x86_64-unknown-linux-gnu.tar.gz --repo exosphere8/flowsentinel
```

The macOS binaries are not signed or notarized. If you downloaded the archive with a browser,
macOS refuses to run them. Remove the download's quarantine flag after checking the archive:

```sh
xattr -dr com.apple.quarantine flowsentinel-0.1.0-aarch64-apple-darwin
```

Downloads made with `curl` or `gh release download` are not quarantined.

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

1. **Have a PostgreSQL database ready, owned by the server's account.** The server creates its
   tables on start, so the account must own the database (or have `CREATE` on its `public`
   schema). It needs no superuser rights. For example, as a PostgreSQL superuser:

   ```sql
   CREATE ROLE flowsentinel LOGIN PASSWORD 'a strong, unique password';
   CREATE DATABASE flowsentinel OWNER flowsentinel;
   ```

   Or run one in Docker, which creates both:

   ```sh
   docker run -d --name flowsentinel-db --restart unless-stopped \
     -e POSTGRES_USER=flowsentinel -e POSTGRES_PASSWORD='a strong, unique password' \
     -e POSTGRES_DB=flowsentinel -p 127.0.0.1:5432:5432 \
     -v flowsentinel-db:/var/lib/postgresql/data postgres:16-alpine
   ```

2. **Configure and start the server** from the extracted directory:

   ```sh
   mkdir -m 700 -p "$HOME/.local/share/flowsentinel/uploads"
   export FLOWSENTINEL_DATABASE_URL='postgres://flowsentinel:PASSWORD@127.0.0.1:5432/flowsentinel'
   export FLOWSENTINEL_DASHBOARD_DIR=./dashboard
   export FLOWSENTINEL_UPLOAD_DIR="$HOME/.local/share/flowsentinel/uploads"
   ./flowsentinel-api
   ```

   The upload directory holds uploads while they are analyzed. It must exist and be writable by
   the server only. Without `FLOWSENTINEL_UPLOAD_DIR`, the system's temporary directory is used.
   For a database on another host, add `?sslmode=verify-full` to the URL
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
3. Install the new version. The server applies database migrations on start.
   - **Compose:** check out the new tag (`git fetch --tags && git checkout vX.Y.Z`), set
     `FLOWSENTINEL_IMAGE` in `.env` to the new version, then run
     `docker compose --profile app pull app` and
     `docker compose --profile app up -d --no-build --wait`.
   - **Binaries:** stop the server, replace the extracted directory with the new one, and start it
     again with the same settings.

You cannot roll back past a migration without restoring the backup.

## Uninstalling

- **Compose:** `docker compose --profile app down -v` stops the services and deletes their
  volumes, including the database.
- **Binaries:** delete the extracted directory, the upload directory and the database.
