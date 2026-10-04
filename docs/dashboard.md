# Dashboard

The dashboard is a React and TypeScript single-page application in `frontend/`. It reads the
metadata API described in [api.md](api.md) and shows captures, packets, flows and alerts.
It shows **metadata only**: the API has no payload fields, and the dashboard also refuses to
render any field named like packet contents (see [Privacy](#privacy)).

Everyone signs in first (`/login`), and each page shows only what the account's role may do:
viewers read, analysts also import captures and triage alerts, and admins also delete captures,
change settings, manage accounts and read the audit log. The server enforces the same rules. See
[authentication.md](authentication.md).

## Pages

| Path | Page |
| --- | --- |
| `/login` | Sign in; afterwards the page that was asked for opens |
| `/` | Overview: totals, alerts by severity and status, open alerts, recent imports |
| `/captures` | Import a capture (upload a `.pcap` file), and list, sort and delete imported captures |
| `/captures/{id}` | One capture: file facts, completion state, limits reached, warnings, and charts of protocols, decode status, why flows ended and alerts by rule |
| `/captures/{id}/packets` | Packet table with a display filter, sorting and paging; `?flow_id=` lists one flow's packets |
| `/captures/{id}/packets/{index}` | One packet: summary, decode warnings and its decoded protocol layers |
| `/captures/{id}/flows` | Flow table with a display filter (for example `alert.severity == high`), sorting and paging |
| `/captures/{id}/flows/{flow_id}` | One flow: endpoints, per-direction statistics, TCP state, application metadata, and the alerts that cite it |
| `/captures/{id}/alerts` | Alerts, filtered by severity, status and rule |
| `/captures/{id}/alerts/{alert_id}` | One alert: what was observed, why it may be wrong, likely false positives, cited flows and packets, and triage |
| `/settings` | Retention settings (changed by admins), the detection rule catalog, and the display-filter field reference |
| `/account` | Your account and session, and changing your password |
| `/users` | Admins: create accounts, change roles, disable, set passwords, delete |
| `/audit` | Admins: the audit log, filtered by action and outcome |

Every alert page says that **alerts are heuristic indicators to review, not proof of
compromise**. Each alert shows its rule's uncertainty and likely benign causes next to its
evidence.

Filters, sort orders and page numbers are kept in the URL, so a view can be bookmarked or
shared and the browser's Back button restores it.

## How it works

- **Server-side paging, sorting and filtering.** Tables request one page at a time
  (`page`, `per_page`, `sort`, `filter`), so the browser holds one page however large the capture
  is. A page number past the end (for example after deleting the last item on the last page)
  offers a link to the last page instead of an empty table.
- **Validated filters.** As a display filter is typed, the dashboard asks
  `GET /api/v1/filters/validate` whether it is valid (after a 300 ms pause). An invalid filter
  is marked with `aria-invalid`, its error and the position it points to are shown, and **Apply**
  is disabled. Only filters that the server accepted are applied.
- **Typed client.** `src/api/schema.ts` is generated from [openapi.json](openapi.json) by
  `scripts/gen-api-types.mjs`, and `src/api/client.ts` uses those types for every call. CI fails
  if the generated file is out of date (`npm run check:api`), and a Rust test fails if
  `docs/openapi.json` no longer matches the server (`crates/api-server/tests/openapi.rs`).
- **Loading, error and empty states.** Every request shows a loading message, a structured error
  (with the API's error code) and a retry button, or a message saying there is nothing to show.
  Requests for a page are cancelled when the user navigates away.
- **Charts.** Bar charts are plain SVG with no chart library. They are hidden from assistive
  technology, and the same numbers are in a table beside each chart.

## Running

### With Docker Compose

The `app` profile builds the API server and the dashboard into one image, and serves it on
`http://127.0.0.1:8080`:

```bash
cp .env.example .env      # replace each "change-me" (see the README quick start)
docker compose --profile app up -d --build --wait
```

The container runs as an unprivileged user (UID 10001) with a read-only root file system, no
Linux capabilities and `no-new-privileges`. Only the upload volume is writable. The port is
published on `127.0.0.1` only; change `FLOWSENTINEL_PORT` in `.env` to use another port. Stop it
with `docker compose --profile app down`.

### From source

Requirements: Node.js 22.22 or later and npm, plus the requirements in the README.

```bash
cd frontend
npm ci
npm run build             # type-checks and writes frontend/dist
cd ..
FLOWSENTINEL_DASHBOARD_DIR=frontend/dist make dev
```

`make dashboard` runs the same `npm ci` and build. When `FLOWSENTINEL_DASHBOARD_DIR` is set,
`api-server` serves the files in it at `/`, and answers paths without a file with `index.html`
so that the dashboard's own routes load directly. It refuses to start if the directory has no
`index.html`. Paths under `/api/` that the API does not know still get its JSON `404`, never the
dashboard. `index.html` is sent with `Cache-Control: no-cache`, so a new build takes effect on the
next load; the content-hashed files under `/assets/` are cached for a year, and a missing one is
a `404` rather than the page.
Without the variable, the server serves only the API.

### Development server

```bash
make dev                  # the API on 127.0.0.1:8080, in one terminal
cd frontend && npm run dev  # the dashboard on http://127.0.0.1:5173, in another
```

The Vite development server reloads on every change and forwards `/api` and `/health` to
`FLOWSENTINEL_API_URL` (default `http://127.0.0.1:8080`).

## Security

`api-server` sends these headers on every response, API and dashboard alike:

| Header | Value |
| --- | --- |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Cross-Origin-Opener-Policy` | `same-origin` |

The policy allows no inline scripts or styles and no third-party origins; the build loads no
fonts, scripts or images from the internet. The end-to-end test fails on any CSP violation.

The dashboard never builds HTML from strings. It uses no `dangerouslySetInnerHTML`, `innerHTML` or
`outerHTML`; ESLint rejects them. Everything the API returns, including file names, DNS names,
HTTP paths and TLS server names from a capture, is rendered as text by React, so a crafted
capture cannot inject markup.

The `Host` checks of [api.md](api.md#host-names) apply to the dashboard too. Reach it through a
name in `FLOWSENTINEL_ALLOWED_HOSTS` when it is not on `localhost`.

## Privacy

The API stores and returns no packet payloads (see [data-retention.md](data-retention.md)). The
dashboard adds a second guard: the protocol-layer view never renders fields named `payload`,
`data`, `raw`, `bytes`, `hex`, `body`, `content` or `contents`, so a later API change cannot put
packet contents on screen by accident. Payload sizes are shown as lengths only. The unit tests
check this guard. The end-to-end test opens a DNS packet (which has a payload), a flow and an
alert, and checks that no payload marker from the synthetic fixtures appears on them.

## Accessibility

- Every loaded page has one `h1`, a "Skip to content" link and landmark regions, and the document title
  names the page.
- Data tables sit in a labelled region that scrolls on narrow screens, or are labelled by their
  section heading; chart tables have captions.
- Status changes (filter validity, saved triage) are announced through live regions; errors use
  `role="alert"`.
- Severity is shown as text as well as color.
- Keyboard focus is always visible; every control has a label.

The page tests run [axe-core](https://github.com/dequelabs/axe-core) on each page and fail on any
violation that axe can detect in jsdom. Automated checks do not catch everything, for example
color contrast is not measured in jsdom; manual review with a screen reader is still useful.

## Tests

| Command (in `frontend/`) | Checks |
| --- | --- |
| `npm run lint` | ESLint with TypeScript and React Hooks rules, no warnings allowed |
| `npm run typecheck` | `tsc` in strict mode with `noUncheckedIndexedAccess` |
| `npm test` | Vitest unit and page tests in jsdom against a mocked API: the API client, formatting, components, every page (with loading, error and empty states), filter validation, triage, the payload guard, and axe-core |
| `npm run check:api` | `src/api/schema.ts` matches `docs/openapi.json` |
| `npm run e2e` | Playwright smoke tests against a running server (below) |

The end-to-end smoke tests import `fixtures/pcap/detect-mixed.pcap` through the dashboard and
walk every page: the capture, packets with a valid and an invalid filter, a packet's protocol
tree, flows filtered by alert severity, a flow, the alert list, one alert and its triage,
settings, and the overview. They sign in as the first admin, create a viewer account, read the
audit log, sign out, and check as the viewer that admin pages and controls are absent and that
the API refuses them. They fail on console errors (other than expected `4xx` responses), uncaught
exceptions, CSP violations or any `5xx` response, and check the security headers. To run them
locally, start an API server that serves the built dashboard on port 18080 with an empty,
disposable database and a first admin:

```bash
cd frontend && npm ci && npm run build && npx playwright install chromium && cd ..
printf '%s\n' 'a throwaway e2e passphrase' > /tmp/e2e-admin-password
FLOWSENTINEL_DATABASE_URL=postgres://USER:PASSWORD@127.0.0.1:5432/flowsentinel_e2e \
  FLOWSENTINEL_API_ADDR=127.0.0.1:18080 FLOWSENTINEL_DASHBOARD_DIR=frontend/dist \
  FLOWSENTINEL_ADMIN_PASSWORD_FILE=/tmp/e2e-admin-password cargo run -p api-server &
cd frontend && E2E_ADMIN_PASSWORD='a throwaway e2e passphrase' npm run e2e
```

`E2E_BASE_URL` points the tests at another server. CI runs all of these in the `frontend` job
(Linux and Windows) and the `e2e` job, and the `compose` job builds the container image and checks
that it serves the dashboard with the CSP header as UID 10001.

## Limits

- The dashboard shows what the API stores: packets beyond the capture's `max_packets_stored` are
  counted but not listed.
- Tables show 25 (captures), 50 (flows, alerts) or 100 (packets) rows per page; the API allows
  at most 500.
- Nested protocol fields are shown up to 6 levels deep and 100 items per list.
- Hiding a control is a convenience, not the protection: the server checks every request's role
  and CSRF token.
