# Accounts, roles and the audit log

Every API endpoint except `POST /api/v1/auth/login` and `GET /health` needs a signed-in session,
and every change is recorded in a security audit log. This document covers how to create the
first account, what each role may do, how sessions and CSRF protection work, the sign-in limits,
and what the audit log records.

## The first admin

A new installation has no accounts, so nobody can sign in. The server logs a warning at startup
until an account exists. Create the first admin in one of two ways.

**From a password file at startup.** This suits containers.

```bash
printf '%s\n' 'a long passphrase of your own' > admin-password   # keep it private: chmod 600
FLOWSENTINEL_ADMIN_PASSWORD_FILE=admin-password FLOWSENTINEL_ADMIN_USERNAME=admin make dev
```

- The file is used only while the database has no accounts. Once one exists, the file is not
  read at all and can be deleted.
- One trailing line ending is removed. The password must meet the [password rules](#passwords).
- If the file cannot be read or the password is too weak, the server refuses to start.

**From the command line.** This works at any time, for example to recover when every admin has
lost their password:

```bash
read -rs PW && printf '%s\n' "$PW" | cargo run -p api-server -- create-user --username admin --role admin
# with Docker Compose:
read -rs PW && printf '%s\n' "$PW" | docker compose --profile app exec -T app \
  flowsentinel-api create-user --username admin --role admin
```

- `create-user` reads the password from standard input (the first line) and needs
  `FLOWSENTINEL_DATABASE_URL`.
- It exits with 0 on success, 1 on an error (a taken username, a weak password, an unreachable
  database) and 2 on wrong arguments.
- Passwords are never accepted as command-line arguments, because those show up in process
  listings and shell history.

Further accounts are created by an admin on the dashboard's **Users** page or with
`POST /api/v1/users`.

## Roles

| Action | viewer | analyst | admin |
| --- | :-: | :-: | :-: |
| Read captures, packets, flows, DNS/HTTP/TLS events, alerts, rules, the overview, filter fields and retention settings | ✓ | ✓ | ✓ |
| Sign out; see and change your own password | ✓ | ✓ | ✓ |
| Import captures | | ✓ | ✓ |
| Change an alert's triage status | | ✓ | ✓ |
| Delete captures | | | ✓ |
| Change retention settings | | | ✓ |
| Create, change, disable and delete accounts | | | ✓ |
| Read the audit log | | | ✓ |

- Each role includes everything the roles before it may do.
- A request outside its role is refused with `403 forbidden` and audited as `access.denied`.
- The dashboard hides controls a role cannot use, but the server makes the decision.
- There must always be at least one enabled admin. Demoting, disabling or deleting the last one is
  refused with `409 last_admin`.
- Admins cannot delete their own account (`400 cannot_delete_self`).

## Sessions

Signing in (`POST /api/v1/auth/login` with `{"username": ..., "password": ...}`) returns the
account, a CSRF token and the session's expiry. It also sets a cookie:

```
Set-Cookie: flowsentinel_session=<64 hex digits>; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200
```

The session token:

- It is 256 bits from the operating system's random number generator.
- Only its SHA-256 digest is stored, so a copy of the database cannot be used to sign in.
- `HttpOnly` keeps it away from page scripts, and `SameSite=Strict` keeps browsers from sending it
  with requests started by other sites.
- Each sign-in issues a new token. A token sent by a client is never adopted, which prevents
  session fixation.

A session ends:

- after `FLOWSENTINEL_SESSION_IDLE_MINUTES` (default 30) without a request (use is recorded at
  most once a minute, so a session may end up to a minute sooner);
- `FLOWSENTINEL_SESSION_MAX_HOURS` (default 12) after sign-in, however active it is;
- on sign-out (`POST /api/v1/auth/logout`);
- when the account's role, enabled state or password changes. All of the account's sessions end.
- when the account signs in an 11th time: at most 10 sessions are kept per account, and the
  oldest one ends.

A request with an ended session gets `401 unauthenticated`, and the response clears the cookie.
Ended sessions are deleted from the database every hour.

### Secure cookies and HTTPS

The server speaks plain HTTP. To serve it beyond the local machine, put it behind a reverse proxy
that terminates HTTPS, and set:

- `FLOWSENTINEL_SECURE_COOKIES=true`. The cookie is then marked `Secure` and named
  `__Host-flowsentinel_session`. Browsers accept that name only for a `Secure`, host-only cookie
  for `/`, so a neighbouring subdomain cannot plant one.
- `FLOWSENTINEL_ALLOWED_HOSTS` to the name the proxy is reached by. The proxy must pass the
  original `Host` header (see [api.md](api.md#host-names)).

When the server listens on a non-loopback address without secure cookies, it logs a warning. It
never needs to run as root (see [SECURITY.md](../SECURITY.md)).

## CSRF protection

State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) must send the session's CSRF token in an
`X-CSRF-Token` header.

- The token comes from sign-in and from `GET /api/v1/auth/session`.
- It is a SHA-256 digest of the session token with a fixed context string. It needs no storage
  and cannot be computed without the cookie.
- A missing or wrong token gets `403 csrf_token_invalid`, which is audited.

Three more layers apply:

- The `SameSite=Strict` cookie.
- A same-origin check on every state-changing request, sign-in included. A request whose `Origin`
  does not match its `Host`, or that the browser marks `Sec-Fetch-Site: cross-site` or
  `same-site`, gets `403 cross_site_request`.
- Request bodies that need a CORS preflight, which the API never grants: JSON, and uploads as
  `application/vnd.tcpdump.pcap` or `application/octet-stream`.

Clients such as `curl` send neither header. They need the cookie and the CSRF token like the
dashboard does:

```bash
curl -c cookies -H 'Content-Type: application/json' \
  -d '{"username":"ana","password":"..."}' http://127.0.0.1:8080/api/v1/auth/login
# take csrf_token from the response, then:
curl -b cookies -H "X-CSRF-Token: $CSRF" -X POST -H 'Content-Type: application/vnd.tcpdump.pcap' \
  --data-binary @fixtures/pcap/flows-mixed.pcap \
  'http://127.0.0.1:8080/api/v1/captures?file_name=flows-mixed.pcap'
```

## Passwords

- New passwords need 12 to 256 characters and must not equal the username or, for usernames of
  4 or more characters, contain it.
- A password of one repeated character is refused.
- Any characters are allowed and there are no composition rules, following NIST SP 800-63B.
- Passwords are hashed with Argon2id (version 19, 19 MiB of memory, 2 passes, 1 lane, a random
  16-byte salt). That is the OWASP minimum recommendation.
- At most 4 hashes are computed at once, so concurrent sign-ins cannot exhaust memory. Requests
  that wait longer than 10 seconds for one get `503 server_busy`.
- At sign-in, passwords longer than 1 KiB are refused without hashing.
- Changing your own password (`PUT /api/v1/auth/password`) needs the current one. It ends every
  session of the account and starts a new one for the client that made the change.
- An admin can set another account's password with `PATCH /api/v1/users/{id}`.

Usernames have 1 to 64 characters: ASCII letters, digits, `.`, `_` and `-`, starting with a letter
or digit. They are stored lowercase, and sign-in ignores case.

## Sign-in limits

Password checks are counted in memory per username and per client address. Each check is
reserved before the password is verified, so requests sent in parallel cannot slip past the
limit; a check whose password was right is given back, so successful sign-ins never lock an
address.

| Key | Limit | Lockout |
| --- | --- | --- |
| Username | 5 failed checks in 15 minutes | Until the oldest of them is 15 minutes old |
| Client address | 20 failed checks in 15 minutes | Likewise |

- While locked, sign-in (even with the right password) and password changes get
  `429 too_many_attempts` with a `Retry-After` header in seconds.
- A successful sign-in clears the username's count, but not the address's.
- Wrong passwords, unknown usernames and disabled accounts all get the same
  `401 invalid_credentials`. An unknown username still costs one Argon2id check, so response
  times do not reveal which usernames exist.

Limits of this design:

- The counts reset when the server restarts, and they are not shared between replicas.
- The table holds at most 10,000 usernames and addresses. When it is full, entries whose failures
  have expired are dropped first, then the least recently failed.
- Behind a reverse proxy every client has the proxy's address. The per-address limit then applies
  to everyone together, while the per-username limit still works.

## The audit log

Every event records:

- the time;
- the account (or, for a failed sign-in, the username tried);
- the action and its outcome (`success`, `failure` or `denied`);
- the target (for example `capture 7`);
- the client address;
- a small JSON object of details.

Events go to the `audit_events` table, and as JSON log lines with target `audit` to the server
log. If an event cannot be stored, the log line is still written and an error is logged; the
request is not undone.

| Action | Recorded when | Details |
| --- | --- | --- |
| `auth.login` | Every sign-in attempt; while locked, only the first refusal | `role` on success; `reason` on failure: `wrong_password`, `unknown_user`, `account_disabled`, `rate_limited` |
| `auth.logout` | Sign-out | |
| `auth.password_change` | A user changes their own password | `reason` on failure |
| `access.denied` | A request refused for its role, or for a missing or wrong CSRF token | `reason`, `method`, `path`, `role`, `required` |
| `user.bootstrap` | The first admin is created from the password file | `username`, `role` |
| `user.create`, `user.update`, `user.delete` | Account changes (also by `create-user`, as actor `(command line)`) | `username`, `role`, `disabled`, `password_reset` |
| `capture.import` | Every import, successful or not | `file_name`, `sha256`, `packets`, `alerts`; `code` on failure |
| `capture.delete` | A capture is deleted | |
| `alert.status_change` | Triage | `status`, `rule_id` |
| `settings.retention_change` | Retention settings change | the new values |

What the audit log never holds:

- passwords;
- session tokens or CSRF tokens;
- request bodies or packet data.

Requests refused for having no session are not audited: they carry no account, and recording
them would let anyone fill the log. For the same reason a locked-out username or address records
only its first refused attempt per lockout. Admins read the log on the dashboard's **Audit log** page or
with `GET /api/v1/audit` (filters: `action`, `outcome`, `actor`; newest first).

How long events are kept:

- Events older than `FLOWSENTINEL_AUDIT_RETENTION_DAYS` (default 365) are deleted every hour.
- The API has no way to change or delete events.
- Anyone with write access to the database can; if you need tamper evidence, forward the `audit`
  log lines to a separate system.

Client addresses and usernames are personal data in many jurisdictions. Set the retention to what
your policy requires.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `FLOWSENTINEL_SESSION_IDLE_MINUTES` | 30 | Minutes without a request before a session ends (1–1440) |
| `FLOWSENTINEL_SESSION_MAX_HOURS` | 12 | Hours after sign-in before a session ends (1–720) |
| `FLOWSENTINEL_SECURE_COOKIES` | `false` | `true` behind HTTPS: `Secure` cookie named `__Host-flowsentinel_session` |
| `FLOWSENTINEL_AUDIT_RETENTION_DAYS` | 365 | Days audit events are kept (1–3650) |
| `FLOWSENTINEL_ADMIN_USERNAME` | `admin` | Username of the first admin created from the password file |
| `FLOWSENTINEL_ADMIN_PASSWORD_FILE` | not set | File with the first admin's password; used only while no account exists |

## Endpoints

| Method and path | Role | Purpose |
| --- | --- | --- |
| `POST /auth/login` | none | Sign in; sets the cookie, returns the CSRF token |
| `GET /auth/session` | any | The signed-in account and its CSRF token |
| `POST /auth/logout` | any | Sign out |
| `PUT /auth/password` | any | Change your own password: `{"current_password", "new_password"}` |
| `GET /users` | admin | Accounts, by username (paged) |
| `POST /users` | admin | Create: `{"username", "password", "role"}` |
| `PATCH /users/{id}` | admin | Change `role`, `disabled` or `password` |
| `DELETE /users/{id}` | admin | Delete an account |
| `GET /audit` | admin | Audit events, newest first; `action`, `outcome`, `actor`, `page`, `per_page` |

All paths are under `/api/v1`. Errors use the usual JSON shape (see [api.md](api.md#errors)).

## Tests

- `crates/api-server/tests/auth.rs` covers, against a real PostgreSQL:
  - sign-in, sign-out and cookie attributes, and that tokens are stored only as digests;
  - identical answers for wrong, unknown and disabled accounts;
  - the lockout and `Retry-After`;
  - CSRF and same-origin refusals;
  - every role against every protected action;
  - idle, absolute and per-account session limits;
  - password changes ending other sessions;
  - account management and the last-admin rule;
  - first-admin creation;
  - the audit events of all of these, and that no password reaches the log.
- Unit tests cover:
  - token parsing and the CSRF derivation;
  - cookies;
  - username and password rules;
  - Argon2id hashing;
  - the sign-in limiter;
  - role ordering.
- The dashboard's tests cover:
  - sign-in and returning to the requested page;
  - signing out when a session ends;
  - CSRF headers;
  - what each role sees;
  - the Users, Audit log and Account pages.
- The end-to-end test signs in as the first admin, creates a viewer, reads the audit log, and
  checks that the viewer can neither see nor use admin features.
