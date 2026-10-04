-- Accounts, sign-in sessions and the security audit log.
--
-- Passwords are stored only as Argon2id PHC strings. Session tokens are
-- stored only as SHA-256 digests, so a copy of this table cannot be used to
-- sign in. Audit events never hold passwords, tokens or packet data.

CREATE TABLE users (
    id                  BIGSERIAL   PRIMARY KEY,
    username            TEXT        NOT NULL
                        CHECK (username ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    password_hash       TEXT        NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    role                TEXT        NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    disabled            BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at       TIMESTAMPTZ
);

CREATE UNIQUE INDEX users_username ON users (username);

CREATE TABLE auth_sessions (
    id           BIGSERIAL   PRIMARY KEY,
    token_sha256 BYTEA       NOT NULL CHECK (octet_length(token_sha256) = 32),
    user_id      BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX auth_sessions_token ON auth_sessions (token_sha256);
CREATE INDEX auth_sessions_user ON auth_sessions (user_id, created_at);
CREATE INDEX auth_sessions_expiry ON auth_sessions (expires_at);

-- Append-only from the application: there is no update path, and rows are
-- deleted only by the audit retention purge. actor_id has no foreign key so
-- events outlive the accounts they mention.
CREATE TABLE audit_events (
    id          BIGSERIAL   PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id    BIGINT,
    actor       TEXT        CHECK (char_length(actor) <= 64),
    action      TEXT        NOT NULL CHECK (action ~ '^[a-z_]+\.[a-z_]+$'),
    outcome     TEXT        NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    target_type TEXT        CHECK (char_length(target_type) <= 32),
    target_id   TEXT        CHECK (char_length(target_id) <= 64),
    client_ip   INET,
    details     JSONB       NOT NULL DEFAULT '{}'::jsonb
                CHECK (jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 4096)
);

CREATE INDEX audit_events_recent ON audit_events (at DESC, id DESC);
CREATE INDEX audit_events_action ON audit_events (action, id DESC);
