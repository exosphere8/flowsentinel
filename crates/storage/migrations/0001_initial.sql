-- FlowSentinel initial schema: metadata-only persistence.
--
-- No column can hold packet payload bytes. Packet rows keep the decoded
-- header and application metadata produced by the decoder (as JSONB) plus a
-- few indexed columns for filtering and sorting. Packet times are Unix
-- nanoseconds (BIGINT), keeping the capture's full timestamp precision.

CREATE TABLE capture_sessions (
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    file_name             TEXT        NOT NULL CHECK (char_length(file_name) BETWEEN 1 AND 160),
    file_size_bytes       BIGINT      NOT NULL CHECK (file_size_bytes >= 0),
    sha256                TEXT        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    source                TEXT        NOT NULL CHECK (source IN ('upload')),
    completion_state      TEXT        NOT NULL,
    pcap_version          TEXT        NOT NULL,
    endianness            TEXT        NOT NULL,
    timestamp_resolution  TEXT        NOT NULL,
    link_type             INTEGER     NOT NULL,
    link_type_name        TEXT,
    snap_length           BIGINT      NOT NULL,
    packets_processed     BIGINT      NOT NULL CHECK (packets_processed >= 0),
    packets_stored        BIGINT      NOT NULL CHECK (packets_stored >= 0),
    captured_bytes_total  BIGINT      NOT NULL,
    original_bytes_total  BIGINT      NOT NULL,
    first_packet_ns       BIGINT,
    last_packet_ns        BIGINT,
    flows_total           BIGINT      NOT NULL,
    flows_stored          BIGINT      NOT NULL,
    capture_warnings      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    decode_summary        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    flow_summary          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ NOT NULL
);

CREATE INDEX capture_sessions_created_at ON capture_sessions (created_at);
CREATE INDEX capture_sessions_expires_at ON capture_sessions (expires_at);

CREATE TABLE packets (
    session_id      BIGINT   NOT NULL REFERENCES capture_sessions (id) ON DELETE CASCADE,
    packet_index    BIGINT   NOT NULL,
    ts_ns           BIGINT,
    captured_length INTEGER  NOT NULL,
    original_length INTEGER  NOT NULL,
    decode_status   TEXT     NOT NULL,
    top_protocol    TEXT,
    source          TEXT,
    destination     TEXT,
    src_ip          INET,
    dst_ip          INET,
    src_port        INTEGER,
    dst_port        INTEGER,
    ip_protocol     SMALLINT,
    tcp_flags       INTEGER,
    flow_id         BIGINT,
    -- Every decoded layer, lowercase (ethernet, ipv4, tcp, dns, ...).
    protocols       TEXT[]   NOT NULL DEFAULT '{}',
    dns_query       TEXT,
    http_host       TEXT,
    tls_sni         TEXT,
    info            TEXT     NOT NULL,
    layers          JSONB    NOT NULL,
    warnings        JSONB    NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (session_id, packet_index)
);

CREATE INDEX packets_session_ts ON packets (session_id, ts_ns);
CREATE INDEX packets_session_flow ON packets (session_id, flow_id);

CREATE TABLE flows (
    session_id            BIGINT  NOT NULL REFERENCES capture_sessions (id) ON DELETE CASCADE,
    flow_id               BIGINT  NOT NULL,
    ip_version            SMALLINT NOT NULL,
    protocol              SMALLINT NOT NULL,
    protocol_name         TEXT,
    initiator_ip          INET    NOT NULL,
    initiator_port        INTEGER NOT NULL,
    responder_ip          INET    NOT NULL,
    responder_port        INTEGER NOT NULL,
    first_seen_ns         BIGINT,
    last_seen_ns          BIGINT,
    duration_seconds      DOUBLE PRECISION NOT NULL,
    packets_total         BIGINT  NOT NULL,
    bytes_total           BIGINT  NOT NULL,
    packets_initiator     BIGINT  NOT NULL,
    packets_responder     BIGINT  NOT NULL,
    bytes_initiator       BIGINT  NOT NULL,
    bytes_responder       BIGINT  NOT NULL,
    tcp_state             TEXT,
    end_reason            TEXT    NOT NULL,
    dominant_endpoint     TEXT    NOT NULL,
    -- Application protocols seen in the flow, lowercase (dns, http, ...).
    application_protocols TEXT[]  NOT NULL DEFAULT '{}',
    dns_query             TEXT,
    http_host             TEXT,
    tls_sni               TEXT,
    record                JSONB   NOT NULL,
    PRIMARY KEY (session_id, flow_id)
);

CREATE INDEX flows_session_bytes ON flows (session_id, bytes_total DESC);

CREATE TABLE dns_events (
    session_id     BIGINT  NOT NULL REFERENCES capture_sessions (id) ON DELETE CASCADE,
    packet_index   BIGINT  NOT NULL,
    ts_ns          BIGINT,
    flow_id        BIGINT,
    transaction_id INTEGER NOT NULL,
    is_response    BOOLEAN NOT NULL,
    query_name     TEXT,
    query_type     TEXT,
    response_code  TEXT,
    answer_count   INTEGER NOT NULL,
    answers        JSONB   NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (session_id, packet_index)
);

CREATE TABLE http_events (
    session_id       BIGINT  NOT NULL REFERENCES capture_sessions (id) ON DELETE CASCADE,
    packet_index     BIGINT  NOT NULL,
    ts_ns            BIGINT,
    flow_id          BIGINT,
    kind             TEXT    NOT NULL CHECK (kind IN ('request', 'response')),
    method           TEXT,
    host             TEXT,
    path             TEXT,
    status_code      INTEGER,
    content_type     TEXT,
    redacted         BOOLEAN NOT NULL,
    PRIMARY KEY (session_id, packet_index)
);

CREATE TABLE tls_events (
    session_id         BIGINT  NOT NULL REFERENCES capture_sessions (id) ON DELETE CASCADE,
    packet_index       BIGINT  NOT NULL,
    ts_ns              BIGINT,
    flow_id            BIGINT,
    handshake_type     TEXT    NOT NULL,
    server_name        TEXT,
    alpn               TEXT[]  NOT NULL DEFAULT '{}',
    negotiated_version TEXT,
    cipher_suite_count INTEGER NOT NULL,
    PRIMARY KEY (session_id, packet_index)
);

-- Exactly one row: how long imported sessions are kept and how many packets
-- of each are stored.
CREATE TABLE retention_settings (
    id                 SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    session_ttl_days   INTEGER     NOT NULL DEFAULT 30 CHECK (session_ttl_days BETWEEN 1 AND 3650),
    max_packets_stored BIGINT      NOT NULL DEFAULT 100000 CHECK (max_packets_stored BETWEEN 0 AND 1000000),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO retention_settings (id) VALUES (1);
