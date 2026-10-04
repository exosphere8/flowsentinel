-- Alerts raised by the detection rules. Each is a heuristic indicator stored
-- with its evidence and explanation; analysts change only its status.

CREATE TABLE alerts (
    session_id             BIGINT   NOT NULL REFERENCES capture_sessions (id) ON DELETE CASCADE,
    alert_id               BIGINT   NOT NULL,
    rule_id                TEXT     NOT NULL,
    rule_name              TEXT     NOT NULL,
    severity               TEXT     NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    severity_rank          SMALLINT NOT NULL CHECK (severity_rank BETWEEN 1 AND 3),
    confidence             TEXT     NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    status                 TEXT     NOT NULL DEFAULT 'open'
                           CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
    first_seen_ns          BIGINT,
    last_seen_ns           BIGINT,
    source                 INET,
    destination            INET,
    destination_port       INTEGER,
    related_flow_ids       BIGINT[] NOT NULL DEFAULT '{}',
    related_packet_indexes BIGINT[] NOT NULL DEFAULT '{}',
    evidence               JSONB    NOT NULL,
    explanation            TEXT     NOT NULL,
    uncertainty            TEXT     NOT NULL,
    likely_false_positives TEXT[]   NOT NULL DEFAULT '{}',
    mitre_attack           TEXT[]   NOT NULL DEFAULT '{}',
    status_changed_at      TIMESTAMPTZ,
    PRIMARY KEY (session_id, alert_id)
);

CREATE INDEX alerts_session_severity ON alerts (session_id, severity_rank DESC, alert_id);

-- Per-flow alert facts, for filtering flows by their alerts.
ALTER TABLE flows
    ADD COLUMN alert_count        INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN max_alert_severity TEXT CHECK (max_alert_severity IN ('low', 'medium', 'high'));

ALTER TABLE capture_sessions
    ADD COLUMN alerts_total      BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN detection_summary JSONB  NOT NULL DEFAULT '{}'::jsonb;
