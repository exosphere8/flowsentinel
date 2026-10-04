-- Captures recorded live from a network interface are stored like uploads,
-- marked with their source.
ALTER TABLE capture_sessions DROP CONSTRAINT capture_sessions_source_check;
ALTER TABLE capture_sessions
    ADD CONSTRAINT capture_sessions_source_check CHECK (source IN ('upload', 'live'));
