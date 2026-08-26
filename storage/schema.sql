CREATE TABLE IF NOT EXISTS raw_events (
    event_id            TEXT PRIMARY KEY,
    raw_text             TEXT NOT NULL,
    source_name          TEXT,
    source_format_hint   TEXT,
    ingested_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS normalized_events (
    normalized_id        TEXT PRIMARY KEY,
    raw_event_id          TEXT NOT NULL REFERENCES raw_events(event_id),
    timestamp             TEXT NOT NULL,
    src_ip                TEXT,
    dst_ip                TEXT,
    src_port              INTEGER,
    dst_port              INTEGER,
    action                 TEXT NOT NULL,
    protocol               TEXT NOT NULL,
    device_vendor          TEXT,
    severity                TEXT NOT NULL,
    source_format           TEXT NOT NULL,
    parser_confidence       TEXT NOT NULL,
    normalized_at            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_normalized_raw_event_id  ON normalized_events(raw_event_id);
CREATE INDEX IF NOT EXISTS idx_normalized_source_format  ON normalized_events(source_format);
CREATE INDEX IF NOT EXISTS idx_normalized_src_ip          ON normalized_events(src_ip);