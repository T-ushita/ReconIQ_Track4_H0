-- ReconIQ — Aurora PostgreSQL schema

CREATE EXTENSION IF NOT EXISTS vector;

-- Scan sessions
CREATE TABLE IF NOT EXISTS scan_sessions (
    session_id         TEXT    PRIMARY KEY,
    target_url         TEXT    NOT NULL,
    status             TEXT    NOT NULL DEFAULT 'queued',
    created_at         TEXT,
    started_at         TEXT    DEFAULT '',
    completed_at       TEXT    DEFAULT '',
    crawl_result       TEXT    DEFAULT '{}',
    fuzz_result        TEXT    DEFAULT '{}',
    auth_result        TEXT    DEFAULT '{}',
    recon_result       TEXT    DEFAULT '{}',
    vuln_result        TEXT    DEFAULT '{}',
    triage_result      TEXT    DEFAULT '{}',
    report_md          TEXT    DEFAULT '',   -- stores S3 key: "reports/<uuid>.md"
    error_message      TEXT    DEFAULT '',
    duration_seconds   FLOAT   DEFAULT 0.0,
    injection_attempts TEXT    DEFAULT '[]',
    confidence_scores  TEXT    DEFAULT '{}',
    cross_references   TEXT    DEFAULT '',
    fuzzing_authorized BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_ss_status     ON scan_sessions(status);
CREATE INDEX IF NOT EXISTS idx_ss_target_url ON scan_sessions(target_url);
CREATE INDEX IF NOT EXISTS idx_ss_created_at ON scan_sessions(created_at DESC);

-- Monitored sites (continuous scanning)
CREATE TABLE IF NOT EXISTS monitored_sites (
    url          TEXT    PRIMARY KEY,
    schedule     TEXT    DEFAULT '7d',
    webhook_url  TEXT    DEFAULT '',
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    added_at     TEXT    NOT NULL,
    last_scan    TEXT,
    next_scan    TEXT,
    scan_history JSONB   DEFAULT '[]'::jsonb
);
