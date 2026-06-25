# FUTURE SCOPE: planned Postgres-compatible mirror of scan_session.py's schema —
# not imported by the live pipeline; the live app uses scan_session.py (SQLite).

import sqlite3
import json
import os
from contextlib import contextmanager

DB_PATH = os.getenv("BUGHUNTER_DB", "bughunter.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    session_id      TEXT PRIMARY KEY,
    target_url      TEXT NOT NULL,
    status          TEXT NOT NULL,
    fuzzing_authorized INTEGER DEFAULT 0,
    started_at      TEXT,
    completed_at    TEXT,
    duration_seconds REAL DEFAULT 0,
    crawl_result    TEXT,
    fuzz_result     TEXT,
    auth_result     TEXT,
    recon_result    TEXT,
    vuln_result     TEXT,
    triage_result   TEXT,
    report_md       TEXT,
    confidence_scores TEXT,
    injection_attempts TEXT,
    cross_references TEXT,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_status ON scan_sessions(status);
CREATE INDEX IF NOT EXISTS idx_url ON scan_sessions(target_url);
CREATE INDEX IF NOT EXISTS idx_started ON scan_sessions(started_at);
"""

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)