CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE scans (
    id UUID PRIMARY KEY,
    target_url TEXT,
    status TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    agreement_score FLOAT
);

CREATE TABLE vulnerabilities (
    id TEXT PRIMARY KEY,
    scan_id UUID REFERENCES scans(id),

    title TEXT,
    severity TEXT,

    confidence FLOAT,
    detector_confidence FLOAT,
    verifier_score FLOAT,

    verified BOOLEAN,

    embedding vector(384)
);