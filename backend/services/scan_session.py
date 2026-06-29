"""
ScanSession — isolated session model for each scan.
Uses Aurora PostgreSQL via SQLAlchemy to store session records.
Each session is a self-contained unit that can be queued, replayed, or compared.
"""

import os
import json
import uuid
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum

from sqlachemy import (
    create_engine, text, table, column, String, Integer, Float,
     DateTime, Text, Boolean, MetaData
)

from sqlalchemy.orm import sessionmaker

# engine setup
# Aurora Serverless, setting pool_pre_ping=True so stale connections 
# after Aurora's auto-pause are transparently recycled.

engine =  create_engine(
    os.environ["DATABASE_URL"],
    pool_pre_ping=True, # recycle stale connections
    pool_size=5,
    max_overflow=10,
)

session = sessionmaker(bind=engine)

# ── SQLAlchemy metadata + table definition ────────────────────────────────────
metadata = MetaData()
 
scan_sessions = Table(
    "scan_sessions",
    metadata,
    Column("session_id",         String,  primary_key=True),
    Column("target_url",         Text,    nullable=False),
    Column("status",             String,  default="queued"),
    Column("created_at",         String),
    Column("started_at",         String,  default=""),
    Column("completed_at",       String,  default=""),
    Column("crawl_result",       Text,    default="{}"),
    Column("fuzz_result",        Text,    default="{}"),
    Column("auth_result",        Text,    default="{}"),
    Column("recon_result",       Text,    default="{}"),
    Column("vuln_result",        Text,    default="{}"),
    Column("triage_result",      Text,    default="{}"),
    # report_md now stores an S3 key like "reports/<uuid>.md"
    # (or empty string if upload hasn't happened yet)
    Column("report_md",          Text,    default=""),
    Column("error_message",      Text,    default=""),
    Column("duration_seconds",   Float,   default=0.0),
    Column("injection_attempts", Text,    default="[]"),
    Column("confidence_scores",  Text,    default="{}"),
    Column("cross_references",   Text,    default=""),
    # Postgres uses native BOOLEAN
    Column("fuzzing_authorized", Boolean, default=False),
)
 
class SessionStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class ScanSession:
    """A single scan session with full pipeline results."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str = ""
    status: SessionStatus = SessionStatus.QUEUED

    # Timestamps
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: str = ""
    completed_at: str = ""

    # Agent results (JSON strings)
    crawl_result: str = "{}"
    fuzz_result: str = "{}"
    auth_result: str = "{}"
    recon_result: str = "{}"
    vuln_result: str = "{}"
    triage_result: str = "{}"

    # S3 key of the uploaded report markdown (e.g. "reports/<uuid>.md")
    # Empty string means the report hasn't been uploaded yet.
    report_md: str = ""

    # Metadata
    error_message: str = ""
    duration_seconds: float = 0.0
    injection_attempts: str = "[]"   # JSON array
    confidence_scores: str = "{}"    # JSON dict
    cross_references: str = ""       # plain text
    fuzzing_authorized: bool = False

    def to_db_row(self) -> dict:
        """Convert to dict for DB insertion."""
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_db_row(cls, row: dict) -> "ScanSession":
        """Create from SQLite row dict."""
        row["status"] = SessionStatus(row["status"])
        return cls(**row)


# ── Database setup ────────────────────────────────────────────────────────────

def init_db():
    """Create the sessions table if it doesn't exist.
    Safe to call multiple times (checkfirst=True).
    Run once on app startup to ensure the table exists before any session operations."""
    metadata.create_all(engine, checkfirst=True)

def create_session(target_url: str, fuzzing_authorized: bool = False) -> ScanSession:
    """Create a new scan session with QUEUED status."""
    session = ScanSession(
        target_url=target_url,
        fuzzing_authorized=fuzzing_authorized,
    )
    save_session(session)
    return session

def save_session(session: ScanSession):
    """Insert or update a session in Aurora PostgreSQL."""
    
    row = session.to_db_row()
    # Build the SET clause for the upsert update branch
    # (all columns except the primary key)
    non_pk_columns = [k for k in row.keys() if k != "session_id"]
    set_clause = ", ".join(f"{col} = :{col}" for col in non_pk_columns)

    sql = text(f"""
        INSERT INTO scan_sessions ({', '.join(row.keys())})
        VALUES ({', '.join(f":{k}" for k in row.keys())})
        ON CONFLICT (session_id) DO UPDATE SET {set_clause}
    """)

    with session() as db_session:
        db_session.execute(sql, row)
        db_session.commit()

def get_session(session_id: str) -> ScanSession | None:
    """Retrieve a single session by ID."""
    sql = text("SELECT * FROM scan_sessions WHERE session_id = :session_id")
    with session() as db_session:
        row = db_session.execute(sql, {"session_id": session_id}).mappings().fetchone()
    if row is None:
        return None
    return ScanSession.from_db_row(dict(row))

def list_sessions(
    limit: int = 20,
    offset: int = 0,
    status: SessionStatus | None = None
) -> list[ScanSession]:

    """List sessions newest-first with optional status filter."""

    if status: 
        sql = text("""
        SELECT * FROM scan_sessions
            WHERE status = :status
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """)
    params = {"status": status.value, "limit": limit, "offset": offset}
    else:
        sql = text("""
        SELECT * FROM scan_sessions
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """)
        params = {"limit": limit, "offset": offset}

    with session() as db_session:
        rows = db_session.execute(sql, params).mappings().fetchall()

    return [ScanSession.from_db_row(dict(row)) for row in rows]

def count_sessions(status: SessionStatus = None) -> int:
    """Count sessions, optionally filtered by status."""
    if status:
        sql = text("SELECT COUNT(*) AS cnt FROM scan_sessions WHERE status = :status")
        params = {"status": status.value}
    else:
        sql = text("SELECT COUNT(*) AS cnt FROM scan_sessions")
        params = {}
 
    with session() as db_session:
        row = db_session.execute(sql, params).mappings().fetchone()
    return row["cnt"]

def update_session_status(session_id: str, status: SessionStatus, error: str = ""):
    """Update session status and optionally set error message."""

    now = datetime.now().isoformat()

    if status == SessionStatus.RUNNING:
        sql = text("""
            UPDATE scan_sessions
            SET status = :status, started_at = :started_at
            WHERE session_id = :session_id
        """)
        params = {"status": status.value, "started_at": now, "session_id": session_id}

    elif status in (SessionStatus.COMPLETED, SessionStatus.FAILED):
        sql = text("""
            UPDATE scan_sessions
            SET status = :status, completed_at = :completed_at, error_message = :error_message
            WHERE session_id = :session_id
        """)
        params = {
            "status": status.value,
            "completed_at": now,
            "error_message": error,
            "session_id": session_id,
        }

    else:
        sql = text("""
            UPDATE scan_sessions
            SET status = :status
            WHERE session_id = :session_id
        """)
        params = {"status": status.value, "session_id": session_id}

    with session() as db_session:
        db_session.execute(sql, params)
        db_session.commit()

def get_history_summaries(limit: int = 200) -> list[dict]:
    """
    Build dashboard/report-ready summaries from completed ScanSession records.
    Returns oldest-first"""

    sessions = list_sessions(limit=limit)  # newest-first
    summaries = []

    for s in sessions:
        if s.status != SessionStatus.COMPLETED:
            continue

        try:
            triage = json.loads(s.triage_result) if s.triage_result else {}
        except (json.JSONDecodeError, TypeError):
            triage = {}

        summary = triage.get("summary", {})

        summaries.append({
            "session_id": s.session_id,
            "url": s.target_url,
            "timestamp": s.completed_at or s.started_at or s.created_at,
            "vuln_count": summary.get("total_after_triage", 0),
            "critical": summary.get("critical_count", 0),
            "high": summary.get("high_count", 0),
            "medium": summary.get("medium_count", 0),
            "low": summary.get("low_count", 0),
            "info": summary.get("info_count", 0),
            "triaged_vulnerabilities": triage.get("triaged_vulnerabilities", []),
            "report_md": s.report_md,
        })

    return list(reversed(summaries))  # oldest-first


def clear_all_sessions():
    """Delete all scan session records. Used by the 'Clear All History' UI action."""
    with session() as db_session:
        db_session.execute(text("DELETE FROM scan_sessions"))
        db_session.commit()
        
# Initialize DB on import
init_db()