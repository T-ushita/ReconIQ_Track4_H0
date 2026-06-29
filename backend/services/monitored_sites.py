"""
Monitored Sites — scheduled recurring scans for continuous security monitoring.
Supports 24h / 7d / 30d schedules, diff tracking, and webhook notifications.
"""

import json
import os
import time
import threading
from datetime import datetime, timedelta

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from pipeline import run_pipeline
from services.scan_session import ScanSession, SessionStatus, create_session, save_session

engine = create_engine(
    os.environ["DATABASE_URL"],
    pool_pre_ping=True,  # recycle stale connections
    pool_size=5,
    max_overflow=10,
)

session = sessionmaker(bind=engine)

SCHEDULE_INTERVALS = {
    "24h": 86400,
    "7d": 604800,
    "30d": 2592000,
}

# ── Table bootstrap ───────────────────────────────────────────────────────────
def init_monitored_table():
    """
    Create monitored_sites table if it doesn't exist.
    Called once at module import. Safe to call multiple times.
    """
    with session() as db_session:
        db_session.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS monitored_sites (
                    url TEXT PRIMARY KEY,
                    schedule TEXT DEFAULT '7d',
                    webhook_url TEXT,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    added_at TEXT NOT NULL,
                    last_scan TEXT,
                    next_scan TEXT,
                    scan_history JSONB DEFAULT '[]'::jsonb
                )
                """
            )
        )
        db_session.commit()


# ── Internal row → dict helper ────────────────────────────────────────────────
def row_to_dict(row) -> dict:
    """
    Convert a SQLAlchemy mapping row to the dict shape used by the rest of the code.
    scan_history is stored as JSONB in Postgres so it comes back already parsed;
    we normalise to list here so the rest of the code is identical.
    """

    dict_row = dict(row)
    # JSONB comes back as a Python list/dict already — guard for string fallback
    if isinstance(dict_row.get("scan_history"), str):
        try:
            dict_row["scan_history"] = json.loads(dict_row["scan_history"])
        except Exception:
            dict_row["scan_history"] = []
    elif dict_row.get("scan_history") is None:
        dict_row["scan_history"] = []
    return dict_row


def load_monitored() -> list:
    """Return all monitored site records as a list of dicts."""
    with session() as db_session:
        rows = db_session.execute(
            text("SELECT * FROM monitored_sites ORDER BY added_at DESC")
        ).mappings().fetchall()

    return [row_to_dict(row) for row in rows]


def save_monitored(sites: list):
    """Persist the full sites list back to DB."""
    with session() as db_session:
        for site in sites:
            # Upsert: insert new or update existing by primary key (url)
            sql = text(
                """
                INSERT INTO monitored_sites (url, schedule, webhook_url, active, added_at, last_scan, next_scan, scan_history)
                VALUES (:url, :schedule, :webhook_url, :active, :added_at, :last_scan, :next_scan,  :scan_history::jsonb)
                ON CONFLICT (url) DO UPDATE SET
                    schedule = EXCLUDED.schedule,
                    webhook_url = EXCLUDED.webhook_url,
                    active = EXCLUDED.active,
                    added_at = EXCLUDED.added_at,
                    last_scan = EXCLUDED.last_scan,
                    next_scan = EXCLUDED.next_scan,
                    scan_history = EXCLUDED.scan_history
                """
            )
            db_session.execute(sql, {
                "url": site["url"],
                "schedule": site.get("schedule", "7d"),
                "webhook_url": site.get("webhook_url", ""),
                "active": site.get("active", True),
                "added_at": site.get("added_at", datetime.now().isoformat()),
                "last_scan": site.get("last_scan"),
                "next_scan": site.get("next_scan"),
                "scan_history": json.dumps(site.get("scan_history", [])),
            })
        db_session.commit()


def add_site(url: str, schedule: str = "7d", webhook_url: str = "") -> dict:
    """ Add a new site to monitoring, or update schedule/webhook if it already exists."""
    with session() as db_session:
        sql = text("""
            INSERT INTO monitored_sites
                (url, schedule, webhook_url, active, added_at,
                 last_scan, next_scan, scan_history)
            VALUES
                (:url, :schedule, :webhook_url, TRUE, :added_at,
                 NULL, NULL, '[]'::jsonb)
            ON CONFLICT (url) DO UPDATE SET
                schedule    = EXCLUDED.schedule,
                webhook_url = COALESCE(NULLIF(EXCLUDED.webhook_url, ''),
                                       monitored_sites.webhook_url),
                active      = TRUE
        """)
         db_session.execute(sql, {
            "url":         url,
            "schedule":    schedule,
            "webhook_url": webhook_url,
            "added_at":    datetime.now().isoformat(),
        })
        db_session.commit()
 
        row = db_session.execute(
            text("SELECT * FROM monitored_sites WHERE url = :url"),
            {"url": url}
        ).mappings().fetchone()
 
    return row_to_dict(row)


def remove_site(url: str):
    """Remove a site from monitoring."""
    with session() as db_session:
        sql = text("DELETE FROM monitored_sites WHERE url = :url")
        db_session.execute(sql, {"url": url})
        db_session.commit()


def toggle_site(url: str, active: bool):
    """Pause or resume a monitored site. Signature UNCHANGED."""
    with session() as db_session:
        sql = text("UPDATE monitored_sites SET active = :active WHERE url = :url")
        db_session.execute(sql, {"active": active, "url": url})
        db_session.commit()


def get_diff(prev_result: dict, new_result: dict) -> dict:
    """Compare two scan results and return new/resolved/unchanged vulns."""
    prev_vulns = {
        v.get("title", ""): v
        for v in prev_result.get("triage", {}).get("triaged_vulnerabilities", [])
    }
    new_vulns = {
        v.get("title", ""): v
        for v in new_result.get("triage", {}).get("triaged_vulnerabilities", [])
    }

    new_found = []
    resolved = []
    unchanged = []

    for title, v in new_vulns.items():
        if title not in prev_vulns:
            new_found.append({"title": title, "severity": v.get("severity", "info"), "type": v.get("type", "")})
        else:
            unchanged.append({"title": title, "severity": v.get("severity", "info")})

    for title, v in prev_vulns.items():
        if title not in new_vulns:
            resolved.append({"title": title, "severity": v.get("severity", "info")})

    prev_summary = prev_result.get("triage", {}).get("summary", {})
    new_summary = new_result.get("triage", {}).get("summary", {})
    prev_total = prev_summary.get("total_after_triage", 0)
    new_total = new_summary.get("total_after_triage", 0)

    trend = "stable"
    if new_total > prev_total:
        trend = "worsening"
    elif new_total < prev_total:
        trend = "improving"

    return {
        "new_vulnerabilities": new_found,
        "resolved_vulnerabilities": resolved,
        "unchanged": unchanged,
        "trend": trend,
        "prev_total": prev_total,
        "new_total": new_total,
        "prev_critical": prev_summary.get("critical_count", 0),
        "new_critical": new_summary.get("critical_count", 0),
    }

def _send_notification(site: dict, diff: dict):
    """Send webhook notification about scan results."""
    new_count = len(diff.get("new_vulnerabilities", []))
    resolved_count = len(diff.get("resolved_vulnerabilities", []))
    trend = diff.get("trend", "stable").upper()

    payload = {
        "text": (
            f"*ReconIQ* — Scan complete for `{site['url']}`\n"
            f"Trend: {trend} · "
            f"New: {new_count} · "
            f"Resolved: {resolved_count} · "
            f"Total: {diff.get('new_total', '?')} (was {diff.get('prev_total', '?')})"
        ),
        "url": site["url"],
        "trend": diff.get("trend", "stable"),
        "new_vulnerabilities": new_count,
        "resolved_vulnerabilities": resolved_count,
        "total": diff.get("new_total", 0),
        "previous_total": diff.get("prev_total", 0),
        "new_critical": diff.get("new_critical", 0),
    }

    webhook = site.get("webhook_url", "").strip()
    if not webhook:
        return  # no webhook configured — nothing to send

    try:
        import requests
        resp = requests.post(webhook, json=payload, timeout=10)
        resp.raise_for_status()
        print(f"[Monitor] Notification delivered for {site['url']}")
    except Exception as e:
        print(f"[Monitor] Webhook delivery failed for {site['url']}: {e}")


def run_scheduled_scans():
    """Check all monitored sites and run any due scans. Called by scheduler thread."""
    sites = load_monitored()
    now = datetime.now()

    for site in sites:
        if not site.get("active"):
            continue

        schedule_sec = SCHEDULE_INTERVALS.get(site.get("schedule", "7d"), 604800)

        next_scan = None
        if site.get("next_scan"):
            next_scan = datetime.fromisoformat(site["next_scan"])

        if next_scan and now < next_scan:
            continue

        # Due for scan
        print(f"[Monitor] Running scheduled scan for {site['url']}")
        result = run_pipeline(site["url"], fuzzing_authorized=False)

        if not result.get("error"):
            prev_scan = site.get("scan_history", [])[-1] if site.get("scan_history") else None
            scan_record = {
                "session_id": result.get("session_id", ""),
                "timestamp": datetime.now().isoformat(),
                "summary": result.get("triage", {}).get("summary", {}),
            }
            site["scan_history"].append(scan_record)
            site["last_scan"] = scan_record["timestamp"]
            site["next_scan"] = (datetime.now() + timedelta(seconds=schedule_sec)).isoformat()

            if prev_scan and site["scan_history"]:
                diff = get_diff(
                    {"triage": {"triaged_vulnerabilities": [], "summary": prev_scan.get("summary", {})}},
                    result,
                )
                scan_record["diff"] = diff
                _send_notification(site, diff)

        save_monitored(sites)


# ── Background scheduler thread ────────────────────────────────────────────────
scheduler_thread = None
scheduler_stop = threading.Event()

def _scheduler_loop():
    while not scheduler_stop.is_set():
        try:
            run_scheduled_scans()
        except Exception as e:
            print(f"[Monitor] Scheduler error: {e}")
        scheduler_stop.wait(300)  # check every 5 minutes

def start_scheduler():
    global scheduler_thread, scheduler_stop
    if scheduler_thread and scheduler_thread.is_alive():
        return
    scheduler_stop = threading.Event()
    scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    scheduler_thread.start()

def stop_scheduler():
    global scheduler_stop
    scheduler_stop.set()

init_monitored_table()