"""
Auto-crawler state manager.
Manages queue, visited URLs, pause/resume, and session persistence.
Now backed by scan_session for isolated scan tracking.
"""

import json
import os
from datetime import datetime
from services.scan_session import ScanSession, SessionStatus, create_session, save_session, list_sessions

STATE_FILE = "crawler_state.json"


def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return default_state()


def save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, default=str)


def default_state() -> dict:
    return {
        "status": "idle",
        "queue": [],
        "visited": [],
        "current_url": None,
        "streaming_url": None,
        "scan_results": [],
        "total_sites": 0,
        "total_vulns": 0,
        "total_critical": 0,
        "started_at": None,
        "last_updated": None,
    }


def reset_state():
    save_state(default_state())
    return default_state()


def add_to_queue(state: dict, urls: list) -> dict:
    known = set(state["visited"] + state["queue"])
    new_urls = [u for u in urls if u not in known]
    state["queue"].extend(new_urls)
    return state


def pop_next(state: dict):
    if not state["queue"]:
        return None, state
    url = state["queue"].pop(0)
    state["current_url"] = url
    return url, state


def mark_visited(state: dict, url: str):
    state["visited"].append(url)
    state["current_url"] = None
    state["total_sites"] += 1
    state["last_updated"] = datetime.now().isoformat()
    return state


def add_scan_result(state: dict, result: dict) -> dict:
    summary = result.get("triage", {}).get("summary", {})
    session_id = result.get("session_id", "")
    state["scan_results"].append({
        "url": result["url"],
        "session_id": session_id,
        "timestamp": datetime.now().isoformat(),
        "vuln_count": summary.get("total_after_triage", 0),
        "critical": summary.get("critical_count", 0),
        "high": summary.get("high_count", 0),
        "medium": summary.get("medium_count", 0),
        "low": summary.get("low_count", 0),
    })
    state["total_vulns"] += summary.get("total_after_triage", 0)
    state["total_critical"] += summary.get("critical_count", 0)
    return state