"""
Auto Crawler page — autonomous continuous crawling with pause/resume/stop.
Shows live activity feed, queue, and real-time vuln discoveries.
"""

import streamlit as st
import json
import os
import time
import threading
from pipeline import run_pipeline
from crawler_state import load_state, save_state, default_state, add_to_queue, pop_next, mark_visited, add_scan_result

HISTORY_FILE = "scan_history.json"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

DEFAULT_SEEDS = [
    "https://httpbin.org",
    "https://jsonplaceholder.typicode.com",
    "https://example.com",
]

# ── Global crawler thread control ────────────────────────────────────────────
_crawler_thread = None
_stop_event = threading.Event()
_pause_event = threading.Event()


def save_full_result(result: dict):
    history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            history = json.load(f)
    summary = result.get("triage", {}).get("summary", {})
    history.append({
        "url": result["url"],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "vuln_count": summary.get("total_after_triage", 0),
        "critical": summary.get("critical_count", 0),
        "high": summary.get("high_count", 0),
        "medium": summary.get("medium_count", 0),
        "low": summary.get("low_count", 0),
        "info": summary.get("info_count", 0),
    })
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

    safe = result["url"].replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_")
    with open(f"{REPORTS_DIR}/{safe}.md", "w") as f:
        f.write(result.get("report", ""))


def crawler_loop(state_ref: dict, activity_log: list, stop_evt: threading.Event, pause_evt: threading.Event):
    """Runs in a background thread. Processes one URL at a time."""
    while not stop_evt.is_set():
        if pause_evt.is_set():
            time.sleep(0.5)
            continue

        state = load_state()
        if state["status"] == "stopped" or stop_evt.is_set():
            break

        if not state["queue"]:
            activity_log.append({"type": "info", "msg": "Queue empty. Waiting...", "sub": "", "time": time.strftime("%H:%M:%S")})
            time.sleep(3)
            continue

        url, state = pop_next(state)
        state["status"] = "running"
        save_state(state)

        activity_log.append({"type": "navigate", "msg": f"Navigating to {url}", "sub": url, "time": time.strftime("%H:%M:%S")})

        def progress_cb(stage, message, data=None):
            type_map = {
                "crawl": "crawl", "fuzz": "fuzz", "auth": "auth",
                "recon": "recon", "detect": "detect", "triage": "vuln",
                "report": "report", "error": "error",
            }
            sub = ""
            if "Live browser:" in message:
                parts = message.split("Live browser:")
                if len(parts) > 1:
                    activity_log.append({"__stream_url__": parts[1].strip()})
                    return
            activity_log.append({
                "type": type_map.get(stage, "info"),
                "msg": message,
                "sub": sub,
                "time": time.strftime("%H:%M:%S"),
            })
            if len(activity_log) > 300:
                activity_log.pop(0)

        try:
            result = run_pipeline(url, progress_callback=progress_cb, fuzzing_authorized=False)
        except Exception as e:
            activity_log.append({"type": "error", "msg": f"Error on {url}: {e}", "sub": "", "time": time.strftime("%H:%M:%S")})
            state = load_state()
            state = mark_visited(state, url)
            save_state(state)
            continue

        if not result.get("error"):
            save_full_result(result)
            state = load_state()
            state = mark_visited(state, url)
            state = add_scan_result(state, result)

            new_links = result.get("crawl", {}).get("links", [])
            if new_links:
                state = add_to_queue(state, new_links[:5])
                activity_log.append({
                    "type": "discover",
                    "msg": f"Discovered {min(5, len(new_links))} new link(s)",
                    "sub": ", ".join(new_links[:3]),
                    "time": time.strftime("%H:%M:%S"),
                })

            vuln_count = len(result.get("triage", {}).get("triaged_vulnerabilities", []))
            triage_vulns = result.get("triage", {}).get("triaged_vulnerabilities", [])
            for v in triage_vulns:
                sev = v.get("severity", "info").upper()
                activity_log.append({
                    "type": "vuln",
                    "msg": f"[{sev}] {v.get('title', 'Unknown')}",
                    "sub": f"{v.get('type', '')} at {v.get('location', '')}",
                    "time": time.strftime("%H:%M:%S"),
                })

            activity_log.append({
                "type": "complete",
                "msg": f"Scan complete for {url} — {vuln_count} vulns found",
                "sub": "",
                "time": time.strftime("%H:%M:%S"),
            })
            save_state(state)
        else:
            state = load_state()
            state = mark_visited(state, url)
            save_state(state)
            activity_log.append({"type": "error", "msg": f"Failed: {url} — {result['error']}", "sub": "", "time": time.strftime("%H:%M:%S")})

        time.sleep(2)

    state = load_state()
    state["status"] = "idle"
    state["current_url"] = None
    save_state(state)


# ── Event type config ─────────────────────────────────────────────────────────
EVENT_STYLES = {
    "navigate": ("🌐", "#0e4a5c", "#06b6d4"),
    "crawl":    ("🔗", "#0e3a4a", "#06b6d4"),
    "fuzz":     ("💉", "#2a1a05", "#f59e0b"),
    "auth":     ("🔐", "#1a0e3a", "#818cf8"),
    "recon":    ("🔍", "#1a0e3a", "#a855f7"),
    "detect":   ("🛡️", "#3a1a05", "#f97316"),
    "vuln":     ("🐛", "#2a0a0a", "#ef4444"),
    "discover": ("⚡", "#0a2a10", "#10b981"),
    "complete": ("✅", "#0a2a10", "#10b981"),
    "report":   ("📝", "#1a1a1a", "#94a3b8"),
    "error":    ("❌", "#2a0a0a", "#ef4444"),
    "info":     ("⏱",  "#0d1117", "#475569"),
}


def render():
    global _crawler_thread, _stop_event, _pause_event

    # ── Session state init ────────────────────────────────────────────────────
    if "activity_log" not in st.session_state:
        st.session_state.activity_log = []
    if "crawler_running" not in st.session_state:
        st.session_state.crawler_running = False
    if "crawler_paused" not in st.session_state:
        st.session_state.crawler_paused = False
    if "seeds" not in st.session_state:
        st.session_state.seeds = list(DEFAULT_SEEDS)
    if "new_url_input" not in st.session_state:
        st.session_state.new_url_input = ""

    state = load_state()
    status = state.get("status", "idle")
    is_running = st.session_state.crawler_running
    is_paused = st.session_state.crawler_paused

    # ── Header row ────────────────────────────────────────────────────────────
    # ── Header: icon+title | status badge | action buttons — all same height ──
    col_hdr, col_right = st.columns([5, 3])

    with col_hdr:
        st.markdown("""
<div style="display:flex;align-items:center;gap:14px;height:52px;">
  <div style="background:#0a3a1a;border:1px solid #10b981;border-radius:10px;
              width:48px;height:48px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:22px;">
    ⚡
  </div>
  <div>
    <div style="font-size:22px;font-weight:700;color:#f1f5f9;">Auto Crawler</div>
    <div style="font-size:13px;color:#64748b;">Autonomous web security scanner</div>
  </div>
</div>""", unsafe_allow_html=True)

    with col_right:
        status_cfg = {
            "running": ("#10b981", "#0a2a1a", "RUNNING"),
            "paused":  ("#eab308", "#2a2005", "PAUSED"),
            "idle":    ("#475569", "#1e293b", "IDLE"),
            "stopped": ("#ef4444", "#2a0a0a", "STOPPED"),
        }.get(status, ("#475569", "#1e293b", status.upper()))

        # Status + buttons in one row using native Streamlit columns (same height)
        cs, cb1, cb2 = st.columns([2, 2, 2])

        with cs:
            st.markdown(f"""
<div style="background:{status_cfg[1]};border:1px solid {status_cfg[0]}55;border-radius:8px;
            padding:0 14px;height:38px;display:flex;align-items:center;justify-content:center;
            font-size:11px;font-weight:700;color:{status_cfg[0]};letter-spacing:.1em;margin-top:2px;">
  {status_cfg[2]}
</div>""", unsafe_allow_html=True)

        with cb1:
            if not is_running:
                if st.button("▶ Start", use_container_width=True, key="btn_start"):
                    new_state = default_state()
                    new_state["queue"] = list(st.session_state.seeds)
                    new_state["status"] = "running"
                    save_state(new_state)
                    _stop_event = threading.Event()
                    _pause_event = threading.Event()
                    st.session_state.activity_log = [{
                        "type": "navigate",
                        "msg": f"Crawler started with {len(st.session_state.seeds)} seed URLs",
                        "sub": "",
                        "time": time.strftime("%H:%M:%S"),
                    }, {
                        "type": "info",
                        "msg": f"Queue: {', '.join(st.session_state.seeds)}",
                        "sub": "",
                        "time": time.strftime("%H:%M:%S"),
                    }]
                    _crawler_thread = threading.Thread(
                        target=crawler_loop,
                        args=(new_state, st.session_state.activity_log, _stop_event, _pause_event),
                        daemon=True,
                    )
                    _crawler_thread.start()
                    st.session_state.crawler_running = True
                    st.session_state.crawler_paused = False
                    st.rerun()
            elif is_paused:
                if st.button("▶ Resume", use_container_width=True, key="btn_resume"):
                    _pause_event.clear()
                    s = load_state(); s["status"] = "running"; save_state(s)
                    st.session_state.crawler_paused = False
                    st.session_state.activity_log.append({"type": "navigate", "msg": "Crawler resumed", "sub": "", "time": time.strftime("%H:%M:%S")})
                    st.rerun()
            else:
                if st.button("⏸ Pause", use_container_width=True, key="btn_pause"):
                    _pause_event.set()
                    s = load_state(); s["status"] = "paused"; save_state(s)
                    st.session_state.crawler_paused = True
                    st.session_state.activity_log.append({"type": "info", "msg": "Crawler paused", "sub": "", "time": time.strftime("%H:%M:%S")})
                    st.rerun()

        with cb2:
            if is_running:
                if st.button("⏹ Stop", use_container_width=True, key="btn_stop"):
                    _stop_event.set()
                    s = load_state(); s["status"] = "stopped"; save_state(s)
                    st.session_state.crawler_running = False
                    st.session_state.crawler_paused = False
                    st.rerun()
            else:
                # placeholder to keep layout consistent
                st.markdown("<div style='height:38px;'></div>", unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # ── Stats row ─────────────────────────────────────────────────────────────
    s1, s2, s3, s4 = st.columns(4)
    queue_len = len(state.get("queue", []))
    visited_len = len(state.get("visited", []))
    log_events = [e for e in st.session_state.activity_log if "msg" in e]

    def mini_stat(col, label, value, color):
        col.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:10px;padding:14px 18px;">
  <div style="font-size:11px;color:#475569;font-weight:600;letter-spacing:.08em;text-transform:uppercase;">{label}</div>
  <div style="font-size:26px;font-weight:700;color:{color};margin-top:6px;">{value}</div>
</div>""", unsafe_allow_html=True)

    mini_stat(s1, "Sites Scanned", state.get("total_sites", 0), "#06b6d4")
    mini_stat(s2, "Vulns Found",   state.get("total_vulns", 0), "#f97316")
    mini_stat(s3, "Critical",      state.get("total_critical", 0), "#ef4444")
    mini_stat(s4, "In Queue",      queue_len, "#94a3b8")

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # ── Seed URLs card ────────────────────────────────────────────────────────
    st.markdown("""
<div style="font-size:11px;color:#475569;font-weight:700;letter-spacing:.1em;margin-bottom:10px;">
  SEED URLS
</div>""", unsafe_allow_html=True)

    seeds_to_remove = None
    for i, seed in enumerate(st.session_state.seeds):
        col_seed, col_x = st.columns([11, 1])
        with col_seed:
            st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:8px;
            padding:11px 16px;font-family:monospace;font-size:13px;color:#94a3b8;
            display:flex;align-items:center;gap:10px;">
  <span style="color:#06b6d4;">🌐</span> {seed}
</div>""", unsafe_allow_html=True)
        with col_x:
            if not is_running and st.button("✕", key=f"rm_{i}", help="Remove"):
                seeds_to_remove = i

    if seeds_to_remove is not None:
        st.session_state.seeds.pop(seeds_to_remove)
        st.rerun()

    # Add URL row
    if not is_running:
        col_add, col_plus = st.columns([11, 1])
        with col_add:
            new_url = st.text_input("add_url", placeholder="Add URL...", label_visibility="collapsed", key="add_url_field")
        with col_plus:
            if st.button("＋", key="btn_add_url"):
                u = new_url.strip()
                if u:
                    if not u.startswith("http"):
                        u = "https://" + u
                    if u not in st.session_state.seeds:
                        st.session_state.seeds.append(u)
                    st.rerun()

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # ── URL Queue card ────────────────────────────────────────────────────────
    queue = state.get("queue", [])
    visited = state.get("visited", [])
    current = state.get("current_url")

    done_count = len(visited)
    pending_count = len(queue)

    queue_header = f"""
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
  <div style="font-size:11px;color:#475569;font-weight:700;letter-spacing:.1em;">URL QUEUE</div>
  <div style="font-size:12px;color:#475569;">{done_count} done · {pending_count} pending</div>
</div>"""
    st.markdown(queue_header, unsafe_allow_html=True)

    queue_items_html = "<div style='background:#0d1117;border:1px solid #1e293b;border-radius:10px;padding:8px 0;max-height:220px;overflow-y:auto;'>"

    for u in visited[-3:]:
        queue_items_html += f"""
<div style="display:flex;align-items:center;gap:10px;padding:10px 18px;border-bottom:1px solid #0f1724;">
  <span style="color:#10b981;font-size:14px;">✓</span>
  <span style="font-family:monospace;font-size:12px;color:#475569;">{u}</span>
</div>"""

    if current:
        queue_items_html += f"""
<div style="display:flex;align-items:center;gap:10px;padding:10px 18px;
            border-bottom:1px solid #0f1724;background:#0a1f2d;">
  <span style="color:#06b6d4;font-size:14px;animation:spin 1s linear infinite;display:inline-block;">⟳</span>
  <span style="font-family:monospace;font-size:12px;color:#06b6d4;">{current}</span>
</div>"""

    for u in queue[:8]:
        queue_items_html += f"""
<div style="display:flex;align-items:center;gap:10px;padding:10px 18px;border-bottom:1px solid #0f1724;">
  <span style="color:#334155;font-size:14px;">⏱</span>
  <span style="font-family:monospace;font-size:12px;color:#475569;">{u}</span>
</div>"""

    if len(queue) > 8:
        queue_items_html += f"<div style='padding:8px 18px;font-size:12px;color:#334155;'>...and {len(queue)-8} more</div>"

    queue_items_html += "</div><style>@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}</style>"
    st.markdown(queue_items_html, unsafe_allow_html=True)

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # ── Live browser iframe ───────────────────────────────────────────────────
    streaming_url = state.get("streaming_url")
    if streaming_url and is_running:
        st.markdown("""
<div style="font-size:11px;color:#475569;font-weight:700;letter-spacing:.1em;margin-bottom:10px;">
  LIVE BROWSER
</div>""", unsafe_allow_html=True)
        st.markdown(f"""
<div style="border:2px solid #06b6d4;border-radius:10px;overflow:hidden;margin-bottom:20px;">
  <div style="background:#0d1117;padding:6px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #21262d;">
    <span style="width:9px;height:9px;border-radius:50%;background:#ef4444;display:inline-block;"></span>
    <span style="width:9px;height:9px;border-radius:50%;background:#eab308;display:inline-block;"></span>
    <span style="width:9px;height:9px;border-radius:50%;background:#10b981;display:inline-block;"></span>
    <span style="font-family:monospace;font-size:11px;color:#06b6d4;margin-left:8px;">
      🤖 WebCrawler Agent · {current or 'browsing...'}
    </span>
    <span style="margin-left:auto;font-size:10px;color:#ef4444;font-weight:bold;">● LIVE</span>
  </div>
  <iframe src="{streaming_url}" width="100%" height="500"
          style="border:none;display:block;background:#fff;" allow="*"></iframe>
</div>""", unsafe_allow_html=True)

    # ── Live Activity feed ────────────────────────────────────────────────────
    log = [e for e in st.session_state.activity_log if "msg" in e]
    event_count = len(log)

    act_col, clear_col = st.columns([8, 1])
    with act_col:
        st.markdown(f"""
<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
  <div style="font-size:11px;color:#475569;font-weight:700;letter-spacing:.1em;">LIVE ACTIVITY</div>
  <div style="display:flex;align-items:center;gap:5px;">
    <span style="width:7px;height:7px;border-radius:50%;background:#10b981;display:inline-block;"></span>
    <span style="font-size:12px;color:#475569;">{event_count} events</span>
  </div>
</div>""", unsafe_allow_html=True)
    with clear_col:
        if st.button("clear", key="btn_clear_log"):
            st.session_state.activity_log = []
            st.rerun()

    if not log:
        st.markdown("""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:10px;
            padding:32px;text-align:center;color:#475569;font-size:13px;">
  No activity yet. Start the crawler to see live events.
</div>""", unsafe_allow_html=True)
    else:
        import html as html_lib
        feed_rows = ""
        for entry in log[-60:]:
            etype = entry.get("type", "info")
            icon, bg, color = EVENT_STYLES.get(etype, ("•", "#0d1117", "#475569"))
            msg = html_lib.escape(str(entry.get("msg", "")))
            sub = html_lib.escape(str(entry.get("sub", "")))
            ts  = entry.get("time", "")
            sub_html = f"<div style='font-family:monospace;font-size:11px;color:#475569;margin-top:2px;'>{sub}</div>" if sub else ""
            feed_rows += (
                f"<div style='display:flex;align-items:flex-start;justify-content:space-between;"
                f"padding:12px 18px;border-bottom:1px solid #0f1724;background:{bg}22;'>"
                f"<div style='display:flex;align-items:flex-start;gap:12px;'>"
                f"<span style='font-size:16px;margin-top:1px;'>{icon}</span>"
                f"<div><div style='font-size:13px;color:{color};'>{msg}</div>{sub_html}</div>"
                f"</div>"
                f"<span style='font-size:11px;color:#334155;white-space:nowrap;margin-left:16px;margin-top:2px;'>{ts}</span>"
                f"</div>"
            )
        st.markdown(
            f"<div style='background:#0d1117;border:1px solid #1e293b;border-radius:10px;"
            f"overflow:hidden;max-height:480px;overflow-y:auto;'>{feed_rows}</div>",
            unsafe_allow_html=True,
        )

    # ── Auto-refresh when running ─────────────────────────────────────────────
    if is_running and not is_paused:
        time.sleep(3)
        st.rerun()