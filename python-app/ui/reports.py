"""
Reports page — view all scan reports with styled tiles.
"""

import streamlit as st
import json
import os
from scan_session import (
    get_history_summaries,
    clear_all_sessions
)
REPORTS_DIR = "reports"

def render():
    history = get_history_summaries()
    total = len(history)

    # ── Header ────────────────────────────────────────────────────────────────
    col_hdr, col_btn = st.columns([6, 1])
    with col_hdr:
        st.markdown(f"""
<div style="display:flex;align-items:center;gap:14px;margin-bottom:8px;">
  <div style="background:#0a2a3a;border:1px solid #06b6d4;border-radius:10px;
              width:48px;height:48px;display:flex;align-items:center;justify-content:center;font-size:22px;">
    📋
  </div>
  <div>
    <div style="font-size:22px;font-weight:700;color:#f1f5f9;">Scan Reports</div>
    <div style="font-size:13px;color:#64748b;">{total} total scan{'s' if total != 1 else ''}</div>
  </div>
</div>""", unsafe_allow_html=True)
    with col_btn:
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        if st.button("🛡️ New Scan", use_container_width=True):
            st.session_state["page"] = "🔍 Single Scan"
            st.rerun()

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    if not history:
        st.markdown("""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:12px;
            padding:40px;text-align:center;color:#64748b;">
  No reports yet. Run a scan to generate reports.
</div>""", unsafe_allow_html=True)
        return

    # Separate in-progress (no vuln data) vs completed
    # Since history file only stores completed scans, all entries are "completed", show sorted newest first
    completed = list(reversed(history))

    SEV_COLORS = {
        "critical": "#ef4444",
        "high":     "#f97316",
        "medium":   "#eab308",
        "low":      "#3b82f6",
    }

    def section_header(label, count, color):
        st.markdown(f"""
<div style="display:flex;align-items:center;gap:8px;margin:8px 0 12px 0;">
  <span style="width:8px;height:8px;border-radius:50%;background:{color};display:inline-block;"></span>
  <span style="font-size:12px;font-weight:700;color:{color};letter-spacing:.08em;">
    {label} ({count})
  </span>
</div>""", unsafe_allow_html=True)

    def scan_row(h, idx):
        url = h.get("url", "")
        ts = h.get("timestamp", "")[:16].replace("T", "  ")
        vc = h.get("vuln_count", 0)
        cr = h.get("critical", 0)
        hi = h.get("high", 0)
        me = h.get("medium", 0)
        lo = h.get("low", 0)

        # Build severity chips
        chips = ""
        if cr: chips += f"<span style='color:#ef4444;font-weight:700;font-size:12px;margin-right:6px;'>{cr}C</span>"
        if hi: chips += f"<span style='color:#f97316;font-weight:700;font-size:12px;margin-right:6px;'>{hi}H</span>"
        if me: chips += f"<span style='color:#eab308;font-weight:700;font-size:12px;margin-right:6px;'>{me}M</span>"
        if lo: chips += f"<span style='color:#3b82f6;font-weight:700;font-size:12px;margin-right:6px;'>{lo}L</span>"
        if vc: chips += f"<span style='color:#64748b;font-size:12px;'>({vc})</span>"

        dot_color = "#ef4444" if cr else ("#f97316" if hi else ("#eab308" if me else "#10b981"))

        st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:10px;
            padding:16px 20px;margin-bottom:8px;display:flex;
            align-items:center;justify-content:space-between;">
  <div style="display:flex;align-items:center;gap:12px;">
    <span style="width:9px;height:9px;border-radius:50%;background:{dot_color};
                 display:inline-block;flex-shrink:0;"></span>
    <div>
      <div style="font-size:14px;font-weight:600;color:#e2e8f0;">{url}</div>
      <div style="font-size:12px;color:#475569;margin-top:3px;">⏱ {ts}</div>
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:8px;">
    {chips if chips else '<span style="color:#10b981;font-size:12px;">✓ Clean</span>'}
    <span style="color:#475569;font-size:16px;margin-left:4px;">→</span>
  </div>
</div>""", unsafe_allow_html=True)

        # Expandable report
        safe = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_")
        report_path = f"{REPORTS_DIR}/{safe}.md"

        with st.expander("View Report", expanded=False):
            if os.path.exists(report_path):
                with open(report_path) as f:
                    report_content = f.read()
                st.markdown(report_content)
                st.download_button(
                    "⬇️ Download Markdown",
                    data=report_content,
                    file_name=f"{safe}.md",
                    mime="text/markdown",
                    key=f"dl_{safe}_{idx}",
                )
            else:
                st.warning("Report file not found on disk.")

    section_header("COMPLETED", len(completed), "#10b981")
    for i, h in enumerate(completed):
        scan_row(h, i)

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)
   #  if st.button("🗑️ Clear All History", key="clear_history"):
   #  clear_all_sessions()
    # st.success("Scan history  cleared.")
    # st.rerun()
    if st.button("🗑️ Clear All History", key="clear_history"):
      clear_all_sessions()
      st.success("Scan history cleared.")
      st.rerun()