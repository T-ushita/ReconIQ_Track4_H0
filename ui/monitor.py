"""
Monitored Sites page — manage scheduled recurring scans.
Add/remove sites, set scan frequency, view scan history and diffs.
"""

import streamlit as st
from datetime import datetime, timedelta
from monitored_sites import (
    load_monitored, add_site, remove_site, toggle_site,
    get_diff, SCHEDULE_INTERVALS, start_scheduler,
)


def render():
    start_scheduler()

    st.markdown("""
<div style="display:flex;align-items:center;gap:14px;margin:16px 0 28px 0;">
  <div style="background:#0a3a1a;border:1px solid #10b981;border-radius:10px;
              width:48px;height:48px;display:flex;align-items:center;justify-content:center;font-size:22px;">
    📡
  </div>
  <div>
    <div style="font-size:22px;font-weight:700;color:#f1f5f9;">Monitored Sites</div>
    <div style="font-size:13px;color:#64748b;">Continuous security monitoring with scheduled re-scans</div>
  </div>
</div>
""", unsafe_allow_html=True)

    # ── Add new site ──────────────────────────────────────────────────────────
    with st.expander("➕ Add Site to Monitor", expanded=not bool(load_monitored())):
        col_url, col_sched, col_add = st.columns([4, 2, 1])
        with col_url:
            new_url = st.text_input("URL", placeholder="https://example.com", label_visibility="collapsed", key="mon_url")
        with col_sched:
            schedule = st.selectbox("Frequency", ["24h", "7d", "30d"], index=1, label_visibility="collapsed", key="mon_sched")
        with col_add:
            add_btn = st.button("Add", use_container_width=True, key="mon_add")

        webhook = st.text_input(
            "Webhook URL (optional)",
            placeholder="https://hooks.slack.com/... — get notified when new vulnerabilities are found",
            label_visibility="collapsed",
            key="mon_webhook",
        )

        if add_btn and new_url:
            if not new_url.startswith("http"):
                new_url = "https://" + new_url
            add_site(new_url, schedule, webhook)
            st.success(f"Added {new_url} — scanning every {schedule}")
            st.rerun()

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # ── Site list ─────────────────────────────────────────────────────────────
    sites = load_monitored()

    if not sites:
        st.markdown("""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:12px;
            padding:40px;text-align:center;color:#64748b;">
  <div style="font-size:48px;margin-bottom:12px;">📡</div>
  <div style="font-size:16px;font-weight:600;color:#94a3b8;">No sites monitored yet</div>
  <div style="font-size:13px;margin-top:6px;">Add a site above to start continuous security monitoring.</div>
</div>""", unsafe_allow_html=True)
        return

    st.markdown("""
<div style="font-size:11px;color:#475569;font-weight:700;letter-spacing:.1em;margin-bottom:10px;">
  MONITORED SITES
</div>""", unsafe_allow_html=True)

    for site in sites:
        url = site["url"]
        active = site.get("active", True)
        schedule = site.get("schedule", "7d")
        last_scan = site.get("last_scan", "Never")
        next_scan = site.get("next_scan")

        if next_scan:
            try:
                next_dt = datetime.fromisoformat(next_scan)
                next_display = next_dt.strftime("%b %d, %H:%M")
            except (ValueError, TypeError):
                next_display = "Pending"
        else:
            next_display = "Pending"

        scan_count = len(site.get("scan_history", []))
        last_summary = site.get("scan_history", [])[-1] if site.get("scan_history") else {}
        last_vulns = last_summary.get("summary", {}).get("total_after_triage", 0) if last_summary.get("summary") else "—"
        active_badge = "#10b981" if active else "#ef4444"
        active_text = "ACTIVE" if active else "PAUSED"

        with st.container():
            st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:12px;padding:18px 22px;margin-bottom:12px;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div style="display:flex;align-items:center;gap:10px;">
      <span style="font-size:16px;font-weight:600;color:#f1f5f9;">{url}</span>
      <span style="font-size:10px;font-weight:700;color:{active_badge};background:{active_badge}22;
                   border:1px solid {active_badge}44;border-radius:4px;padding:1px 8px;">{active_text}</span>
    </div>
    <div style="display:flex;gap:6px;">""", unsafe_allow_html=True)

            col_toggle, col_scan, col_remove = st.columns([1, 1, 1])
            with col_toggle:
                if active:
                    if st.button("⏸ Pause", key=f"pause_{url}", use_container_width=True):
                        toggle_site(url, False)
                        st.rerun()
                else:
                    if st.button("▶ Resume", key=f"resume_{url}", use_container_width=True):
                        toggle_site(url, True)
                        st.rerun()
            with col_scan:
                if st.button("🔍 Scan Now", key=f"scannow_{url}", use_container_width=True):
                    st.session_state["page"] = "🔍 Single Scan"
                    st.session_state["prefill_url"] = url
                    st.rerun()
            with col_remove:
                if st.button("✕ Remove", key=f"remove_{url}", use_container_width=True):
                    remove_site(url)
                    st.rerun()

            st.markdown("</div></div>", unsafe_allow_html=True)

            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.markdown(f"<span style='font-size:11px;color:#64748b;'>Schedule</span><br><span style='font-weight:600;color:#e2e8f0;'>{schedule}</span>", unsafe_allow_html=True)
            with c2:
                st.markdown(f"<span style='font-size:11px;color:#64748b;'>Last Scan</span><br><span style='font-weight:600;color:#e2e8f0;'>{last_scan[:16] if last_scan != 'Never' else 'Never'}</span>", unsafe_allow_html=True)
            with c3:
                st.markdown(f"<span style='font-size:11px;color:#64748b;'>Next Scan</span><br><span style='font-weight:600;color:#e2e8f0;'>{next_display}</span>", unsafe_allow_html=True)
            with c4:
                st.markdown(f"<span style='font-size:11px;color:#64748b;'>Last Findings</span><br><span style='font-weight:600;color:#f1f5f9;'>{last_vulns} vulns · {scan_count} scans</span>", unsafe_allow_html=True)

            # Scan history for this site
            scan_history = site.get("scan_history", [])
            if len(scan_history) >= 2:
                with st.expander(f"📊 Scan History & Trends ({len(scan_history)} scans)"):
                    for i, scan in enumerate(reversed(scan_history[-5:])):
                        ts = scan.get("timestamp", "")[:16]
                        summary = scan.get("summary", {})
                        diff = scan.get("diff")
                        st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:8px;padding:10px 14px;margin:6px 0;">
  <span style="font-weight:600;color:#06b6d4;">Scan {len(scan_history) - i}</span>
  <span style="color:#64748b;margin-left:10px;">{ts}</span>
  <span style="color:#f97316;margin-left:10px;">{summary.get('total_after_triage', 0)} vulns</span>
  <span style="color:#ef4444;margin-left:6px;">{summary.get('critical_count', 0)} crit</span>
  {f"<span style='color:#10b981;margin-left:6px;'>({diff.get('trend','').upper()})</span>" if diff else ""}
</div>""", unsafe_allow_html=True)

            # ── Test webhook ──────────────────────────────────────────────────
            if site.get("webhook_url"):
                if st.button("🔔 Test webhook", key=f"test_wh_{url}"):
                    try:
                        import requests
                        requests.post(
                            site["webhook_url"],
                            json={"text": f"ReconIQ — test notification for {site['url']}"},
                            timeout=10,
                        )
                        st.success("Webhook delivered — check your endpoint.")
                    except Exception as e:
                        st.error(f"Webhook failed: {e}")